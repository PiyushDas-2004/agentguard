"""FastAPI application of the hosted AgentGuard service.

Security model (see docs/HOSTED_SECURITY.md):
authentication with argon2id + server-side sessions; CSRF tokens and Origin checks on every state
change; strict per-user data isolation (every lookup is scoped to the signed-in user, unknown and
foreign ids both return 404); rate limits on authentication, verification and scanning; endpoint
ownership verification before scanning; SSRF-safe, origin-pinned outbound traffic; secrets
(Gemini key, agent credentials) kept in memory only; nonce-based CSP and a sandboxed origin for
reports that render agent output.
"""

import contextlib
import logging
import re
import uuid
from collections.abc import AsyncIterator
from datetime import timedelta
from importlib import resources
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from jinja2 import Environment, PackageLoader, select_autoescape
from jsonpath_ng.parser import parse as jsonpath_parse
from sqlalchemy import Engine, text
from sqlmodel import Session, SQLModel, col, create_engine, func, select

from agentguard.core.types import RunResult, utcnow
from agentguard.harness.canary import make_canary
from agentguard.netsafe import NetPolicy, UnsafeURLError, check_url, origin_of
from agentguard.reporting.writer import EXTENSIONS, RENDERERS
from agentguard.version import __version__
from agentguard.web.jobs import ScanManager, validate_hosted_template
from agentguard.web.models import AuditEvent, Scan, Target, User, UserSession
from agentguard.web.scans import HOSTED_CATEGORIES, REQUEST_PRESETS, ScanSecrets
from agentguard.web.security import (
    RateLimiter,
    SecurityHeadersMiddleware,
    client_ip,
    constant_time_equals,
    hash_password,
    hash_token,
    new_token,
    password_problem,
    verify_password,
)
from agentguard.web.settings import WebSettings, load_settings
from agentguard.web.verification import dns_record_name, new_verification_token, verify_dns, verify_http, well_known_url

__all__ = ["create_web_app"]

logger = logging.getLogger("agentguard.web")

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,190}\.[A-Za-z]{2,24}$")
HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9\-]{1,64}$")
FORBIDDEN_HEADERS = {"host", "content-length", "transfer-encoding", "connection", "cookie", "content-type"}
MAX_TARGETS_PER_USER = 20
LOCKOUT_THRESHOLD = 10
LOCKOUT_MINUTES = 15


def _engine(settings: WebSettings) -> Engine:
    url = settings.database_url
    if url.startswith("sqlite"):
        if url.startswith("sqlite:///") and url != "sqlite:///:memory:":
            from pathlib import Path

            Path(url.removeprefix("sqlite:///")).parent.mkdir(parents=True, exist_ok=True)
        if url == "sqlite:///:memory:":
            from sqlalchemy.pool import StaticPool

            return create_engine(url, connect_args={"check_same_thread": False}, poolclass=StaticPool)
        return create_engine(url, connect_args={"check_same_thread": False})
    return create_engine(url, pool_pre_ping=True, pool_size=5, max_overflow=5)


def create_web_app(settings: WebSettings | None = None) -> FastAPI:
    """Create the hosted application (settings default to environment variables)."""
    settings = settings or load_settings()
    engine = _engine(settings)
    SQLModel.metadata.create_all(engine)
    manager = ScanManager(engine, settings)
    limiter = RateLimiter()
    templates = Environment(
        loader=PackageLoader("agentguard.web", "templates"), autoescape=select_autoescape(["html", "j2"])
    )
    session_cookie = "__Host-ag_session" if settings.secure_cookies else "ag_session"
    csrf_cookie = "__Host-ag_csrf" if settings.secure_cookies else "ag_csrf"
    base_origin = origin_of(settings.base_url)

    @contextlib.asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        recovered = manager.recover_after_restart()
        purged = manager.purge_expired()
        if recovered or purged:
            logger.info("startup: %d interrupted scans marked failed, %d expired scans purged", recovered, purged)
        manager.start()
        yield
        await manager.stop()

    app = FastAPI(
        title="AgentGuard", version=__version__, docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan
    )
    app.add_middleware(SecurityHeadersMiddleware, hsts=settings.production)
    app.state.manager = manager
    app.state.settings = settings
    app.state.engine = engine
    app.state.limiter = limiter

    # ------------------------------------------------------------------ helpers
    def db() -> Session:
        return Session(engine)

    def ip_of(request: Request) -> str:
        return client_ip(request, settings.trusted_proxy_hops)

    def audit(user_id: int | None, event: str, request: Request, detail: str = "") -> None:
        with db() as session:
            session.add(AuditEvent(user_id=user_id, event=event, ip=ip_of(request), detail=detail[:500]))
            session.commit()

    def current(request: Request) -> tuple[UserSession, User] | None:
        token = request.cookies.get(session_cookie)
        if not token or len(token) > 200:
            return None
        with db() as session:
            row = session.get(UserSession, hash_token(token))
            if row is None:
                return None
            expires = row.expires_at if row.expires_at.tzinfo else row.expires_at.replace(tzinfo=utcnow().tzinfo)
            if expires < utcnow():
                session.delete(row)
                session.commit()
                return None
            user = session.get(User, row.user_id)
            if user is None:
                return None
            session.expunge(row)
            session.expunge(user)
            return row, user

    def require_user(request: Request) -> tuple[UserSession, User]:
        found = current(request)
        if found is None:
            raise HTTPException(status_code=303, headers={"Location": "/login"})
        return found

    Auth = Annotated[tuple[UserSession, User], Depends(require_user)]  # noqa: N806 - type alias

    def render(request: Request, name: str, status_code: int = 200, **context: Any) -> HTMLResponse:
        found = current(request)
        new_anonymous_token = None
        if found:
            csrf = found[0].csrf_token
        else:
            csrf = request.cookies.get(csrf_cookie) or ""
            if not csrf or len(csrf) > 200:
                csrf = new_anonymous_token = new_token(24)
        response = HTMLResponse(
            templates.get_template(name).render(
                user=found[1] if found else None,
                csrf_token=csrf,
                nonce=request.state.csp_nonce,
                version=__version__,
                settings=settings,
                **context,
            ),
            status_code=status_code,
        )
        if new_anonymous_token is not None:
            # Double-submit token for forms shown before sign-in (sign-up / sign-in).
            response.set_cookie(
                csrf_cookie,
                new_anonymous_token,
                httponly=True,
                secure=settings.secure_cookies,
                samesite="strict",
                path="/",
            )
        return response

    def check_origin(request: Request) -> None:
        origin = request.headers.get("origin")
        if origin is None:
            referer = request.headers.get("referer")
            origin = origin_of(referer) if referer else None
        elif origin != "null":
            origin = origin_of(origin)
        if origin is not None and origin != base_origin:
            raise HTTPException(status_code=403, detail="cross-origin request refused")

    def check_csrf(request: Request, form_token: str | None, expected: str | None) -> None:
        check_origin(request)
        supplied = form_token or request.headers.get("x-csrf-token")
        if not constant_time_equals(supplied, expected):
            raise HTTPException(status_code=403, detail="invalid CSRF token")

    def owned_target(session: Session, user: User, target_id: int) -> Target:
        target = session.get(Target, target_id)
        if target is None or target.user_id != user.id:
            raise HTTPException(status_code=404)
        return target

    def owned_scan(session: Session, user: User, scan_id: str) -> Scan:
        if not re.fullmatch(r"[0-9a-f]{32}", scan_id):
            raise HTTPException(status_code=404)
        scan = session.get(Scan, scan_id)
        if scan is None or scan.user_id != user.id:
            raise HTTPException(status_code=404)
        return scan

    def start_session(user: User, request: Request, response: Response) -> None:
        token = new_token(32)
        with db() as session:
            session.add(
                UserSession(
                    id=hash_token(token),
                    user_id=user.id or 0,
                    csrf_token=new_token(24),
                    expires_at=utcnow() + timedelta(hours=settings.session_hours),
                )
            )
            session.commit()
        response.set_cookie(
            session_cookie,
            token,
            httponly=True,
            secure=settings.secure_cookies,
            samesite="lax",
            path="/",
            max_age=settings.session_hours * 3600,
        )
        response.delete_cookie(csrf_cookie, path="/")

    def outbound_policy() -> NetPolicy:
        return NetPolicy(allow_http=settings.allow_http_targets, allow_private=settings.allow_private_targets)

    # ------------------------------------------------------------------ errors
    @app.exception_handler(HTTPException)
    async def http_error(request: Request, exc: HTTPException) -> Response:
        if exc.status_code in (301, 302, 303, 307) and exc.headers:
            return RedirectResponse(exc.headers["Location"], status_code=303)
        message = {403: "Forbidden", 404: "Not found", 429: "Too many requests"}.get(exc.status_code, "Error")
        detail = exc.detail if exc.status_code in (400, 403, 409, 429) and isinstance(exc.detail, str) else ""
        return render(request, "error.html.j2", status_code=exc.status_code, title=message, detail=detail)

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception) -> Response:
        logger.exception("unhandled error on %s", request.url.path)
        return render(
            request,
            "error.html.j2",
            status_code=500,
            title="Server error",
            detail="Something went wrong. The error was logged.",
        )

    # ------------------------------------------------------------------ health & static
    @app.get("/healthz")
    def healthz() -> JSONResponse:
        return JSONResponse({"status": "ok", "version": __version__})

    @app.get("/readyz")
    def readyz() -> JSONResponse:
        with db() as session:
            session.exec(text("SELECT 1"))  # type: ignore[call-overload]
        return JSONResponse({"status": "ready", "queued": manager.queue.qsize()})

    @app.get("/static/htmx.min.js")
    def htmx() -> Response:
        body = resources.files("agentguard.web.static").joinpath("htmx.min.js").read_bytes()
        return Response(body, media_type="application/javascript", headers={"Cache-Control": "public, max-age=86400"})

    # ------------------------------------------------------------------ public pages
    @app.get("/", response_class=HTMLResponse)
    def index(request: Request) -> Response:
        if current(request):
            return RedirectResponse("/scans", status_code=303)
        return render(request, "index.html.j2")

    @app.get("/signup", response_class=HTMLResponse)
    def signup_form(request: Request) -> Response:
        return render(request, "signup.html.j2", error=None, email="")

    @app.post("/signup")
    def signup(
        request: Request,
        email: Annotated[str, Form(max_length=254)],
        password: Annotated[str, Form(max_length=256)],
        invite_code: Annotated[str, Form(max_length=200)] = "",
        csrf_token: Annotated[str, Form(max_length=200)] = "",
    ) -> Response:
        check_csrf(request, csrf_token, request.cookies.get(csrf_cookie))
        ip = ip_of(request)
        if not limiter.allow(f"signup:{ip}", 5, 3600):
            raise HTTPException(status_code=429, detail="Too many sign-ups from this address. Try later.")
        email = email.strip().lower()
        error = None
        if not EMAIL_RE.match(email):
            error = "Enter a valid e-mail address."
        elif not settings.open_signup and not constant_time_equals(
            invite_code.strip(), settings.signup_code.get_secret_value() if settings.signup_code else None
        ):
            error = "Invalid invite code."
        else:
            error = password_problem(password, email)
        if error is None:
            with db() as session:
                if session.exec(select(User).where(User.email == email)).first() is not None:
                    error = "An account with this e-mail already exists."
                else:
                    user = User(email=email, password_hash=hash_password(password))
                    session.add(user)
                    session.commit()
                    session.refresh(user)
                    session.expunge(user)
        if error is not None:
            return render(request, "signup.html.j2", status_code=400, error=error, email=email)
        audit(user.id, "signup", request)
        response = RedirectResponse("/targets", status_code=303)
        start_session(user, request, response)
        return response

    @app.get("/login", response_class=HTMLResponse)
    def login_form(request: Request) -> Response:
        return render(request, "login.html.j2", error=None, email="")

    @app.post("/login")
    def login(
        request: Request,
        email: Annotated[str, Form(max_length=254)],
        password: Annotated[str, Form(max_length=256)],
        csrf_token: Annotated[str, Form(max_length=200)] = "",
    ) -> Response:
        check_csrf(request, csrf_token, request.cookies.get(csrf_cookie))
        ip = ip_of(request)
        email = email.strip().lower()
        if not limiter.allow(f"login-ip:{ip}", 20, 900) or not limiter.allow(f"login-email:{email}", 10, 900):
            audit(None, "login_throttled", request, email)
            raise HTTPException(status_code=429, detail="Too many sign-in attempts. Wait 15 minutes.")
        with db() as session:
            user = session.exec(select(User).where(User.email == email)).first()
            user_id = user.id if user is not None else None
            locked = False
            if user is not None and user.locked_until is not None:
                until = (
                    user.locked_until if user.locked_until.tzinfo else user.locked_until.replace(tzinfo=utcnow().tzinfo)
                )
                locked = until > utcnow()
            ok = verify_password(user.password_hash if user else None, password) and not locked
            if user is not None and not ok:
                user.failed_logins += 1
                if user.failed_logins >= LOCKOUT_THRESHOLD:
                    user.locked_until = utcnow() + timedelta(minutes=LOCKOUT_MINUTES)
                    user.failed_logins = 0
                session.add(user)
                session.commit()
            if ok and user is not None:
                user.failed_logins = 0
                user.locked_until = None
                session.add(user)
                session.commit()
                session.refresh(user)
                session.expunge(user)
        if not ok or user is None:
            audit(user_id, "login_failed", request, email)
            return render(request, "login.html.j2", status_code=400, error="Invalid e-mail or password.", email=email)
        limiter.reset(f"login-email:{email}")
        audit(user.id, "login", request)
        response = RedirectResponse("/scans", status_code=303)
        start_session(user, request, response)
        return response

    @app.post("/logout")
    def logout(request: Request, auth: Auth, csrf_token: Annotated[str, Form(max_length=200)] = "") -> Response:
        row, user = auth
        check_csrf(request, csrf_token, row.csrf_token)
        with db() as session:
            stored = session.get(UserSession, row.id)
            if stored is not None:
                session.delete(stored)
                session.commit()
        audit(user.id, "logout", request)
        response = RedirectResponse("/", status_code=303)
        response.delete_cookie(session_cookie, path="/")
        return response

    # ------------------------------------------------------------------ targets
    @app.get("/targets", response_class=HTMLResponse)
    def targets(request: Request, auth: Auth) -> Response:
        _, user = auth
        with db() as session:
            rows = session.exec(
                select(Target).where(Target.user_id == user.id).order_by(col(Target.created_at).desc())
            ).all()
        return render(request, "targets.html.j2", targets=rows, presets=REQUEST_PRESETS, error=None, form={})

    @app.post("/targets")
    def add_target(
        request: Request,
        auth: Auth,
        name: Annotated[str, Form(max_length=80)],
        kind: Annotated[str, Form(max_length=20)],
        url: Annotated[str, Form(max_length=2048)],
        preset: Annotated[str, Form(max_length=40)] = "message",
        request_template: Annotated[str, Form(max_length=4000)] = "",
        text_path: Annotated[str, Form(max_length=200)] = "$.reply",
        tool_calls_path: Annotated[str, Form(max_length=200)] = "",
        model: Annotated[str, Form(max_length=120)] = "",
        csrf_token: Annotated[str, Form(max_length=200)] = "",
    ) -> Response:
        row, user = auth
        check_csrf(request, csrf_token, row.csrf_token)
        form = {
            "name": name,
            "kind": kind,
            "url": url,
            "preset": preset,
            "request_template": request_template,
            "text_path": text_path,
            "tool_calls_path": tool_calls_path,
            "model": model,
        }
        error = None
        url = url.strip()
        template = request_template.strip() or REQUEST_PRESETS.get(preset, "")
        if kind not in HOSTED_CATEGORIES:
            error = "Target type must be HTTP JSON API or OpenAI-compatible."
        elif not name.strip():
            error = "Give the target a name."
        else:
            try:
                check_url(url, outbound_policy())
            except UnsafeURLError as exc:
                error = f"URL rejected: {exc}."
        if error is None and kind == "http":
            error = validate_hosted_template(template)
            for label, expression in (("Reply path", text_path), ("Tool-calls path", tool_calls_path)):
                if error is None and expression.strip():
                    try:
                        jsonpath_parse(expression.strip())
                    except Exception:
                        error = f"{label} is not a valid JSONPath expression."
        with db() as session:
            count = session.exec(select(func.count()).select_from(Target).where(Target.user_id == user.id)).one()
            if error is None and count >= MAX_TARGETS_PER_USER:
                error = f"You can register at most {MAX_TARGETS_PER_USER} targets."
            if (
                error is None
                and session.exec(select(Target).where(Target.user_id == user.id, Target.url == url)).first() is not None
            ):
                error = "This URL is already registered."
            if error is not None:
                rows = session.exec(select(Target).where(Target.user_id == user.id)).all()
                return render(
                    request,
                    "targets.html.j2",
                    status_code=400,
                    targets=rows,
                    presets=REQUEST_PRESETS,
                    error=error,
                    form=form,
                )
            target = Target(
                user_id=user.id or 0,
                name=name.strip(),
                kind=kind,
                url=url,
                origin=origin_of(url),
                request_template=template if kind == "http" else "",
                text_path=text_path.strip() or "$.reply",
                tool_calls_path=tool_calls_path.strip(),
                model=model.strip(),
                verification_token=new_verification_token(),
                canary=make_canary(uuid.uuid4().int & ((1 << 62) - 1), "hosted-target"),
            )
            session.add(target)
            session.commit()
            session.refresh(target)
            # Already-verified origins of the same user are reused (ownership is per origin).
            prior = session.exec(
                select(Target).where(
                    Target.user_id == user.id, Target.origin == target.origin, col(Target.verified_at).is_not(None)
                )
            ).first()
            if prior is not None:
                target.verified_at = utcnow()
                session.add(target)
                session.commit()
            target_id = target.id
        audit(user.id, "target_added", request, origin_of(url))
        return RedirectResponse(f"/targets/{target_id}", status_code=303)

    @app.get("/targets/{target_id}", response_class=HTMLResponse)
    def target_detail(request: Request, target_id: int, auth: Auth) -> Response:
        _, user = auth
        with db() as session:
            target = owned_target(session, user, target_id)
            session.expunge(target)
        return render(
            request,
            "target.html.j2",
            target=target,
            well_known=well_known_url(target.url),
            dns_name=dns_record_name(target.url),
            message=None,
        )

    @app.post("/targets/{target_id}/verify")
    async def verify_target(
        request: Request,
        target_id: int,
        auth: Auth,
        method: Annotated[str, Form(max_length=10)] = "http",
        csrf_token: Annotated[str, Form(max_length=200)] = "",
    ) -> Response:
        row, user = auth
        check_csrf(request, csrf_token, row.csrf_token)
        if not limiter.allow(f"verify:{user.id}", 30, 3600):
            raise HTTPException(status_code=429, detail="Too many verification attempts. Try again later.")
        with db() as session:
            target = owned_target(session, user, target_id)
            session.expunge(target)
        if method == "dns":
            result = await verify_dns(target.url, target.verification_token)
        else:
            result = await verify_http(target.url, target.verification_token, outbound_policy())
        if result.ok:
            with db() as session:
                stored = owned_target(session, user, target_id)
                stored.verified_at = utcnow()
                session.add(stored)
                session.commit()
                session.refresh(stored)
                session.expunge(stored)
                target = stored
        audit(user.id, "target_verified" if result.ok else "target_verify_failed", request, result.message)
        return render(
            request,
            "target.html.j2",
            status_code=200 if result.ok else 400,
            target=target,
            well_known=well_known_url(target.url),
            dns_name=dns_record_name(target.url),
            message=result.message,
            ok=result.ok,
        )

    @app.post("/targets/{target_id}/delete")
    def delete_target(
        request: Request, target_id: int, auth: Auth, csrf_token: Annotated[str, Form(max_length=200)] = ""
    ) -> Response:
        row, user = auth
        check_csrf(request, csrf_token, row.csrf_token)
        with db() as session:
            target = owned_target(session, user, target_id)
            for scan in session.exec(select(Scan).where(Scan.target_id == target.id)).all():
                manager.cancel(scan.id)
                session.delete(scan)
            session.delete(target)
            session.commit()
        audit(user.id, "target_deleted", request, str(target_id))
        return RedirectResponse("/targets", status_code=303)

    # ------------------------------------------------------------------ Gemini key check
    @app.post("/gemini/models", response_class=HTMLResponse)
    async def gemini_models(
        request: Request,
        auth: Auth,
        gemini_api_key: Annotated[str, Form(max_length=200)] = "",
        csrf_token: Annotated[str, Form(max_length=200)] = "",
    ) -> Response:
        row, user = auth
        check_csrf(request, csrf_token, row.csrf_token)
        if not limiter.allow(f"gemini:{user.id}", 10, 600):
            raise HTTPException(status_code=429, detail="Too many key checks. Try again in a few minutes.")
        from agentguard.llm.gemini_client import GeminiError, list_gemini_models

        try:
            models = await list_gemini_models(gemini_api_key.strip()) if gemini_api_key.strip() else []
            error = None if models else "Enter a Gemini API key."
        except GeminiError as exc:
            models, error = [], f"Key check failed: {exc.message}"
        except Exception:
            models, error = [], "Could not reach the Gemini API."
        return render(request, "_models.html.j2", models=models, error=error)

    # ------------------------------------------------------------------ scans
    @app.get("/scans", response_class=HTMLResponse)
    def scans(request: Request, auth: Auth) -> Response:
        _, user = auth
        with db() as session:
            rows = session.exec(
                select(Scan).where(Scan.user_id == user.id).order_by(col(Scan.created_at).desc()).limit(100)
            ).all()
            names = {t.id: t.name for t in session.exec(select(Target).where(Target.user_id == user.id)).all()}
        return render(request, "scans.html.j2", scans=rows, names=names)

    @app.get("/scans/new", response_class=HTMLResponse)
    def new_scan(request: Request, auth: Auth, target: int | None = None) -> Response:
        _, user = auth
        with db() as session:
            verified = session.exec(
                select(Target).where(Target.user_id == user.id, col(Target.verified_at).is_not(None))
            ).all()
        return render(
            request,
            "scan_new.html.j2",
            targets=verified,
            selected=target,
            error=None,
            categories={k: [c.value for c in v] for k, v in HOSTED_CATEGORIES.items()},
            max_trials=settings.max_trials,
        )

    @app.post("/scans")
    def create_scan(
        request: Request,
        auth: Auth,
        target_id: Annotated[int, Form()],
        categories: Annotated[list[str], Form()],
        trials: Annotated[int, Form(ge=1, le=10)] = 1,
        mutations: Annotated[bool, Form()] = False,
        judge: Annotated[str, Form(max_length=20)] = "deterministic",
        judge_model: Annotated[str, Form(max_length=120)] = "",
        gemini_api_key: Annotated[str, Form(max_length=200)] = "",
        auth_header_name: Annotated[str, Form(max_length=64)] = "Authorization",
        auth_header_value: Annotated[str, Form(max_length=2000)] = "",
        csrf_token: Annotated[str, Form(max_length=200)] = "",
    ) -> Response:
        row, user = auth
        check_csrf(request, csrf_token, row.csrf_token)
        with db() as session:
            target = owned_target(session, user, target_id)
            if target.verified_at is None:
                raise HTTPException(status_code=409, detail="Verify ownership of this endpoint before scanning it.")
            allowed = {c.value for c in HOSTED_CATEGORIES[target.kind]}
            chosen = [c for c in dict.fromkeys(categories) if c in allowed]
            if not chosen:
                raise HTTPException(status_code=400, detail="Select at least one supported category.")
            if trials > settings.max_trials:
                raise HTTPException(status_code=400, detail=f"At most {settings.max_trials} trials per case.")
            if judge not in {"deterministic", "gemini"}:
                raise HTTPException(status_code=400, detail="Unknown judge.")
            key = gemini_api_key.strip()
            if judge == "gemini" and not re.fullmatch(r"[A-Za-z0-9_\-]{20,200}", key):
                raise HTTPException(status_code=400, detail="The Gemini judge needs a valid Gemini API key.")
            if judge_model and not re.fullmatch(r"[A-Za-z0-9.\-_/]{1,120}", judge_model):
                raise HTTPException(status_code=400, detail="Invalid model name.")
            header_name = auth_header_name.strip() or "Authorization"
            header_value = auth_header_value.strip()
            if header_value and (not HEADER_NAME_RE.match(header_name) or header_name.lower() in FORBIDDEN_HEADERS):
                raise HTTPException(status_code=400, detail="Invalid authentication header name.")
            if any(ch in header_value for ch in "\r\n\x00"):
                raise HTTPException(status_code=400, detail="Invalid authentication header value.")
            day_ago = utcnow() - timedelta(days=1)
            recent = session.exec(
                select(func.count()).select_from(Scan).where(Scan.user_id == user.id, col(Scan.created_at) >= day_ago)
            ).one()
            if recent >= settings.scans_per_user_per_day:
                raise HTTPException(status_code=429, detail="Daily scan quota reached.")
            active = session.exec(
                select(func.count())
                .select_from(Scan)
                .where(Scan.user_id == user.id, col(Scan.status).in_(["queued", "running"]))
            ).one()
            if active >= 1:
                raise HTTPException(status_code=429, detail="You already have a scan in progress.")
            scan = Scan(
                id=uuid.uuid4().hex,
                user_id=user.id or 0,
                target_id=target.id or 0,
                categories=",".join(chosen),
                trials=trials,
                mutations=mutations,
                judge=judge,
                judge_model=judge_model if judge == "gemini" else "",
            )
            session.add(scan)
            session.commit()
            scan_id = scan.id
        secrets = ScanSecrets(
            gemini_api_key=key or None, auth_header_value=header_value or None, auth_header_name=header_name
        )
        if not manager.submit(scan_id, secrets):
            with db() as session:
                stored = session.get(Scan, scan_id)
                if stored is not None:
                    stored.status, stored.error = "failed", "The scan queue is full. Please try again shortly."
                    session.add(stored)
                    session.commit()
        audit(user.id, "scan_created", request, f"{scan_id} target={target_id} judge={judge}")
        return RedirectResponse(f"/scans/{scan_id}", status_code=303)

    @app.get("/scans/{scan_id}", response_class=HTMLResponse)
    def scan_detail(request: Request, scan_id: str, auth: Auth) -> Response:
        _, user = auth
        with db() as session:
            scan = owned_scan(session, user, scan_id)
            target = session.get(Target, scan.target_id)
            session.expunge(scan)
        result = RunResult.model_validate_json(scan.result_json) if scan.result_json else None
        return render(
            request,
            "scan.html.j2",
            scan=scan,
            target=target,
            result=result,
            formats=["json", "sarif", "junit", "markdown"],
        )

    @app.get("/scans/{scan_id}/status", response_class=HTMLResponse)
    def scan_status(request: Request, scan_id: str, auth: Auth) -> Response:
        _, user = auth
        with db() as session:
            scan = owned_scan(session, user, scan_id)
            session.expunge(scan)
        response = render(request, "_status.html.j2", scan=scan)
        if scan.status in {"completed", "failed", "cancelled"}:
            response.headers["HX-Refresh"] = "true"
        return response

    @app.post("/scans/{scan_id}/cancel")
    def cancel_scan(
        request: Request, scan_id: str, auth: Auth, csrf_token: Annotated[str, Form(max_length=200)] = ""
    ) -> Response:
        row, user = auth
        check_csrf(request, csrf_token, row.csrf_token)
        with db() as session:
            scan = owned_scan(session, user, scan_id)
            if scan.status in {"queued", "running"}:
                manager.cancel(scan.id)
                scan.status, scan.error, scan.finished_at = "cancelled", "Cancelled by the user.", utcnow()
                session.add(scan)
                session.commit()
        return RedirectResponse(f"/scans/{scan_id}", status_code=303)

    @app.post("/scans/{scan_id}/delete")
    def delete_scan(
        request: Request, scan_id: str, auth: Auth, csrf_token: Annotated[str, Form(max_length=200)] = ""
    ) -> Response:
        row, user = auth
        check_csrf(request, csrf_token, row.csrf_token)
        with db() as session:
            scan = owned_scan(session, user, scan_id)
            manager.cancel(scan.id)
            session.delete(scan)
            session.commit()
        return RedirectResponse("/scans", status_code=303)

    @app.get("/scans/{scan_id}/report", response_class=HTMLResponse)
    def scan_report(request: Request, scan_id: str, auth: Auth) -> Response:
        _, user = auth
        with db() as session:
            scan = owned_scan(session, user, scan_id)
            payload = scan.result_json
        if not payload:
            raise HTTPException(status_code=404)
        from agentguard.reporting.html import render_html

        request.state.csp_sandbox = True  # agent output is untrusted: opaque, sandboxed origin
        return HTMLResponse(render_html(RunResult.model_validate_json(payload), nonce=request.state.csp_nonce))

    @app.get("/scans/{scan_id}/download/{fmt}")
    def download(request: Request, scan_id: str, fmt: str, auth: Auth) -> Response:
        _, user = auth
        if fmt not in {"json", "sarif", "junit", "markdown"}:
            raise HTTPException(status_code=404)
        with db() as session:
            scan = owned_scan(session, user, scan_id)
            payload = scan.result_json
        if not payload:
            raise HTTPException(status_code=404)
        body = RENDERERS[fmt](RunResult.model_validate_json(payload))
        media = {
            "json": "application/json",
            "sarif": "application/sarif+json",
            "junit": "application/xml",
            "markdown": "text/markdown",
        }[fmt]
        return Response(
            body,
            media_type=media,
            headers={"Content-Disposition": f'attachment; filename="agentguard-{scan_id}.{EXTENSIONS[fmt]}"'},
        )

    # ------------------------------------------------------------------ account
    @app.get("/account", response_class=HTMLResponse)
    def account(request: Request, auth: Auth) -> Response:
        return render(request, "account.html.j2", error=None)

    @app.post("/account/delete")
    def delete_account(
        request: Request,
        auth: Auth,
        password: Annotated[str, Form(max_length=256)] = "",
        csrf_token: Annotated[str, Form(max_length=200)] = "",
    ) -> Response:
        row, user = auth
        check_csrf(request, csrf_token, row.csrf_token)
        if not verify_password(user.password_hash, password):
            return render(request, "account.html.j2", status_code=400, error="Password is incorrect.")
        with db() as session:
            for model in (Scan, Target, UserSession):
                for item in session.exec(select(model).where(model.user_id == user.id)).all():
                    if isinstance(item, Scan):
                        manager.cancel(item.id)
                    session.delete(item)
            stored = session.get(User, user.id)
            if stored is not None:
                session.delete(stored)
            session.commit()
        audit(None, "account_deleted", request, f"user {user.id}")
        response = RedirectResponse("/", status_code=303)
        response.delete_cookie(session_cookie, path="/")
        return response

    return app
