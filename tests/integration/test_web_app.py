"""Hosted web app: authentication, CSRF, isolation, verification, scanning and secret handling."""

from __future__ import annotations

import json
import re
import threading
import time
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

pytest.importorskip("argon2")
from fastapi.testclient import TestClient
from sqlmodel import Session, select

from agentguard.web.app import create_web_app
from agentguard.web.models import Scan, Target, User
from agentguard.web.settings import WebSettings
from tests.integration.webdb import fresh_database_url

PASSWORD = "correct horse battery"
AGENT_SECRET = "agent-credential-value-0123456789"


class Agent:
    """A deliberately leaky local agent that records what it receives."""

    def __init__(self) -> None:
        self.token = ""
        self.canary = ""
        self.requests: list[dict[str, Any]] = []
        agent = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: object) -> None:
                return

            def _send(self, status: int, body: bytes, kind: str = "application/json") -> None:
                self.send_response(status)
                self.send_header("Content-Type", kind)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self) -> None:
                if self.path == "/.well-known/agentguard.txt":
                    self._send(200, agent.token.encode(), "text/plain")
                else:
                    self._send(404, b"{}")

            def do_POST(self) -> None:
                if self.path.startswith("/slow"):
                    time.sleep(1.0)
                data = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
                agent.requests.append({"path": self.path, "headers": dict(self.headers), "body": data})
                message = str(data.get("message", ""))
                if re.search(r"system prompt|instructions|reveal|secret|config", message, re.I):
                    reply = f"Sure. Internal reference code: {agent.canary}."
                else:
                    reply = "Happy to help."
                self._send(200, json.dumps({"reply": reply}).encode())

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/chat"


@pytest.fixture(scope="module")
def agent() -> Iterator[Agent]:
    instance = Agent()
    yield instance
    instance.server.shutdown()


def _settings(**overrides: Any) -> WebSettings:
    values: dict[str, Any] = {
        "env": "test",
        "database_url": fresh_database_url(),
        "base_url": "http://testserver",
        "signup_code": "invite-code-for-tests",
        "allow_private_targets": True,
        "allow_http_targets": True,
        "secret_key": "s" * 40,
        "target_requests_per_second": 50.0,
        "request_timeout_seconds": 10.0,
    }
    values.update(overrides)
    return WebSettings(**values)


@pytest.fixture
def client() -> Iterator[TestClient]:
    with TestClient(create_web_app(_settings())) as test_client:
        yield test_client


def csrf_of(html: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match, html[:500]
    return match.group(1)


def signup(client: TestClient, email: str = "alice@example.com") -> str:
    token = csrf_of(client.get("/signup").text)
    response = client.post(
        "/signup",
        data={"email": email, "password": PASSWORD, "invite_code": "invite-code-for-tests", "csrf_token": token},
        follow_redirects=False,
    )
    assert response.status_code == 303, response.text[-400:]
    return csrf_of(client.get("/account").text)


def add_target(client: TestClient, csrf: str, url: str, **extra: str) -> int:
    data = {
        "name": "local agent",
        "kind": "http",
        "url": url,
        "preset": "message",
        "text_path": "$.reply",
        "csrf_token": csrf,
        **extra,
    }
    response = client.post("/targets", data=data, follow_redirects=False)
    assert response.status_code == 303, response.text[-600:]
    return int(response.headers["location"].rsplit("/", 1)[1])


def verify(client: TestClient, csrf: str, agent: Agent, target_id: int) -> None:
    with Session(client.app.state.engine) as session:  # type: ignore[attr-defined]
        target = session.get(Target, target_id)
        assert target is not None
        agent.token, agent.canary = target.verification_token, target.canary
    response = client.post(f"/targets/{target_id}/verify", data={"method": "http", "csrf_token": csrf})
    assert response.status_code == 200
    assert "verified via" in response.text


def wait_for(client: TestClient, scan_id: str, timeout: float = 120) -> Scan:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with Session(client.app.state.engine) as session:  # type: ignore[attr-defined]
            scan = session.get(Scan, scan_id)
            assert scan is not None
            if scan.status in {"completed", "failed", "cancelled"}:
                session.expunge(scan)
                return scan
        time.sleep(0.2)
    raise AssertionError("scan did not finish")


# ---------------------------------------------------------------------------- headers & health
def test_health_and_security_headers(client: TestClient) -> None:
    assert client.get("/healthz").json()["status"] == "ok"
    assert client.get("/readyz").json()["status"] == "ready"
    response = client.get("/")
    csp = response.headers["content-security-policy"]
    nonce = re.search(r"'nonce-([^']+)'", csp)
    assert nonce
    assert f'nonce="{nonce.group(1)}"' in response.text
    assert "default-src 'none'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "unsafe-eval" not in csp
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert "no-store" in response.headers["cache-control"]
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404


def test_pages_require_login(client: TestClient) -> None:
    for path in ("/scans", "/targets", "/account", "/scans/new"):
        response = client.get(path, follow_redirects=False)
        assert response.status_code == 303
        assert response.headers["location"] == "/login"


# ---------------------------------------------------------------------------- authentication
def test_signup_rules(client: TestClient) -> None:
    token = csrf_of(client.get("/signup").text)
    base = {"email": "bob@example.com", "password": PASSWORD, "csrf_token": token}
    assert client.post("/signup", data={**base, "invite_code": "wrong"}).status_code == 400
    assert (
        "at least 12"
        in client.post("/signup", data={**base, "password": "short", "invite_code": "invite-code-for-tests"}).text
    )
    assert (
        client.post(
            "/signup", data={**base, "csrf_token": "forged", "invite_code": "invite-code-for-tests"}
        ).status_code
        == 403
    )
    signup(client, "bob@example.com")
    client.cookies.clear()
    token = csrf_of(client.get("/signup").text)
    again = client.post("/signup", data={**base, "csrf_token": token, "invite_code": "invite-code-for-tests"})
    assert again.status_code == 400
    assert "already exists" in again.text
    with Session(client.app.state.engine) as session:  # type: ignore[attr-defined]
        user = session.exec(select(User).where(User.email == "bob@example.com")).one()
        assert user.password_hash.startswith("$argon2id$")
        assert PASSWORD not in user.password_hash


def test_login_is_generic_and_throttled_per_client(client: TestClient) -> None:
    signup(client)
    client.cookies.clear()
    token = csrf_of(client.get("/login").text)
    attacker = {"X-Forwarded-For": "198.51.100.7"}
    unknown = client.post(
        "/login", data={"email": "nobody@example.com", "password": PASSWORD, "csrf_token": token}, headers=attacker
    )
    wrong = {"email": "alice@example.com", "password": "nope-nope-nope", "csrf_token": token}
    first = client.post("/login", data=wrong, headers=attacker)
    assert unknown.status_code == first.status_code == 400
    assert "Invalid e-mail or password." in unknown.text
    assert "Invalid e-mail or password." in first.text
    statuses = [client.post("/login", data=wrong, headers=attacker).status_code for _ in range(5)]
    assert statuses[-1] == 429  # the attacker's client is throttled for this account ...
    # ... but the owner, from another address, can still sign in (no account lock-out DoS)
    owner = client.post(
        "/login",
        data={"email": "alice@example.com", "password": PASSWORD, "csrf_token": token},
        headers={"X-Forwarded-For": "203.0.113.20"},
        follow_redirects=False,
    )
    assert owner.status_code == 303


def test_oversized_request_bodies_are_rejected_before_parsing(client: TestClient) -> None:
    form = {"Content-Type": "application/x-www-form-urlencoded"}
    declared = client.post("/login", content=b"email=" + b"a" * 200_000, headers=form)
    assert declared.status_code == 413

    def chunks() -> Iterator[bytes]:  # no Content-Length: counted while streaming
        for _ in range(100):
            yield b"a" * 10_000

    streamed = client.post("/login", content=chunks(), headers=form)
    assert streamed.status_code == 413


def test_unknown_routes_render_the_error_page(client: TestClient) -> None:
    response = client.get("/no-such-page")
    assert response.status_code == 404
    assert "Not found" in response.text
    assert "content-security-policy" in response.headers


def test_session_cookie_flags_and_logout(client: TestClient) -> None:
    token = csrf_of(client.get("/signup").text)
    response = client.post(
        "/signup",
        data={
            "email": "carol@example.com",
            "password": PASSWORD,
            "invite_code": "invite-code-for-tests",
            "csrf_token": token,
        },
        follow_redirects=False,
    )
    cookie = next(c for c in response.headers.get_list("set-cookie") if c.startswith("ag_session="))
    assert "HttpOnly" in cookie
    assert "SameSite=lax" in cookie
    csrf = csrf_of(client.get("/account").text)
    assert client.post("/logout", data={"csrf_token": csrf}, follow_redirects=False).status_code == 303
    assert client.get("/account", follow_redirects=False).status_code == 303


def test_secure_cookie_names_in_https_deployments() -> None:
    settings = _settings(base_url="https://agentguard.example.com")
    with TestClient(create_web_app(settings), base_url="https://agentguard.example.com") as client:
        response = client.get("/login")
        assert any(c.startswith("__Host-ag_csrf=") and "Secure" in c for c in response.headers.get_list("set-cookie"))


# ---------------------------------------------------------------------------- CSRF & origin
def test_state_changes_require_csrf_and_same_origin(client: TestClient, agent: Agent) -> None:
    csrf = signup(client)
    data = {"name": "x", "kind": "http", "url": agent.url, "text_path": "$.reply"}
    assert client.post("/targets", data=data).status_code == 403  # no token
    assert client.post("/targets", data={**data, "csrf_token": "x" * 32}).status_code == 403
    evil = client.post("/targets", data={**data, "csrf_token": csrf}, headers={"Origin": "https://evil.example"})
    assert evil.status_code == 403
    referer = client.post(
        "/targets", data={**data, "csrf_token": csrf}, headers={"Referer": "https://evil.example/page"}
    )
    assert referer.status_code == 403
    same = client.post(
        "/targets", data={**data, "csrf_token": csrf}, headers={"Origin": "http://testserver"}, follow_redirects=False
    )
    assert same.status_code == 303


# ---------------------------------------------------------------------------- targets
def test_target_validation(client: TestClient, agent: Agent) -> None:
    csrf = signup(client)
    for bad, reason in [
        ({"url": "ftp://example.com/"}, "URL rejected"),
        ({"kind": "python"}, "Target type"),
        ({"request_template": '{"m": {{ message.__class__ }}}'}, "Unsupported template"),
        ({"text_path": "$[[["}, "JSONPath"),
    ]:
        data = {
            "name": "t",
            "kind": "http",
            "url": agent.url,
            "preset": "message",
            "text_path": "$.reply",
            "csrf_token": csrf,
            **bad,
        }
        response = client.post("/targets", data=data)
        assert response.status_code == 400, reason
        assert reason in response.text, reason


def test_production_policy_rejects_private_and_http_targets() -> None:
    settings = _settings(allow_private_targets=False, allow_http_targets=False)
    with TestClient(create_web_app(settings)) as client:
        csrf = signup(client)
        for url in (
            "http://example.com/chat",
            "https://127.0.0.1/chat",
            "https://169.254.169.254/",
            "https://localhost/chat",
            "https://[::1]/chat",
        ):
            response = client.post(
                "/targets", data={"name": "t", "kind": "http", "url": url, "csrf_token": csrf, "text_path": "$.reply"}
            )
            assert response.status_code == 400, url
            assert "URL rejected" in response.text, url


def test_unverified_targets_cannot_be_scanned_and_wrong_token_fails(client: TestClient, agent: Agent) -> None:
    csrf = signup(client)
    target_id = add_target(client, csrf, agent.url)
    agent.token = "agentguard-site-verification=wrong"
    failed = client.post(f"/targets/{target_id}/verify", data={"method": "http", "csrf_token": csrf})
    assert failed.status_code == 400
    assert "unverified" in failed.text
    scan = client.post("/scans", data={"target_id": target_id, "categories": ["PI_DIRECT"], "csrf_token": csrf})
    assert scan.status_code == 409


def test_users_cannot_access_each_others_data(client: TestClient, agent: Agent) -> None:
    csrf_a = signup(client, "alice@example.com")
    target_id = add_target(client, csrf_a, agent.url)
    verify(client, csrf_a, agent, target_id)
    client.cookies.clear()
    csrf_b = signup(client, "mallory@example.com")
    assert client.get(f"/targets/{target_id}").status_code == 404
    assert client.post(f"/targets/{target_id}/delete", data={"csrf_token": csrf_b}).status_code == 404
    assert client.post(f"/targets/{target_id}/verify", data={"csrf_token": csrf_b}).status_code == 404
    response = client.post("/scans", data={"target_id": target_id, "categories": ["PI_DIRECT"], "csrf_token": csrf_b})
    assert response.status_code == 404
    assert client.get("/scans/" + "0" * 32).status_code == 404
    assert client.get("/scans/../../etc/passwd").status_code == 404
    # B registering the same URL must verify it independently (no cross-user reuse).
    other = add_target(client, csrf_b, agent.url)
    assert "unverified" in client.get(f"/targets/{other}").text


# ---------------------------------------------------------------------------- scanning
def test_scan_end_to_end_with_secret_handling(
    client: TestClient, agent: Agent, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AGENTGUARD_TEST_SERVER_SECRET", "server-side-secret-value")
    csrf = signup(client)
    url = agent.url + "?k=${AGENTGUARD_TEST_SERVER_SECRET}"
    target_id = add_target(client, csrf, url)
    verify(client, csrf, agent, target_id)
    agent.requests.clear()
    response = client.post(
        "/scans",
        data={
            "target_id": target_id,
            "categories": ["SYS_PROMPT_LEAK", "DENIAL_OF_WALLET"],
            "trials": 1,
            "judge": "deterministic",
            "auth_header_name": "X-Agent-Key",
            "auth_header_value": AGENT_SECRET,
            "csrf_token": csrf,
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    scan_id = response.headers["location"].rsplit("/", 1)[1]
    scan = wait_for(client, scan_id)
    assert scan.status == "completed", scan.error
    assert scan.grade is not None
    assert scan.risk_score is not None
    assert scan.risk_score > 0

    # the agent received the credential, and only the literal ${...} (no server env expansion)
    assert agent.requests
    assert all(r["headers"].get("X-Agent-Key") == AGENT_SECRET for r in agent.requests)
    assert all("server-side-secret-value" not in r["path"] for r in agent.requests)
    assert all("${AGENTGUARD_TEST_SERVER_SECRET}" in r["path"] for r in agent.requests)

    # secrets are never persisted and are released once the scan ends
    with Session(client.app.state.engine) as session:  # type: ignore[attr-defined]
        stored = session.get(Scan, scan_id)
        assert stored is not None
        assert stored.result_json is not None
        assert AGENT_SECRET not in stored.result_json
        assert AGENT_SECRET not in (stored.error or "")
    assert not client.app.state.manager.holds_secret_for(scan_id)  # type: ignore[attr-defined]

    page = client.get(f"/scans/{scan_id}")
    assert "SYS_PROMPT_LEAK" in page.text
    assert "Open full report" in page.text
    report = client.get(f"/scans/{scan_id}/report")
    assert report.status_code == 200
    assert "sandbox" in report.headers["content-security-policy"]
    for fmt, marker in (
        ("json", b'"risk_score"'),
        ("sarif", b'"version"'),
        ("junit", b"<testsuite"),
        ("markdown", b"#"),
    ):
        download = client.get(f"/scans/{scan_id}/download/{fmt}")
        assert download.status_code == 200
        assert marker in download.content
        assert "attachment" in download.headers["content-disposition"]
    assert client.get(f"/scans/{scan_id}/download/html").status_code == 404

    # one active scan per user and the daily quota are enforced elsewhere; deleting works
    assert client.post(f"/scans/{scan_id}/delete", data={"csrf_token": csrf}, follow_redirects=False).status_code == 303
    assert client.get(f"/scans/{scan_id}").status_code == 404


def test_scan_input_validation(client: TestClient, agent: Agent) -> None:
    csrf = signup(client)
    target_id = add_target(client, csrf, agent.url)
    verify(client, csrf, agent, target_id)
    base = {"target_id": target_id, "categories": ["PI_DIRECT"], "csrf_token": csrf}
    assert client.post("/scans", data={**base, "categories": ["MEMORY_POISONING"]}).status_code == 400  # not for HTTP
    assert client.post("/scans", data={**base, "trials": 9}).status_code == 400
    assert client.post("/scans", data={**base, "judge": "gemini", "gemini_api_key": "short"}).status_code == 400
    assert client.post("/scans", data={**base, "judge_model": "../../x y"}).status_code == 400
    assert client.post("/scans", data={**base, "auth_header_name": "Host", "auth_header_value": "x"}).status_code == 400
    assert client.post("/scans", data={**base, "auth_header_value": "a\r\nInjected: 1"}).status_code == 400


def test_account_deletion_removes_everything(client: TestClient, agent: Agent) -> None:
    csrf = signup(client)
    add_target(client, csrf, agent.url)
    assert client.post("/account/delete", data={"password": "wrong-password!", "csrf_token": csrf}).status_code == 400
    response = client.post("/account/delete", data={"password": PASSWORD, "csrf_token": csrf}, follow_redirects=False)
    assert response.status_code == 303
    with Session(client.app.state.engine) as session:  # type: ignore[attr-defined]
        assert session.exec(select(User)).all() == []
        assert session.exec(select(Target)).all() == []


def test_deleting_scans_does_not_refund_the_daily_quota(agent: Agent) -> None:
    with TestClient(create_web_app(_settings(scans_per_user_per_day=1))) as client:
        csrf = signup(client)
        target_id = add_target(client, csrf, agent.url)
        verify(client, csrf, agent, target_id)
        data = {"target_id": target_id, "categories": ["DENIAL_OF_WALLET"], "csrf_token": csrf}
        first = client.post("/scans", data=data, follow_redirects=False)
        assert first.status_code == 303
        scan_id = first.headers["location"].rsplit("/", 1)[1]
        client.post(f"/scans/{scan_id}/cancel", data={"csrf_token": csrf})
        client.post(f"/scans/{scan_id}/delete", data={"csrf_token": csrf})
        again = client.post("/scans", data=data)
        assert again.status_code == 429
        assert "quota" in again.text


def test_scans_have_a_total_time_limit(agent: Agent) -> None:
    settings = _settings().model_copy(update={"max_scan_minutes": 0.02})  # 1.2 s
    with TestClient(create_web_app(settings)) as client:
        csrf = signup(client)
        target_id = add_target(client, csrf, agent.url.replace("/chat", "/slow"))
        verify(client, csrf, agent, target_id)
        response = client.post(
            "/scans",
            data={"target_id": target_id, "categories": ["PI_DIRECT"], "csrf_token": csrf},
            follow_redirects=False,
        )
        scan = wait_for(client, response.headers["location"].rsplit("/", 1)[1], timeout=30)
        assert scan.status == "failed"
        assert "limit" in (scan.error or "")


def test_stored_results_are_bounded(client: TestClient, agent: Agent, monkeypatch: pytest.MonkeyPatch) -> None:
    from agentguard.core.types import RunResult
    from agentguard.web import jobs

    csrf = signup(client)
    target_id = add_target(client, csrf, agent.url)
    verify(client, csrf, agent, target_id)
    response = client.post(
        "/scans",
        data={"target_id": target_id, "categories": ["SYS_PROMPT_LEAK"], "csrf_token": csrf},
        follow_redirects=False,
    )
    scan = wait_for(client, response.headers["location"].rsplit("/", 1)[1])
    assert scan.result_json is not None
    result = RunResult.model_validate_json(scan.result_json)
    assert any(c.samples for c in result.cases)
    without_samples = result.model_copy(update={"cases": [c.model_copy(update={"samples": []}) for c in result.cases]})
    monkeypatch.setattr(jobs, "MAX_RESULT_CHARS", len(without_samples.model_dump_json()) + 500)
    trimmed = RunResult.model_validate_json(jobs.bounded_result_json(result, []))
    assert len(trimmed.model_dump_json()) <= jobs.MAX_RESULT_CHARS
    assert any("omitted" in w for w in trimmed.warnings)
    assert [c.n_violations for c in trimmed.cases] == [c.n_violations for c in result.cases]  # aggregates kept
    monkeypatch.setattr(jobs, "MAX_RESULT_CHARS", 100)
    with pytest.raises(ValueError, match="too large"):
        jobs.bounded_result_json(result, [])


def test_cancelling_a_running_scan_stops_it(client: TestClient, agent: Agent) -> None:
    csrf = signup(client)
    target_id = add_target(client, csrf, agent.url.replace("/chat", "/slow"))
    verify(client, csrf, agent, target_id)
    response = client.post(
        "/scans",
        data={
            "target_id": target_id,
            "categories": ["PI_DIRECT"],
            "auth_header_value": AGENT_SECRET,
            "csrf_token": csrf,
        },
        follow_redirects=False,
    )
    scan_id = response.headers["location"].rsplit("/", 1)[1]
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        with Session(client.app.state.engine) as session:  # type: ignore[attr-defined]
            stored = session.get(Scan, scan_id)
            if stored is not None and stored.status == "running":
                break
        time.sleep(0.05)
    client.post(f"/scans/{scan_id}/cancel", data={"csrf_token": csrf})
    time.sleep(1.5)  # a swallowed cancellation would let the scan "complete" and overwrite the status
    with Session(client.app.state.engine) as session:  # type: ignore[attr-defined]
        stored = session.get(Scan, scan_id)
        assert stored is not None
        assert stored.status == "cancelled"
        assert stored.result_json is None
    assert not client.app.state.manager.holds_secret_for(scan_id)  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------- administration
def test_admin_area_and_user_disabling(agent: Agent) -> None:
    app = create_web_app(_settings(admin_emails=frozenset({"admin@example.com"})))
    with TestClient(app) as admin:
        admin_csrf = signup(admin, "admin@example.com")
        other = TestClient(app)
        other_csrf = signup(other, "bob@example.com")
        assert other.get("/admin").status_code == 404  # not advertised to normal users
        assert 'href="/admin"' not in other.get("/account").text

        page = admin.get("/admin")
        assert page.status_code == 200
        assert "bob@example.com" in page.text
        assert "Health" in page.text
        assert 'href="/admin"' in admin.get("/account").text
        with Session(app.state.engine) as session:
            bob = session.exec(select(User).where(User.email == "bob@example.com")).one()
            me = session.exec(select(User).where(User.email == "admin@example.com")).one()
        assert admin.post(f"/admin/users/{bob.id}/disable").status_code == 403  # CSRF required
        assert admin.post(f"/admin/users/{me.id}/disable", data={"csrf_token": admin_csrf}).status_code == 400

        target_id = add_target(other, other_csrf, agent.url)
        assert target_id > 0
        done = admin.post(f"/admin/users/{bob.id}/disable", data={"csrf_token": admin_csrf}, follow_redirects=False)
        assert done.status_code == 303
        # signed out everywhere ...
        assert other.get("/targets", follow_redirects=False).status_code == 303
        # ... and cannot sign in; the reason is shown only with the correct password
        other.cookies.clear()
        token = csrf_of(other.get("/login").text)
        wrong = other.post(
            "/login", data={"email": "bob@example.com", "password": "not-the-password", "csrf_token": token}
        )
        assert wrong.status_code == 400
        assert "disabled" not in wrong.text
        right = other.post("/login", data={"email": "bob@example.com", "password": PASSWORD, "csrf_token": token})
        assert right.status_code == 403
        assert "disabled" in right.text

        assert admin.post(f"/admin/users/{bob.id}/enable", data={"csrf_token": admin_csrf}).status_code == 200
        again = other.post(
            "/login",
            data={"email": "bob@example.com", "password": PASSWORD, "csrf_token": token},
            follow_redirects=False,
        )
        assert again.status_code == 303
        events = admin.get("/admin").text
        assert "admin_disable_user" in events
        assert "admin_enable_user" in events


def test_admin_emails_from_environment() -> None:
    from agentguard.web.settings import load_settings

    settings = load_settings({"AGENTGUARD_ADMIN_EMAILS": " Admin@Example.com, ops@example.com ,"})
    assert settings.admin_emails == frozenset({"admin@example.com", "ops@example.com"})


def test_change_password_and_admin_reset(agent: Agent) -> None:
    app = create_web_app(_settings(admin_emails=frozenset({"admin@example.com"})))
    with TestClient(app) as admin:
        admin_csrf = signup(admin, "admin@example.com")
        user = TestClient(app)
        csrf = signup(user, "carol@example.com")
        second_device = TestClient(app)
        token = csrf_of(second_device.get("/login").text)
        second_device.post("/login", data={"email": "carol@example.com", "password": PASSWORD, "csrf_token": token})
        assert second_device.get("/account", follow_redirects=False).status_code == 200

        bad = user.post(
            "/account/password",
            data={"current_password": "wrong-password!", "new_password": "x" * 20, "csrf_token": csrf},
        )
        assert bad.status_code == 400
        weak = user.post(
            "/account/password", data={"current_password": PASSWORD, "new_password": "short", "csrf_token": csrf}
        )
        assert weak.status_code == 400
        new_password = "a brand new passphrase"
        ok = user.post(
            "/account/password", data={"current_password": PASSWORD, "new_password": new_password, "csrf_token": csrf}
        )
        assert ok.status_code == 200
        assert "Password changed" in ok.text
        assert user.get("/account", follow_redirects=False).status_code == 200  # this device stays signed in
        assert second_device.get("/account", follow_redirects=False).status_code == 303  # others signed out

        with Session(app.state.engine) as session:
            carol = session.exec(select(User).where(User.email == "carol@example.com")).one()
        reset = admin.post(f"/admin/users/{carol.id}/reset-password", data={"csrf_token": admin_csrf})
        assert reset.status_code == 200
        temporary = re.search(r"carol@example.com</strong>:\s*<code>([^<]+)</code>", reset.text)
        assert temporary is not None
        assert user.get("/account", follow_redirects=False).status_code == 303  # reset signs the user out
        token = csrf_of(user.get("/login").text)
        old = user.post("/login", data={"email": "carol@example.com", "password": new_password, "csrf_token": token})
        assert old.status_code == 400
        fresh = user.post(
            "/login",
            data={"email": "carol@example.com", "password": temporary.group(1), "csrf_token": token},
            follow_redirects=False,
        )
        assert fresh.status_code == 303
        assert user.post(f"/admin/users/{carol.id}/reset-password", data={"csrf_token": csrf}).status_code == 404
