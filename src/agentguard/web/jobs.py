"""In-process scan queue with bounded concurrency.

Secrets for queued/running scans are kept **only in memory** (``_secrets``) and deleted as soon as
the scan ends. If the process restarts, unfinished scans are marked failed on startup — their
secrets are gone by design, so the user simply re-submits.

This queue serves a single instance (the Render blueprint deploys one). Running several instances
would require an external queue with an encrypted secret hand-off; see docs/DEPLOYMENT.md.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import re
import time
from datetime import timedelta
from typing import Any

from sqlalchemy import Engine
from sqlmodel import Session, col, select

from agentguard.core.types import AttackCategory, utcnow
from agentguard.web.models import AuditEvent, Scan, Target
from agentguard.web.scans import ScanRequest, ScanSecrets, run_hosted_scan
from agentguard.web.security import redact
from agentguard.web.settings import WebSettings

__all__ = ["ScanManager", "validate_hosted_template"]

logger = logging.getLogger("agentguard.web.jobs")

_EXPR = re.compile(
    r"^\s*(message|messages|system_prompt|session|case_id)(\[\s*-?\d{0,3}\s*(:\s*-?\d{0,3}\s*)?\])?"
    r"(\s*\|\s*(tojson|lower|upper|trim))*\s*$"
)


def validate_hosted_template(template: str) -> str | None:
    """Reason a hosted request template is rejected, or ``None``.

    Only ``{{ variable }}`` substitutions (optionally sliced and filtered by tojson/lower/upper/trim)
    are allowed: no statements, comments, attribute access, calls or arithmetic, which rules out
    template-driven resource exhaustion and sandbox-escape attempts.
    """
    if len(template) > 4000:
        return "Request template must be at most 4000 characters."
    if "{%" in template or "{#" in template:
        return "Request template may only contain {{ ... }} substitutions."
    for expression in re.findall(r"\{\{(.*?)\}\}", template, flags=re.S):
        if not _EXPR.match(expression):
            return f"Unsupported template expression: {{{{{expression.strip()[:60]}}}}}"
    if "{{" not in template:
        return "Request template must include {{ message | tojson }} or {{ messages | tojson }}."
    rest = re.sub(r"\{\{.*?\}\}", "", template, flags=re.S)
    if "{{" in rest or "}}" in rest:
        return "Unbalanced template braces."
    return None


class ScanManager:
    """Queues scans and runs them on a fixed pool of asyncio workers."""

    def __init__(self, engine: Engine, settings: WebSettings) -> None:
        self.engine = engine
        self.settings = settings
        self.queue: asyncio.Queue[str] = asyncio.Queue(maxsize=settings.max_queued_scans)
        self._secrets: dict[str, ScanSecrets] = {}
        self._tasks: dict[str, asyncio.Task[None]] = {}
        self._workers: list[asyncio.Task[None]] = []

    # ------------------------------------------------------------------ lifecycle
    def recover_after_restart(self) -> int:
        """Mark scans left queued/running by a previous process as failed; returns the count."""
        with Session(self.engine) as session:
            stale = session.exec(select(Scan).where(col(Scan.status).in_(["queued", "running"]))).all()
            for scan in stale:
                scan.status = "failed"
                scan.error = "Interrupted by a server restart. Secrets are never stored, so please run the scan again."
                scan.finished_at = utcnow()
                session.add(scan)
            session.commit()
            return len(stale)

    def purge_expired(self) -> int:
        """Delete scans older than the retention period; returns the count."""
        cutoff = utcnow() - timedelta(days=self.settings.retention_days)
        with Session(self.engine) as session:
            old = session.exec(select(Scan).where(col(Scan.created_at) < cutoff)).all()
            for scan in old:
                session.delete(scan)
            session.commit()
            return len(old)

    def start(self) -> None:
        """Start the worker tasks."""
        for index in range(self.settings.max_concurrent_scans):
            self._workers.append(asyncio.create_task(self._worker(), name=f"scan-worker-{index}"))

    async def stop(self) -> None:
        """Cancel workers and running scans; wipe secrets."""
        for task in [*self._workers, *self._tasks.values()]:
            task.cancel()
        await asyncio.gather(*self._workers, *self._tasks.values(), return_exceptions=True)
        self._secrets.clear()

    # ------------------------------------------------------------------ API
    def submit(self, scan_id: str, secrets: ScanSecrets) -> bool:
        """Queue a scan; False when the queue is full."""
        try:
            self.queue.put_nowait(scan_id)
        except asyncio.QueueFull:
            return False
        self._secrets[scan_id] = secrets
        return True

    def cancel(self, scan_id: str) -> None:
        """Cancel a queued or running scan."""
        self._secrets.pop(scan_id, None)
        task = self._tasks.get(scan_id)
        if task is not None:
            task.cancel()

    def holds_secret_for(self, scan_id: str) -> bool:
        """Whether secrets for ``scan_id`` are still held (tests/diagnostics)."""
        return scan_id in self._secrets

    # ------------------------------------------------------------------ workers
    async def _worker(self) -> None:
        while True:
            scan_id = await self.queue.get()
            try:
                task = asyncio.create_task(self._run(scan_id))
                self._tasks[scan_id] = task
                with contextlib.suppress(asyncio.CancelledError):
                    await task
            finally:
                self._tasks.pop(scan_id, None)
                self._secrets.pop(scan_id, None)
                self.queue.task_done()

    def _update(self, scan_id: str, **fields: Any) -> None:
        with Session(self.engine) as session:
            scan = session.get(Scan, scan_id)
            if scan is None:
                return
            for key, value in fields.items():
                setattr(scan, key, value)
            session.add(scan)
            session.commit()

    async def _run(self, scan_id: str) -> None:
        secrets = self._secrets.get(scan_id)
        with Session(self.engine) as session:
            scan = session.get(Scan, scan_id)
            target = session.get(Target, scan.target_id) if scan else None
            if scan is None or target is None or scan.status != "queued":
                return
            if secrets is None:  # cancelled while queued
                return
            user_id = scan.user_id
            session.expunge(target)
            request = ScanRequest(
                categories=tuple(AttackCategory(c) for c in scan.categories.split(",") if c),
                trials=scan.trials,
                mutations=scan.mutations,
                judge=scan.judge,
                judge_model=scan.judge_model,
            )
        self._update(scan_id, status="running", started_at=utcnow())
        last = 0.0

        def progress(done: int, total: int) -> None:
            nonlocal last
            now = time.monotonic()
            if now - last > 1.0 or done == total:
                last = now
                self._update(scan_id, progress_done=done, progress_total=total)

        try:
            result = await run_hosted_scan(target, request, secrets, self.settings, progress=progress)
        except asyncio.CancelledError:
            self._update(scan_id, status="cancelled", finished_at=utcnow(), error="Cancelled by the user.")
            raise
        except Exception as exc:
            message = redact(f"{type(exc).__name__}: {exc}", *secrets.values())[:900]
            logger.warning("scan %s failed: %s", scan_id, message)
            self._update(scan_id, status="failed", finished_at=utcnow(), error=message)
            self._audit(user_id, "scan_failed", scan_id)
            return
        payload = redact(result.model_dump_json(), *secrets.values())
        self._update(
            scan_id,
            status="completed",
            finished_at=utcnow(),
            risk_score=result.risk_score,
            grade=result.grade,
            result_json=payload,
            error=redact("; ".join(result.warnings[:3]), *secrets.values())[:900],
        )
        self._audit(user_id, "scan_completed", f"{scan_id} risk={result.risk_score:.1f}")

    def _audit(self, user_id: int | None, event: str, detail: str) -> None:
        with Session(self.engine) as session:
            session.add(AuditEvent(user_id=user_id, event=event, detail=detail[:500]))
            session.commit()


def result_summary(result_json: str | None) -> dict[str, Any]:
    """Small summary extracted from a stored result (for list views)."""
    if not result_json:
        return {}
    data = json.loads(result_json)
    return {"risk": data.get("risk_score"), "grade": data.get("grade"), "trials": data.get("total_trials")}
