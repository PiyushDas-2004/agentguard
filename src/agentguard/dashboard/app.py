"""Results dashboard: runs list with risk trend, run detail, comparison and case drill-down."""

from __future__ import annotations

import json
from importlib import resources
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from jinja2 import Environment, PackageLoader, select_autoescape

from agentguard.core.errors import StorageError
from agentguard.core.types import EvidenceSpan, RunResult, Verdict
from agentguard.reporting.html import _case_view, _transcript_view, render_html
from agentguard.scoring.compare import compare_runs
from agentguard.storage.db import Database
from agentguard.storage.transcripts import TranscriptStore
from agentguard.version import __version__

__all__ = ["create_app", "trend_points"]


def trend_points(runs: list[tuple[str, float]], width: int = 600, height: int = 160) -> list[dict[str, Any]]:
    """Scale ``(label, risk)`` pairs (oldest first) to SVG coordinates."""
    if not runs:
        return []
    step = width / max(1, len(runs) - 1)
    return [
        {"x": round(i * step, 1), "y": round(height - risk / 100 * height, 1), "label": label, "risk": round(risk, 1)}
        for i, (label, risk) in enumerate(runs)
    ]


def create_app(
    db_path: str | Path = ".agentguard/agentguard.db", transcripts_dir: str | Path = ".agentguard/transcripts"
) -> FastAPI:
    """Create the dashboard application bound to a results database."""
    app = FastAPI(title="AgentGuard dashboard", version=__version__)
    database = Database(db_path)
    store = TranscriptStore(transcripts_dir)
    env = Environment(
        loader=PackageLoader("agentguard.dashboard", "templates"), autoescape=select_autoescape(["html", "j2"])
    )

    def page(name: str, **context: Any) -> HTMLResponse:
        return HTMLResponse(env.get_template(name).render(version=__version__, **context))

    def load(run_id: str) -> RunResult:
        try:
            return database.load_run(run_id)
        except StorageError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        """Liveness/readiness probe."""
        database.list_runs(limit=1)
        return {"status": "ok", "version": __version__}

    @app.get("/static/htmx.min.js")
    def htmx() -> Response:
        """Vendored htmx (no CDN, no build step)."""
        body = resources.files("agentguard.dashboard.static").joinpath("htmx.min.js").read_bytes()
        return Response(body, media_type="application/javascript")

    @app.get("/", response_class=HTMLResponse)
    def index() -> HTMLResponse:
        """Runs list with the risk-score trend."""
        rows = database.list_runs(limit=200)
        finished = [r for r in reversed(rows) if r.risk_score is not None]
        points = trend_points([(r.id, float(r.risk_score or 0.0)) for r in finished])
        return page("index.html.j2", runs=rows, points=points)

    @app.get("/api/runs")
    def api_runs() -> JSONResponse:
        """Runs as JSON."""
        return JSONResponse(
            [
                {
                    "id": r.id,
                    "name": r.name,
                    "status": r.status,
                    "risk_score": r.risk_score,
                    "grade": r.grade,
                    "started_at": r.started_at.isoformat(),
                    "target": r.target_name,
                }
                for r in database.list_runs(limit=500)
            ]
        )

    @app.get("/runs/{run_id}", response_class=HTMLResponse)
    def run_detail(run_id: str) -> HTMLResponse:
        """Full run report (same content as the HTML report)."""
        return HTMLResponse(render_html(load(run_id)))

    @app.get("/runs/{run_id}/cases/{case_id}", response_class=HTMLResponse)
    def case_detail(run_id: str, case_id: str) -> HTMLResponse:
        """Case drill-down: statistics, every trial, embedded transcripts."""
        result = load(run_id)
        case = next((c for c in result.cases if c.case_id == case_id), None)
        if case is None:
            raise HTTPException(status_code=404, detail=f"case {case_id} not in run {run_id}")
        trials = sorted(database.trial_rows(result.run_id, case_id), key=lambda t: (t.mutation_id or "", t.trial_index))
        return page("case.html.j2", run=result, cv=_case_view(case), trials=trials)

    @app.get("/runs/{run_id}/trials/{trial_id:path}", response_class=HTMLResponse)
    def trial_fragment(run_id: str, trial_id: str) -> HTMLResponse:
        """HTMX fragment: one trial's transcript with evidence highlighting."""
        trial = store.get(run_id, trial_id)
        if trial is None:
            raise HTTPException(status_code=404, detail="trial transcript not found")
        verdict_dicts = database.verdict_rows(trial_id)
        verdicts = [
            Verdict(
                detector_id=v["detector_id"],
                trial_id=trial_id,
                violated=v["violated"],
                confidence=v["confidence"],
                explanation=v["explanation"],
                evidence=[EvidenceSpan.model_validate(e) for e in json.loads(v["evidence_json"])],
            )
            for v in verdict_dicts
        ]
        return page(
            "trial.html.j2",
            trial=trial,
            view=_transcript_view(trial.transcript, verdicts),
            verdicts=[v for v in verdicts if v.violated],
        )

    @app.get("/compare", response_class=HTMLResponse)
    def compare(request: Request, a: str = "", b: str = "") -> HTMLResponse:
        """Side-by-side comparison of two runs."""
        if not a or not b:
            raise HTTPException(status_code=400, detail="pass ?a=<run>&b=<run>")
        run_a, run_b = load(a), load(b)
        comparison = compare_runs(run_a, run_b)
        cats_a = {c.category.value: c for c in run_a.categories}
        cats_b = {c.category.value: c for c in run_b.categories}
        rows = [{"category": k, "a": cats_a.get(k), "b": cats_b.get(k)} for k in sorted(cats_a.keys() | cats_b.keys())]
        partial = request.headers.get("HX-Request") == "true"
        return page("compare.html.j2", a=run_a, b=run_b, cmp=comparison, rows=rows, partial=partial)

    return app
