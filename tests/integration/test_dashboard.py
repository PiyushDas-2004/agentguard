"""Dashboard (FastAPI + HTMX) against a results database populated by two real offline runs."""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from pathlib import Path

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient  # noqa: E402

from agentguard.config.loader import parse_config  # noqa: E402
from agentguard.core.runner import RunOptions, Runner  # noqa: E402
from agentguard.core.types import RunResult, utcnow  # noqa: E402
from agentguard.dashboard.app import create_app, trend_points  # noqa: E402
from agentguard.storage.db import Database  # noqa: E402
from agentguard.storage.models import RunRow  # noqa: E402
from agentguard.version import __version__  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
CASES = ["PI-DIR-001", "SPL-001", "SPL-002"]


@dataclass
class Populated:
    db_path: Path
    transcripts: Path
    vulnerable: RunResult
    hardened: RunResult


def _run(agent: str, name: str, base: Path) -> RunResult:
    config = parse_config(
        {
            "version": 1,
            "run": {"name": name, "trials_per_case": 2, "seed": 1337, "concurrency": 4},
            "target": {"type": "python_callable", "path": str(ROOT / "examples" / "targets" / agent)},
            "policy": str(ROOT / "examples" / "policy.yaml"),
            "suites": {
                "security": {
                    "datasets": [str(ROOT / "datasets" / "attacks")],
                    "cases": CASES,
                }
            },
            "reports": {"formats": ["json"], "out_dir": str(base / "reports")},
            "storage": {"db_path": str(base / "ag.db"), "transcripts_dir": str(base / "transcripts")},
        }
    )
    return asyncio.run(Runner(config, RunOptions(offline=True), base_dir=ROOT).run())


@pytest.fixture(scope="module")
def populated(tmp_path_factory: pytest.TempPathFactory) -> Populated:
    base = tmp_path_factory.mktemp("dashboard")
    vulnerable = _run("vulnerable_agent.py:agent", "dash-vulnerable", base)
    hardened = _run("hardened_agent.py:agent", "dash-hardened", base)
    # an unfinished run: listed, but excluded from the trend and not loadable
    Database(base / "ag.db").start_run(
        RunRow(
            id="20990101-000000-unfini",
            name="still-running",
            started_at=utcnow(),
            target_type="python_callable",
            target_name="x",
            config_hash="h",
        )
    )
    return Populated(base / "ag.db", base / "transcripts", vulnerable, hardened)


@pytest.fixture(scope="module")
def client(populated: Populated) -> TestClient:
    return TestClient(create_app(populated.db_path, populated.transcripts))


def test_healthz(client: TestClient) -> None:
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "version": __version__}


def test_index_lists_runs_with_trend(client: TestClient, populated: Populated) -> None:
    response = client.get("/")
    assert response.status_code == 200
    html = response.text
    assert "text/html" in response.headers["content-type"]
    for run in (populated.vulnerable, populated.hardened):
        assert f'href="/runs/{run.run_id}"' in html
        assert run.name in html
        assert f"{run.risk_score:.1f}" in html
    assert "still-running" in html
    assert 'aria-label="risk trend"' in html
    # one trend point per finished run (the unfinished run is excluded)
    assert len(re.findall(r"<circle ", html)) == 2
    assert f"{populated.vulnerable.run_id}: {round(populated.vulnerable.risk_score, 1)}" in html
    assert '<script src="/static/htmx.min.js"></script>' in html
    assert 'hx-get="/compare"' in html


def test_index_empty_database(tmp_path: Path) -> None:
    empty = TestClient(create_app(tmp_path / "empty.db", tmp_path / "tr"))
    html = empty.get("/").text
    assert "No finished runs yet" in html
    assert "<svg" not in html
    assert empty.get("/api/runs").json() == []


def test_api_runs(client: TestClient, populated: Populated) -> None:
    runs = client.get("/api/runs").json()
    by_id = {r["id"]: r for r in runs}
    vulnerable = by_id[populated.vulnerable.run_id]
    assert vulnerable["name"] == "dash-vulnerable"
    assert vulnerable["risk_score"] == pytest.approx(populated.vulnerable.risk_score)
    assert vulnerable["grade"] == populated.vulnerable.grade
    assert vulnerable["target"].endswith("vulnerable_agent.py:agent")
    assert by_id["20990101-000000-unfini"]["risk_score"] is None
    assert vulnerable["status"] == "completed"
    assert by_id["20990101-000000-unfini"]["status"] == "running"
    assert vulnerable["started_at"].startswith(str(populated.vulnerable.started_at.year))


def test_run_detail(client: TestClient, populated: Populated) -> None:
    run = populated.vulnerable
    response = client.get(f"/runs/{run.run_id}")
    assert response.status_code == 200
    assert run.run_id in response.text
    for case_id in CASES:
        assert case_id in response.text
    # a unique prefix of the run id is accepted
    assert client.get(f"/runs/{run.run_id[:-2]}").status_code == 200


def test_case_drill_down(client: TestClient, populated: Populated) -> None:
    run = populated.vulnerable
    response = client.get(f"/runs/{run.run_id}/cases/SPL-001")
    assert response.status_code == 200
    html = response.text
    assert "SPL-001" in html
    assert f'href="/runs/{run.run_id}"' in html
    buttons = re.findall(r'hx-get="(/runs/[^"]+/trials/[^"]+)"', html)
    assert len(buttons) == 2  # two trials
    assert "violated" in html


def test_trial_fragment_with_evidence(client: TestClient, populated: Populated) -> None:
    run = populated.vulnerable
    case_html = client.get(f"/runs/{run.run_id}/cases/SPL-001").text
    url = re.findall(r'hx-get="(/runs/[^"]+/trials/[^"]+)"', case_html)[0]
    response = client.get(url)
    assert response.status_code == 200
    fragment = response.text
    assert "<html" not in fragment.lower()  # an HTMX fragment, not a page
    assert f"{run.run_id}:SPL-001:seed:" in fragment
    assert '<div class="turn user">' in fragment
    assert "<mark" in fragment  # violated verdict evidence is highlighted
    assert "system_prompt" in fragment or "canary" in fragment


def test_trial_fragment_hardened_clean(client: TestClient, populated: Populated) -> None:
    run = populated.hardened
    response = client.get(f"/runs/{run.run_id}/trials/{run.run_id}:SPL-001:seed:0")
    assert response.status_code == 200
    assert '<div class="turn assistant">' in response.text


def test_compare_full_and_partial(client: TestClient, populated: Populated) -> None:
    a, b = populated.vulnerable.run_id, populated.hardened.run_id
    full = client.get("/compare", params={"a": a, "b": b})
    assert full.status_code == 200
    assert "<html" in full.text.lower()
    assert f"{a} → {b}" in full.text
    assert "dash-vulnerable" in full.text and "dash-hardened" in full.text
    assert "SYS_PROMPT_LEAK" in full.text
    assert "Fixed:" in full.text

    partial = client.get("/compare", params={"a": a, "b": b}, headers={"HX-Request": "true"})
    assert partial.status_code == 200
    assert "<html" not in partial.text.lower()
    assert f"{a} → {b}" in partial.text
    assert "Δ" in partial.text


def test_vendored_htmx(client: TestClient) -> None:
    response = client.get("/static/htmx.min.js")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/javascript")
    assert "htmx" in response.text[:5000]
    assert len(response.content) > 10_000


@pytest.mark.parametrize(
    "path",
    [
        "/runs/does-not-exist",
        "/runs/20990101-000000-unfini",
        "/compare?a=nope&b=nope",
        "/runs/{run}/cases/NOPE-999",
        "/runs/does-not-exist/cases/SPL-001",
        "/runs/{run}/trials/{run}:SPL-001:seed:99",
        "/nope",
    ],
)
def test_not_found(client: TestClient, populated: Populated, path: str) -> None:
    response = client.get(path.format(run=populated.vulnerable.run_id))
    assert response.status_code == 404


def test_compare_requires_both_runs(client: TestClient, populated: Populated) -> None:
    response = client.get("/compare", params={"a": populated.vulnerable.run_id})
    assert response.status_code == 400
    assert "pass ?a=<run>&b=<run>" in response.json()["detail"]


def test_trend_points_scaling() -> None:
    assert trend_points([]) == []
    points = trend_points([("a", 0.0), ("b", 50.0), ("c", 100.0)], width=600, height=160)
    assert [(p["x"], p["y"]) for p in points] == [(0.0, 160.0), (300.0, 80.0), (600.0, 0.0)]
    assert points[1] == {"x": 300.0, "y": 80.0, "label": "b", "risk": 50.0}
    single = trend_points([("only", 12.345)])
    assert single == [{"x": 0.0, "y": 140.2, "label": "only", "risk": 12.3}]
