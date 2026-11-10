"""Snapshot tests: JSON, Markdown and SARIF of a fixed, seeded offline run.

The run uses the vulnerable demo agent on a small case subset with mutations enabled. Volatile
fields (run id, timestamps, durations, latencies, git SHA, paths and the config hash, which covers
the temporary storage paths) are blanked by the normalizer in ``scripts/determinism_check.py``.

Regenerate after an intentional change with ``uv run pytest tests/snapshots --snapshot-update``.
"""

from __future__ import annotations

import json

import pytest
from syrupy.extensions.json import JSONSnapshotExtension
from syrupy.extensions.single_file import SingleFileSnapshotExtension, WriteMode

from agentguard.core.types import RunResult
from agentguard.reporting.json_report import render_json
from agentguard.reporting.markdown import render_markdown
from agentguard.reporting.sarif import build_sarif
from tests.failure_injection._support import demo_run, load_script

SNAPSHOT_CASES = ["BEN-003", "PKG-005", "EXA-016", "PI-DIR-001", "PI-DIR-007", "PII-001"]
EXTRA_VOLATILE = frozenset({"config_hash"})


class MarkdownSnapshot(SingleFileSnapshotExtension):
    """Store Markdown snapshots as readable ``.md`` files."""

    file_extension = "md"
    _write_mode = WriteMode.TEXT


@pytest.fixture(scope="module")
def snapshot_run(tmp_path_factory) -> RunResult:
    return demo_run(tmp_path_factory.mktemp("snap"), SNAPSHOT_CASES, trials=2, mutations=True, seed=2024)


@pytest.fixture(scope="module")
def normalizer():
    return load_script("determinism_check")


def test_json_report_snapshot(snapshot_run, normalizer, snapshot):
    data = normalizer.normalize(json.loads(render_json(snapshot_run)), EXTRA_VOLATILE)
    assert data == snapshot.use_extension(JSONSnapshotExtension)


def test_markdown_report_snapshot(snapshot_run, normalizer, snapshot):
    text = normalizer.normalize_text(render_markdown(snapshot_run))
    assert text == snapshot.use_extension(MarkdownSnapshot)


def test_sarif_report_snapshot(snapshot_run, normalizer, snapshot):
    data = normalizer.normalize(build_sarif(snapshot_run), EXTRA_VOLATILE)
    assert data == snapshot.use_extension(JSONSnapshotExtension)


def test_snapshot_run_is_meaningful(snapshot_run):
    statuses = {c.status.value for c in snapshot_run.cases}
    assert {"fail", "inconclusive"} <= statuses
    assert any(c.mutation_rates for c in snapshot_run.cases)
    assert sorted(c.case_id for c in snapshot_run.cases) == sorted(SNAPSHOT_CASES)
