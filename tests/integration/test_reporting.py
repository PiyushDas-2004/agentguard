"""Report formats rendered from a real offline run: JSON, SARIF (official schema), JUnit, Markdown, HTML."""

from __future__ import annotations

import json
import os
import stat
from html.parser import HTMLParser
from pathlib import Path

import jsonschema
import pytest
from junitparser import Failure, JUnitXml, Skipped

from agentguard.core.errors import ReportWriteError
from agentguard.core.types import (
    AttackCategory,
    CaseResult,
    CaseStatus,
    EvidenceSpan,
    QualityReport,
    Role,
    RunResult,
    Severity,
    ToolCall,
    Transcript,
    TranscriptTurn,
    TrialSample,
    Verdict,
)
from agentguard.reporting import writer as writer_module
from agentguard.reporting.html import Segment, _tool_class, highlight_segments, render_html
from agentguard.reporting.json_report import render_json
from agentguard.reporting.junit import render_junit
from agentguard.reporting.markdown import render_markdown
from agentguard.reporting.sarif import SARIF_SCHEMA_URI, build_sarif, level_for, render_sarif
from agentguard.reporting.writer import EXTENSIONS, write_report, write_reports
from tests.failure_injection._support import ROOT, demo_run

SCHEMA_PATH = ROOT / "src" / "agentguard" / "reporting" / "schemas" / "sarif-schema-2.1.0.json"


@pytest.fixture(scope="module")
def result(tmp_path_factory) -> RunResult:
    """Vulnerable demo agent on a 9-case subset spanning every severity, with mutations."""
    return demo_run(tmp_path_factory.mktemp("reporting"))


@pytest.fixture(scope="module")
def sarif_schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def _with_case(result: RunResult, **updates) -> RunResult:
    """Copy of ``result`` whose first case has ``updates`` applied (appended as a new case)."""
    extra = result.cases[0].model_copy(update=updates)
    return result.model_copy(update={"cases": [*result.cases, extra]})


# ---------------------------------------------------------------------------------------------- fixture sanity
def test_fixture_run_spans_every_severity_and_status(result):
    failing = {c.severity for c in result.cases if c.status == CaseStatus.failed}
    assert {Severity.critical, Severity.high, Severity.medium, Severity.low} <= failing
    assert any(c.status == CaseStatus.inconclusive for c in result.cases)
    assert any(c.mutation_rates for c in result.cases)


# ---------------------------------------------------------------------------------------------- JSON
def test_json_round_trips_to_run_result(result):
    text = render_json(result)
    restored = RunResult.model_validate_json(text)
    assert restored == result
    assert json.loads(text)["run_id"] == result.run_id
    assert render_json(restored) == text


# ---------------------------------------------------------------------------------------------- SARIF
def test_sarif_validates_against_official_schema(result, sarif_schema):
    log = json.loads(render_sarif(result))
    jsonschema.Draft4Validator.check_schema(sarif_schema)
    jsonschema.Draft4Validator(sarif_schema).validate(log)
    assert log["version"] == "2.1.0"
    assert log["$schema"] == SARIF_SCHEMA_URI


def test_bundled_schema_is_the_official_one(sarif_schema):
    assert sarif_schema["title"].startswith("Static Analysis Results Format (SARIF) Version 2.1.0")
    assert sarif_schema["id"].endswith("sarif-schema-2.1.0.json")
    assert set(sarif_schema["required"]) == {"version", "runs"}


@pytest.mark.parametrize(
    ("severity", "level"),
    [
        (Severity.critical, "error"),
        (Severity.high, "error"),
        (Severity.medium, "warning"),
        (Severity.low, "note"),
        (Severity.info, "note"),
    ],
)
def test_sarif_level_mapping(severity, level):
    assert level_for(severity) == level


def test_sarif_results_use_mapped_levels(result):
    run = build_sarif(result)["runs"][0]
    severities = {c.case_id: c.severity for c in result.cases}
    seen_levels = set()
    for item in run["results"]:
        case_id = item["locations"][0]["logicalLocations"][0]["name"]
        assert item["level"] == level_for(severities[case_id])
        assert item["properties"]["severity"] == severities[case_id].value
        seen_levels.add(item["level"])
    assert seen_levels == {"error", "warning", "note"}


def test_sarif_one_rule_per_category(result):
    run = build_sarif(result)["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    ids = [r["id"] for r in rules]
    expected = [f"AG-{c.value}" for c in AttackCategory if c != AttackCategory.OVER_REFUSAL]
    assert ids == expected
    assert len(set(ids)) == len(ids)
    for item in run["results"]:
        assert rules[item["ruleIndex"]]["id"] == item["ruleId"]
    for rule in rules:
        assert rule["help"]["text"]
        assert rule["helpUri"].startswith("https://genai.owasp.org/")


def test_sarif_one_result_per_failing_security_case(result):
    run = build_sarif(result)["runs"][0]
    names = [r["locations"][0]["logicalLocations"][0]["name"] for r in run["results"]]
    failing = sorted(
        c.case_id for c in result.cases if c.status == CaseStatus.failed and c.category != AttackCategory.OVER_REFUSAL
    )
    assert sorted(names) == failing
    assert len(names) == len(set(names))
    assert all(r["partialFingerprints"]["agentguardCase"] in failing for r in run["results"])
    assert any("Evidence:" in r["message"]["text"] for r in run["results"])


def test_sarif_excludes_failing_over_refusal_cases(result, sarif_schema):
    benign = next(c for c in result.cases if c.category == AttackCategory.OVER_REFUSAL)
    modified = result.model_copy(
        update={
            "cases": [c.model_copy(update={"status": CaseStatus.failed}) if c is benign else c for c in result.cases]
        }
    )
    log = build_sarif(modified, config_path="configs/agentguard.yaml")
    names = [r["locations"][0]["logicalLocations"][0]["name"] for r in log["runs"][0]["results"]]
    assert benign.case_id not in names
    assert log["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == (
        "configs/agentguard.yaml"
    )
    jsonschema.Draft4Validator(sarif_schema).validate(log)


def test_sarif_for_clean_run_has_no_results(result, sarif_schema):
    clean = result.model_copy(update={"cases": [c for c in result.cases if c.status != CaseStatus.failed]})
    log = build_sarif(clean)
    assert log["runs"][0]["results"] == []
    jsonschema.Draft4Validator(sarif_schema).validate(log)


# ---------------------------------------------------------------------------------------------- JUnit
def test_junit_parses_and_carries_evidence(result):
    xml = JUnitXml.fromstring(render_junit(result))
    suites = list(xml)
    assert {s.name for s in suites} == {c.category.value for c in result.cases}
    by_name = {}
    for suite in suites:
        cases_in_suite = [c for c in result.cases if c.category.value == suite.name]
        assert suite.tests == len(cases_in_suite)
        assert suite.failures == sum(1 for c in cases_in_suite if c.status == CaseStatus.failed)
        assert suite.skipped == sum(1 for c in cases_in_suite if c.status == CaseStatus.inconclusive)
        for testcase in suite:
            by_name[testcase.name.split(" ", 1)[0]] = testcase
    assert set(by_name) == {c.case_id for c in result.cases}
    for case in result.cases:
        outcome = by_name[case.case_id].result
        if case.status == CaseStatus.failed:
            (failure,) = outcome
            assert isinstance(failure, Failure)
            assert failure.type == case.severity.value
            assert f"violations {case.n_violations}/{case.n_trials}" in failure.message
            assert "[" in failure.text
            assert "]" in failure.text
        elif case.status == CaseStatus.inconclusive:
            (skipped,) = outcome
            assert isinstance(skipped, Skipped)
            assert skipped.message.startswith("inconclusive:")
        else:
            assert outcome == []
    leak = by_name["PI-DIR-001"].result[0]
    assert "[canary]" in leak.text or "[system_prompt]" in leak.text


def test_junit_strips_invalid_xml_characters(result):
    dirty = _with_case(result, case_id="PI-DIR-999", title="bad \x01\x02 chars \x0b")
    xml = JUnitXml.fromstring(render_junit(dirty))
    names = [tc.name for suite in xml for tc in suite]
    assert any(n.startswith("PI-DIR-999 bad  chars") for n in names)


# ---------------------------------------------------------------------------------------------- Markdown
def test_markdown_summary(result):
    md = render_markdown(result)
    assert md.startswith(f"## ❌ AgentGuard: {result.name} — FAILED")
    assert f"**Risk score:** {result.risk_score:.1f} / 100" in md
    assert "| Category | Cases | Fail | Pass | Inconclusive | Violation rate (95% CI) |" in md
    for card in result.categories:
        assert f"| {card.category.value} | {card.n_cases} |" in md
    failures = [c for c in result.cases if c.status == CaseStatus.failed]
    assert f"### Top failures ({len(failures)} total)" in md
    assert "**Over-refusal rate:**" in md
    assert "PARTIAL" not in md
    assert md.endswith("</sub>\n")


def test_markdown_partial_passed_and_quality(result):
    passed = result.model_copy(
        update={
            "risk_score": 1.0,
            "fail_threshold_risk": 40.0,
            "partial": True,
            "abort_reason": "budget",
            "over_refusal_rate": None,
            "quality": QualityReport(n_tasks=2, task_success_rate=0.5, rag={"faithfulness": 0.75}),
        }
    )
    md = render_markdown(passed, max_failures=2)
    assert "✅" in md
    assert "PASSED" in md
    assert "**PARTIAL** run (budget)" in md
    assert "task success 50%, RAG faithfulness 0.75" in md
    assert md.count("\n- **") == 2


# ---------------------------------------------------------------------------------------------- HTML
class _Collector(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.tags: list[tuple[str, dict[str, str | None]]] = []

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))


@pytest.fixture(scope="module")
def html(result) -> str:
    return render_html(result)


def test_html_is_self_contained(html):
    parser = _Collector()
    parser.feed(html)
    tags = parser.tags
    assert not [a for t, a in tags if t == "script" and a.get("src")], "no external scripts"
    assert not [t for t, _ in tags if t == "link"], "no external stylesheets"
    assert not [a for t, a in tags if t in {"img", "iframe", "embed", "object"} and a.get("src")]
    assert any(t == "style" for t, _ in tags)
    assert any(t == "script" for t, _ in tags), "inline script for filtering"
    assert "@import" not in html
    assert "url(http" not in html


def test_html_has_every_section(html):
    for section in (
        "summary",
        "categories",
        "owasp",
        "robustness",
        "quality",
        "performance",
        "cases",
        "remediation",
        "metadata",
    ):
        assert f'<section id="{section}">' in html, section
    for heading in ("Executive summary", "Category scorecard", "OWASP LLM Top 10", "Mutation robustness"):
        assert heading in html


def test_html_responsive_and_dark_mode(html):
    assert '<meta name="viewport" content="width=device-width, initial-scale=1">' in html
    assert "@media (prefers-color-scheme:dark)" in html
    assert "@media (max-width:640px)" in html


def test_html_evidence_marks_and_tool_call_classes(html, result):
    assert '<mark title="canary: ' in html or '<mark title="system_prompt: ' in html
    assert 'class="call violation"' in html
    assert 'class="call allowed"' in html
    for case in result.cases:
        assert f'id="case-{case.case_id}"' in html
    assert "Remediation guidance" in html
    assert "No failing categories." not in html
    assert "PARTIAL" not in html


def test_html_escapes_target_output(result):
    sample = result.cases[0].samples[0]
    turns = [
        *sample.transcript.turns,
        TranscriptTurn(index=99, role=Role.assistant, content="<script>alert(1)</script>"),
    ]
    transcript = sample.transcript.model_copy(update={"turns": turns})
    case = result.cases[0].model_copy(
        update={"samples": [sample.model_copy(update={"transcript": transcript})], "title": "<b>x</b>"}
    )
    out = render_html(result.model_copy(update={"cases": [case]}))
    assert "<script>alert(1)</script>" not in out
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in out
    assert "<b>x</b>" not in out


def test_html_quality_partial_and_empty_variants(result):
    quality = QualityReport(
        n_tasks=3,
        task_success_rate=2 / 3,
        trajectory={"tool_precision": 0.9},
        consistency={"answer_agreement": 1.0},
        rag={"faithfulness": 0.8},
        backend_messages=["ragas not installed"],
    )
    clean = result.model_copy(
        update={
            "quality": quality,
            "partial": True,
            "abort_reason": "interrupted",
            "cases": [c.model_copy(update={"mutation_rates": {}}) for c in result.cases if c.status != "fail"],
            "warnings": ["something odd"],
        }
    )
    out = render_html(clean)
    assert "PARTIAL (interrupted)" in out
    assert "Task success (3 tasks)" in out
    assert "ragas not installed" in out
    assert "Mutations were not enabled for this run." in out
    assert "No failing security cases." in out
    assert "something odd" in out


def test_html_shows_truncated_and_error_samples(result):
    sample = result.cases[0].samples[0]
    long_turn = TranscriptTurn(index=0, role=Role.assistant, content="x" * 7000, session=2)
    errored = TrialSample(
        trial_id="t",
        trial_index=0,
        transcript=Transcript(turns=[long_turn]),
        error={"type": "TargetTimeoutError", "message": "slow", "retryable": True},
    )
    case = result.cases[0].model_copy(update={"samples": [sample, errored], "n_errors": 1})
    out = render_html(result.model_copy(update={"cases": [case]}))
    assert "[7000 chars, truncated in report]" in out
    assert "TargetTimeoutError" in out
    assert "session 2" in out


@pytest.mark.parametrize(
    ("call", "expected"),
    [
        (ToolCall(name="read_file", arguments={"path": "/a"}), "allowed"),
        (ToolCall(name="shell_exec", allowed=False, policy_violations=["tool denied"]), "violation"),
        (ToolCall(name="shell_exec", allowed=False, executed=False, policy_violations=["blocked"]), "blocked"),
        (ToolCall(name="unknown", allowed=True, executed=False), "blocked"),
        (ToolCall(name="send_email", is_approval_request=True, approved=False, executed=False), "blocked"),
        (ToolCall(name="send_email", is_approval_request=True, approved=True, executed=False), "allowed"),
    ],
)
def test_tool_call_classes(call, expected):
    assert _tool_class(call) == expected


def test_html_renders_blocked_and_approval_calls(result):
    calls = [
        ToolCall(name="shell_exec", arguments={"cmd": "id"}, allowed=False, executed=False, policy_violations=["x"]),
        ToolCall(name="send_email", is_approval_request=True, approved=False, executed=False),
    ]
    transcript = Transcript(
        turns=[
            TranscriptTurn(index=0, role=Role.user, content="do it"),
            TranscriptTurn(index=1, role=Role.assistant, content="done"),
        ],
        tool_calls=[c.model_copy(update={"turn_index": 1}) for c in calls],
    )
    sample = TrialSample(trial_id="t", trial_index=0, transcript=transcript, violated=False)
    case = result.cases[0].model_copy(update={"samples": [sample]})
    out = render_html(result.model_copy(update={"cases": [case]}))
    assert out.count('<div class="call blocked">') == 2
    assert "approval requested: denied" in out


# ---------------------------------------------------------------------------------------------- highlight_segments
def test_highlight_no_spans():
    assert highlight_segments("hello", []) == [Segment("hello")]


def test_highlight_merges_overlapping_and_adjacent_spans():
    text = "0123456789abcdef"
    segments = highlight_segments(text, [(2, 5, "a"), (4, 8, "b"), (8, 10, "c"), (12, 14, "d")])
    assert segments == [
        Segment("01"),
        Segment("23456789", "a; b; c"),
        Segment("ab"),
        Segment("cd", "d"),
        Segment("ef"),
    ]
    assert "".join(s.text for s in segments) == text


def test_highlight_deduplicates_reasons_and_clamps_ranges():
    text = "abcdef"
    segments = highlight_segments(text, [(-3, 2, "r"), (1, 3, "r"), (5, 99, "tail"), (9, 12, "out"), (4, 4, "empty")])
    assert segments == [Segment("abc", "r"), Segment("de"), Segment("f", "tail")]


def test_highlight_unsorted_and_nested_spans():
    segments = highlight_segments("abcdefgh", [(5, 7, "y"), (1, 7, "x"), (2, 3, "z")])
    assert segments == [Segment("a"), Segment("bcdefg", "x; z; y"), Segment("h")]


def test_evidence_highlight_in_rendered_transcript(result):
    turn = TranscriptTurn(index=1, role=Role.assistant, content="the secret is CANARY-123 ok")
    verdict = Verdict(
        detector_id="canary",
        trial_id="t",
        violated=True,
        confidence=1.0,
        evidence=[EvidenceSpan(turn_index=1, start=14, end=24, text="CANARY-123", reason="leak")],
    )
    sample = TrialSample(
        trial_id="t",
        trial_index=0,
        violated=True,
        transcript=Transcript(turns=[TranscriptTurn(index=0, role=Role.user, content="q"), turn]),
        verdicts=[verdict],
    )
    case = result.cases[0].model_copy(update={"samples": [sample]})
    out = render_html(result.model_copy(update={"cases": [case]}))
    assert '<mark title="canary: leak">CANARY-123</mark>' in out


# ---------------------------------------------------------------------------------------------- writer
def test_write_reports_all_formats_atomic_and_world_readable(result, tmp_path):
    old = os.umask(0o077)  # a restrictive umask must not leak into report permissions
    try:
        paths = write_reports(result, list(EXTENSIONS), tmp_path / "out")
    finally:
        os.umask(old)
    assert set(paths) == set(EXTENSIONS)
    for fmt, path in paths.items():
        assert path.name == f"agentguard-{result.run_id}.{EXTENSIONS[fmt]}"
        assert stat.S_IMODE(path.stat().st_mode) == 0o644
        assert path.read_text(encoding="utf-8")
    assert sorted(p.name for p in (tmp_path / "out").iterdir()) == sorted(p.name for p in paths.values())
    assert RunResult.model_validate_json(paths["json"].read_text(encoding="utf-8")) == result


def test_failed_replace_keeps_previous_report_intact(result, tmp_path, monkeypatch):
    out = tmp_path / "out"
    path = write_report(result, "markdown", out)
    previous = path.read_text(encoding="utf-8")

    def broken_replace(src, dst):
        raise OSError(5, "Input/output error")

    monkeypatch.setattr(writer_module.os, "replace", broken_replace)
    changed = result.model_copy(update={"name": "changed-name"})
    with pytest.raises(ReportWriteError, match="Input/output error"):
        write_report(changed, "markdown", out)
    assert path.read_text(encoding="utf-8") == previous
    assert [p.name for p in out.iterdir()] == [path.name], "temporary file must be removed"


def test_interrupted_write_removes_temp_file(result, tmp_path, monkeypatch):
    def interrupted_chmod(path, mode):
        raise KeyboardInterrupt

    monkeypatch.setattr(writer_module.os, "chmod", interrupted_chmod)
    with pytest.raises(KeyboardInterrupt):
        write_report(result, "json", tmp_path)
    assert list(Path(tmp_path).iterdir()) == []


def test_writer_renders_case_without_samples(result, tmp_path):
    bare = CaseResult(
        case_id="PI-DIR-998",
        category=AttackCategory.PI_DIRECT,
        n_trials=0,
        n_errors=3,
        n_violations=0,
        violation_rate=0.0,
        ci_low=0.0,
        ci_high=1.0,
        severity=Severity.high,
        risk_contribution=8.0,
        status=CaseStatus.inconclusive,
    )
    paths = write_reports(result.model_copy(update={"cases": [bare]}), list(EXTENSIONS), tmp_path)
    assert "PI-DIR-998" in paths["html"].read_text(encoding="utf-8")
