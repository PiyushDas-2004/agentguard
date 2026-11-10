"""Hypothesis JSON round-trip for every Part-E core model."""

from __future__ import annotations

from datetime import UTC
from typing import Any

from hypothesis import given
from hypothesis import strategies as st
from pydantic import BaseModel

from agentguard.core.types import (
    AttackCase,
    AttackCategory,
    CaseResult,
    CaseStatus,
    CategoryScorecard,
    ErrorInfo,
    EvidenceSpan,
    InjectionVector,
    Objective,
    ObjectiveType,
    OwaspCoverageRow,
    PerformanceReport,
    Poison,
    QualityReport,
    Role,
    RunResult,
    Severity,
    TargetInfo,
    ToolCall,
    Transcript,
    TranscriptTurn,
    Trial,
    TrialSample,
    Turn,
    Verdict,
)

text = st.text(max_size=30)
nonempty = st.text(min_size=1, max_size=30)
floats = st.floats(allow_nan=False, allow_infinity=False, width=64)
unit = st.floats(0.0, 1.0)
nonneg = st.floats(0.0, 1e9)
small_int = st.integers(-(2**40), 2**40)
nonneg_int = st.integers(0, 10**6)
datetimes = st.datetimes(timezones=st.just(UTC))

json_scalar = st.none() | st.booleans() | small_int | floats | text
json_value = st.recursive(
    json_scalar,
    lambda children: st.lists(children, max_size=3) | st.dictionaries(text, children, max_size=3),
    max_leaves=8,
)
json_dict = st.dictionaries(text, json_value, max_size=4)

severities = st.sampled_from(Severity)
categories = st.sampled_from(AttackCategory)
vectors = st.sampled_from(InjectionVector)
non_user_vectors = st.sampled_from([v for v in InjectionVector if v != InjectionVector.user_message])

safe_regex = st.sampled_from(["^a", "b+", r"\d{3}", "(x|y)", ".*", "CANARY-[0-9a-f]+"])

turns = st.builds(Turn, role=st.sampled_from(["user", "assistant"]), content=text, session=st.integers(1, 10))


@st.composite
def poisons(draw: st.DrawFn, vector: st.SearchStrategy[InjectionVector] = non_user_vectors) -> Poison:
    content = draw(text)
    corpus_doc = draw(st.none() | nonempty)
    if not content and not corpus_doc:
        content = "payload"
    return Poison(vector=draw(vector), content=content, location=draw(st.none() | text), corpus_doc=corpus_doc)


@st.composite
def objectives(draw: st.DrawFn) -> Objective:
    otype = draw(st.sampled_from(ObjectiveType))
    tool = draw(nonempty) if otype == ObjectiveType.tool_call else draw(st.none() | text)
    pattern = draw(safe_regex) if otype == ObjectiveType.output_regex else draw(st.none() | safe_regex)
    return Objective(
        type=otype,
        description=draw(text),
        tool=tool,
        args_match=draw(st.dictionaries(text, safe_regex, max_size=3)),
        pattern=pattern,
    )


case_ids = st.from_regex(r"\A[A-Z][A-Z0-9]{0,4}(-[A-Z0-9]{1,4}){0,2}-[0-9]{3}\Z")


@st.composite
def attack_cases(draw: st.DrawFn) -> AttackCase:
    vector = draw(vectors)
    poison = None if vector == InjectionVector.user_message else draw(poisons(st.just(vector)))
    if vector == InjectionVector.user_message and draw(st.booleans()):
        poison = draw(poisons())
    return AttackCase(
        id=draw(case_ids),
        category=draw(categories),
        title=draw(st.text(min_size=3, max_size=30)),
        description=draw(st.text(min_size=10, max_size=40)),
        severity=draw(severities),
        owasp_llm=draw(st.lists(text, max_size=3)),
        mitre_atlas=draw(st.lists(text, max_size=3)),
        vector=vector,
        turns=draw(st.lists(turns, min_size=1, max_size=4)),
        poison=poison,
        objective=draw(objectives()),
        detectors=draw(st.lists(nonempty, min_size=1, max_size=3)),
        mutations_allowed=draw(st.booleans()),
        tags=draw(st.lists(text, max_size=3)),
        adaptive=draw(st.booleans()),
    )


tool_calls = st.builds(
    ToolCall,
    name=nonempty,
    arguments=json_dict,
    timestamp=datetimes,
    allowed=st.booleans(),
    approval_required=st.booleans(),
    approved=st.none() | st.booleans(),
    executed=st.booleans(),
    is_approval_request=st.booleans(),
    policy_violations=st.lists(text, max_size=3),
    result_preview=text,
    turn_index=nonneg_int,
    session=st.integers(1, 10),
)

transcript_turns = st.builds(
    TranscriptTurn,
    index=nonneg_int,
    role=st.sampled_from(Role),
    content=text,
    session=st.integers(1, 10),
    model=st.none() | text,
    tokens_in=nonneg_int,
    tokens_out=nonneg_int,
    cost_usd=nonneg,
    latency_ms=nonneg,
    truncated=st.booleans(),
)

transcripts = st.builds(
    Transcript,
    turns=st.lists(transcript_turns, max_size=4),
    tool_calls=st.lists(tool_calls, max_size=3),
    model=st.none() | text,
    metadata=json_dict,
)

error_infos = st.builds(ErrorInfo, type=nonempty, message=text, retryable=st.booleans())

trials = st.builds(
    Trial,
    run_id=nonempty,
    case_id=nonempty,
    trial_index=nonneg_int,
    seed=small_int,
    mutation_id=st.none() | text,
    transcript=transcripts,
    error=st.none() | error_infos,
    started_at=datetimes,
    ended_at=st.none() | datetimes,
    violated=st.none() | st.booleans(),
    inconclusive=st.booleans(),
    objective_met=st.none() | st.booleans(),
)


@st.composite
def evidence_spans(draw: st.DrawFn) -> EvidenceSpan:
    start = draw(nonneg_int)
    end = start + draw(st.integers(0, 1000))
    return EvidenceSpan(turn_index=draw(st.integers(-1, 100)), start=start, end=end, text=draw(text), reason=draw(text))


verdicts = st.builds(
    Verdict,
    detector_id=nonempty,
    trial_id=nonempty,
    violated=st.booleans(),
    confidence=unit,
    evidence=st.lists(evidence_spans(), max_size=3),
    explanation=text,
    inconclusive=st.booleans(),
)

trial_samples = st.builds(
    TrialSample,
    trial_id=nonempty,
    trial_index=nonneg_int,
    mutation_id=st.none() | text,
    violated=st.none() | st.booleans(),
    error=st.none() | error_infos,
    transcript=transcripts,
    verdicts=st.lists(verdicts, max_size=2),
)

case_results = st.builds(
    CaseResult,
    case_id=nonempty,
    category=categories,
    title=text,
    owasp_llm=st.lists(text, max_size=3),
    n_trials=nonneg_int,
    n_errors=nonneg_int,
    n_inconclusive=nonneg_int,
    n_violations=nonneg_int,
    violation_rate=unit,
    ci_low=unit,
    ci_high=unit,
    severity=severities,
    risk_contribution=nonneg,
    status=st.sampled_from(CaseStatus),
    seed_violation_rate=st.none() | unit,
    mutated_violation_rate=st.none() | unit,
    mutation_rates=st.dictionaries(text, unit, max_size=3),
    objective_success_rate=st.none() | unit,
    detectors_triggered=st.dictionaries(text, nonneg_int, max_size=3),
    samples=st.lists(trial_samples, max_size=1),
)

scorecards = st.builds(
    CategoryScorecard,
    category=categories,
    n_cases=nonneg_int,
    n_pass=nonneg_int,
    n_fail=nonneg_int,
    n_inconclusive=nonneg_int,
    n_trials=nonneg_int,
    n_violations=nonneg_int,
    violation_rate=floats,
    ci_low=floats,
    ci_high=floats,
    risk=floats,
)

owasp_rows = st.builds(
    OwaspCoverageRow,
    owasp_id=text,
    title=text,
    n_cases=nonneg_int,
    n_pass=nonneg_int,
    n_fail=nonneg_int,
    n_inconclusive=nonneg_int,
)

performance = st.builds(
    PerformanceReport,
    n_calls=nonneg_int,
    latency_p50_ms=nonneg,
    latency_p95_ms=nonneg,
    latency_p99_ms=nonneg,
    tokens_in=nonneg_int,
    tokens_out=nonneg_int,
    cost_usd=nonneg,
    cost_per_task_usd=nonneg,
    error_rate=unit,
)

quality_reports = st.builds(
    QualityReport,
    n_tasks=nonneg_int,
    task_success_rate=st.none() | unit,
    trajectory=st.dictionaries(text, floats, max_size=3),
    consistency=st.dictionaries(text, floats, max_size=3),
    rag=st.dictionaries(text, floats, max_size=3),
    backends=st.dictionaries(text, st.dictionaries(text, floats, max_size=2), max_size=2),
    backend_messages=st.lists(text, max_size=2),
    per_task=st.lists(json_dict, max_size=2),
    per_question=st.lists(json_dict, max_size=2),
    performance=performance,
)

run_results = st.builds(
    RunResult,
    run_id=nonempty,
    name=text,
    started_at=datetimes,
    ended_at=st.none() | datetimes,
    duration_s=nonneg,
    partial=st.booleans(),
    abort_reason=st.none() | text,
    target=st.builds(TargetInfo, type=text, name=text, details=json_dict),
    config_hash=text,
    git_sha=st.none() | text,
    agentguard_version=text,
    seed=small_int,
    trials_per_case=nonneg_int,
    fail_threshold_risk=floats,
    status_threshold=unit,
    cases=st.lists(case_results, max_size=2),
    categories=st.lists(scorecards, max_size=2),
    quality=st.none() | quality_reports,
    risk_score=floats,
    grade=text,
    over_refusal_rate=st.none() | unit,
    owasp_coverage=st.lists(owasp_rows, max_size=2),
    total_cost_usd=nonneg,
    total_trials=nonneg_int,
    total_errors=nonneg_int,
    performance=performance,
    warnings=st.lists(text, max_size=2),
)


def _roundtrip(model: BaseModel) -> None:
    cls = type(model)
    restored = cls.model_validate_json(model.model_dump_json())
    assert restored == model
    # dump → python → validate also lossless
    assert cls.model_validate(model.model_dump(mode="json")) == model


def _adapter_roundtrip(tp: Any, value: Any) -> bool:
    from pydantic import TypeAdapter

    adapter = TypeAdapter(tp)
    restored = adapter.validate_json(adapter.dump_json(value))
    return restored == value and type(restored) is type(value)


@given(severities)
def test_severity_roundtrip(value: Severity) -> None:
    assert Severity(value.value) is value
    assert _adapter_roundtrip(Severity, value)


@given(categories)
def test_attack_category_roundtrip(value: AttackCategory) -> None:
    assert _adapter_roundtrip(AttackCategory, value)


@given(vectors)
def test_injection_vector_roundtrip(value: InjectionVector) -> None:
    assert _adapter_roundtrip(InjectionVector, value)


@given(turns)
def test_turn_roundtrip(m: Turn) -> None:
    _roundtrip(m)


@given(poisons())
def test_poison_roundtrip(m: Poison) -> None:
    _roundtrip(m)


@given(objectives())
def test_objective_roundtrip(m: Objective) -> None:
    _roundtrip(m)


@given(attack_cases())
def test_attack_case_roundtrip(m: AttackCase) -> None:
    _roundtrip(m)


@given(tool_calls)
def test_tool_call_roundtrip(m: ToolCall) -> None:
    _roundtrip(m)


@given(transcript_turns)
def test_transcript_turn_roundtrip(m: TranscriptTurn) -> None:
    _roundtrip(m)


@given(transcripts)
def test_transcript_roundtrip(m: Transcript) -> None:
    _roundtrip(m)


@given(error_infos)
def test_error_info_roundtrip(m: ErrorInfo) -> None:
    _roundtrip(m)


@given(trials)
def test_trial_roundtrip(m: Trial) -> None:
    _roundtrip(m)


@given(evidence_spans())
def test_evidence_span_roundtrip(m: EvidenceSpan) -> None:
    _roundtrip(m)


@given(verdicts)
def test_verdict_roundtrip(m: Verdict) -> None:
    _roundtrip(m)


@given(trial_samples)
def test_trial_sample_roundtrip(m: TrialSample) -> None:
    _roundtrip(m)


@given(case_results)
def test_case_result_roundtrip(m: CaseResult) -> None:
    _roundtrip(m)


@given(scorecards)
def test_category_scorecard_roundtrip(m: CategoryScorecard) -> None:
    _roundtrip(m)


@given(quality_reports)
def test_quality_report_roundtrip(m: QualityReport) -> None:
    _roundtrip(m)


@given(run_results)
def test_run_result_roundtrip(m: RunResult) -> None:
    _roundtrip(m)
