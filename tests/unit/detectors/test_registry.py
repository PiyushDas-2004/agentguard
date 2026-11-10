"""DetectorRegistry: built-ins, plugin registration, caching."""

from __future__ import annotations

import pytest

from agentguard.core.types import Verdict
from agentguard.detectors.base import DetectionContext, Detector
from agentguard.detectors.registry import BUILTIN_DETECTORS, JUDGE_DETECTOR_ID, DetectorRegistry
from tests.unit.detectors._helpers import make_ctx

BUILTINS = {
    "canary",
    "tool_policy",
    "exfil",
    "pii",
    "system_prompt",
    "dangerous_output",
    "refusal",
    "resource",
    "package_halluc",
}


class AlwaysViolates(Detector):
    id = "always"
    description = "test plugin"

    def detect(self, ctx: DetectionContext) -> Verdict:
        return self.verdict(ctx, [], "never", "always")


def test_builtins_and_judge_are_known() -> None:
    assert set(BUILTIN_DETECTORS) == BUILTINS
    assert DetectorRegistry().known() == BUILTINS | {JUDGE_DETECTOR_ID}


@pytest.mark.parametrize("detector_id", sorted(BUILTINS))
def test_get_returns_cached_instance_with_matching_id(policy, detector_id: str) -> None:
    registry = DetectorRegistry()
    detector = registry.get(detector_id)
    assert detector.id == detector_id
    assert detector.description
    assert registry.get(detector_id) is detector
    verdict = detector.detect(make_ctx(policy, "Hello! How can I help?"))
    assert verdict.detector_id == detector_id
    assert verdict.violated is False


def test_unknown_detector_raises() -> None:
    with pytest.raises(KeyError):
        DetectorRegistry().get("nope")
    with pytest.raises(KeyError):
        DetectorRegistry().get(JUDGE_DETECTOR_ID)  # pseudo-detector, not instantiable


def test_register_plugin_and_replace_cached_instance() -> None:
    registry = DetectorRegistry()
    registry.register(AlwaysViolates)
    assert "always" in registry.known()
    first = registry.get("always")
    registry.register(AlwaysViolates)
    assert registry.get("always") is not first


def test_registries_are_independent() -> None:
    a = DetectorRegistry()
    a.register(AlwaysViolates)
    assert "always" not in DetectorRegistry().known()


def test_verdict_helper_caps_evidence_and_sets_confidence(policy) -> None:
    from agentguard.core.types import EvidenceSpan

    det = AlwaysViolates()
    ctx = make_ctx(policy, "x")
    spans = [EvidenceSpan(turn_index=0, start=0, end=1, text="x", reason="r")] * 25
    bad = det.verdict(ctx, spans, "ok", "bad", confidence=0.4)
    assert bad.violated
    assert bad.confidence == 0.4
    assert len(bad.evidence) == 20
    assert bad.explanation == "bad"
    good = det.verdict(ctx, [], "ok", "bad", confidence=0.4)
    assert not good.violated
    assert good.confidence == 1.0
    assert good.explanation == "ok"
