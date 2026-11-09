"""Detector registry (built-ins + plugins)."""

from __future__ import annotations

from agentguard.detectors.base import Detector
from agentguard.detectors.canary import CanaryDetector
from agentguard.detectors.dangerous_output import DangerousOutputDetector
from agentguard.detectors.exfil import ExfilDetector
from agentguard.detectors.package_halluc import PackageHallucinationDetector
from agentguard.detectors.pii import PiiDetector
from agentguard.detectors.refusal import RefusalDetector
from agentguard.detectors.resource import ResourceDetector
from agentguard.detectors.system_prompt import SystemPromptDetector
from agentguard.detectors.tool_policy import ToolPolicyDetector

__all__ = ["BUILTIN_DETECTORS", "JUDGE_DETECTOR_ID", "DetectorRegistry"]

JUDGE_DETECTOR_ID = "judge"

BUILTIN_DETECTORS: dict[str, type[Detector]] = {
    cls.id: cls
    for cls in (
        CanaryDetector,
        ToolPolicyDetector,
        ExfilDetector,
        PiiDetector,
        SystemPromptDetector,
        DangerousOutputDetector,
        RefusalDetector,
        ResourceDetector,
        PackageHallucinationDetector,
    )
}


class DetectorRegistry:
    """Instantiates detectors by id; plugins may register more."""

    def __init__(self) -> None:
        self._classes: dict[str, type[Detector]] = dict(BUILTIN_DETECTORS)
        self._instances: dict[str, Detector] = {}

    def register(self, cls: type[Detector]) -> None:
        """Register a detector class under its ``id``."""
        self._classes[cls.id] = cls
        self._instances.pop(cls.id, None)

    def known(self) -> set[str]:
        """All valid detector ids (including the pseudo-detector ``judge``)."""
        return set(self._classes) | {JUDGE_DETECTOR_ID}

    def get(self, detector_id: str) -> Detector:
        """Return a (cached) detector instance.

        Raises:
            KeyError: unknown id.
        """
        if detector_id not in self._instances:
            self._instances[detector_id] = self._classes[detector_id]()
        return self._instances[detector_id]
