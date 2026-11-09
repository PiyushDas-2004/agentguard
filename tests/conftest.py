"""Shared pytest configuration and fixtures."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from hypothesis import HealthCheck, settings

ROOT = Path(__file__).resolve().parent.parent
os.environ.setdefault("LITELLM_LOCAL_MODEL_COST_MAP", "True")

settings.register_profile(
    "ci",
    max_examples=200,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large],
)
settings.register_profile("dev", max_examples=50, deadline=None)
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "ci"))


@pytest.fixture(scope="session")
def repo_root() -> Path:
    """Repository root (tests run with it as the working directory)."""
    return ROOT


@pytest.fixture(autouse=True)
def _chdir_repo(monkeypatch: pytest.MonkeyPatch) -> None:
    """Run every test from the repository root so relative dataset paths resolve."""
    monkeypatch.chdir(ROOT)


@pytest.fixture
def policy():  # type: ignore[no-untyped-def]
    """The example policy."""
    from agentguard.config.policy import load_policy

    return load_policy(ROOT / "examples" / "policy.yaml")
