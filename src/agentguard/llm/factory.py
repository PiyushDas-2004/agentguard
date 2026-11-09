"""Construct LLM clients from configuration."""

from __future__ import annotations

from agentguard.config.models import LLMConfig
from agentguard.llm.base import BaseLLM
from agentguard.llm.litellm_client import LiteLLMClient
from agentguard.llm.mock import MockLLM

__all__ = ["build_llm"]


def build_llm(config: LLMConfig, seed: int = 0, *, offline: bool = False) -> BaseLLM:
    """Return a MockLLM for ``provider: mock`` (or when ``offline``), else a LiteLLM client."""
    if config.provider == "mock" or offline:
        profile = config.profile if config.provider == "mock" else "vulnerable"
        return MockLLM(profile, seed=seed, injection_compliance=config.injection_compliance)
    return LiteLLMClient(config.provider, config.model, api_base=config.api_base, temperature=config.temperature)
