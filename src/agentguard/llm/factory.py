"""Construct LLM clients from configuration."""

from __future__ import annotations

import os

from agentguard.config.models import LLMConfig
from agentguard.core.errors import ConfigError
from agentguard.llm.base import BaseLLM
from agentguard.llm.litellm_client import LiteLLMClient
from agentguard.llm.mock import MockLLM

__all__ = ["build_llm"]


def build_llm(config: LLMConfig, seed: int = 0, *, offline: bool = False) -> BaseLLM:
    """MockLLM for ``mock`` (or ``offline``), native Gemini client for ``gemini``, else LiteLLM."""
    if config.provider == "mock" or offline:
        profile = config.profile if config.provider == "mock" else "vulnerable"
        return MockLLM(profile, seed=seed, injection_compliance=config.injection_compliance)
    if config.provider == "gemini":
        from agentguard.llm.gemini_client import GeminiClient

        key = config.api_key.get_secret_value() if config.api_key else os.environ.get("GEMINI_API_KEY", "")
        if not key:
            raise ConfigError("provider 'gemini' needs an API key (set GEMINI_API_KEY)")
        return GeminiClient(key, config.model, temperature=config.temperature)
    return LiteLLMClient(config.provider, config.model, api_base=config.api_base, temperature=config.temperature)
