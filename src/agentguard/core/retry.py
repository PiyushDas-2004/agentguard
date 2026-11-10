"""Exponential backoff with jitter, compatible across tenacity versions."""

from __future__ import annotations

import inspect

from tenacity import wait_exponential_jitter

__all__ = ["backoff"]

_HAS_MULTIPLIER = "multiplier" in inspect.signature(wait_exponential_jitter.__init__).parameters


def backoff(base: float, maximum: float) -> wait_exponential_jitter:
    """Wait ``base × 2^attempt`` seconds (capped at ``maximum``) plus up to ``base`` of jitter."""
    if _HAS_MULTIPLIER:
        return wait_exponential_jitter(multiplier=base, max=maximum, jitter=base)
    return wait_exponential_jitter(initial=base, max=maximum, jitter=base)  # pragma: no cover - tenacity < 9.2
