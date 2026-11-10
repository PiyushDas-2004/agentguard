"""Deterministic seed derivation.

Every random decision in AgentGuard derives from the run seed plus a path of identifiers, so a run
is reproducible regardless of task scheduling order.
"""

from __future__ import annotations

import hashlib
import random

__all__ = ["derive_rng", "derive_seed", "stable_hash"]


def stable_hash(*parts: object) -> str:
    """Return a hex SHA-256 digest of the string forms of ``parts`` joined by ``\\x1f``."""
    joined = "\x1f".join(str(p) for p in parts)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()


def derive_seed(base_seed: int, *parts: object) -> int:
    """Derive a 63-bit child seed from a base seed and identifying parts.

    Args:
        base_seed: the run-level seed.
        *parts: identifiers such as case id, trial index, mutation id.

    Returns:
        A non-negative integer seed that is stable across processes and Python versions.
    """
    return int(stable_hash(base_seed, *parts)[:16], 16) & ((1 << 63) - 1)


def derive_rng(base_seed: int, *parts: object) -> random.Random:
    """Return a ``random.Random`` seeded with :func:`derive_seed` (not for cryptography)."""
    return random.Random(derive_seed(base_seed, *parts))  # noqa: S311  # simulation RNG, not security  # nosec B311
