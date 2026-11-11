"""Locate the datasets bundled with AgentGuard.

The wheel ships the repository's ``datasets/`` directory as ``agentguard/_datasets`` so that
``pip install agentguard`` users get the full attack library. In a source checkout the repository's
own ``datasets/`` directory is used instead.
"""

from __future__ import annotations

from pathlib import Path

__all__ = ["bundled_datasets_root", "resolve_bundled"]

_PREFIX = "datasets"


def bundled_datasets_root() -> Path | None:
    """Directory holding the bundled datasets, or ``None`` if they are not available."""
    package_dir = Path(__file__).resolve().parent
    candidates = [package_dir / "_datasets", package_dir.parent.parent / _PREFIX]
    return next((c for c in candidates if (c / "attacks").is_dir()), None)


def resolve_bundled(value: str | Path) -> Path | None:
    """Map a relative ``datasets/...`` path onto the bundled datasets (``None`` if not applicable)."""
    path = Path(value)
    if path.is_absolute() or not path.parts or path.parts[0] != _PREFIX:
        return None
    root = bundled_datasets_root()
    if root is None:
        return None
    candidate = root.joinpath(*path.parts[1:])
    return candidate if candidate.exists() else None
