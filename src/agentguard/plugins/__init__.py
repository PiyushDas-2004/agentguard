"""Plugin discovery via Python entry points and explicit ``module:object`` references.

Entry-point groups:

* ``agentguard.targets`` — a :class:`~agentguard.targets.base.BaseTarget` subclass whose
  constructor accepts ``(config: TargetConfig)``; the entry-point name is the config ``type``;
* ``agentguard.detectors`` — a :class:`~agentguard.detectors.base.Detector` subclass;
* ``agentguard.judges`` — a :class:`~agentguard.judges.base.Judge` subclass;
* ``agentguard.attacks`` — a callable returning a list of dataset paths (attack packs).
"""

from __future__ import annotations

from importlib.metadata import EntryPoint, entry_points
from typing import Any

from agentguard.core.errors import ConfigError

__all__ = ["GROUPS", "discover", "load_reference"]

GROUPS = ("agentguard.targets", "agentguard.detectors", "agentguard.judges", "agentguard.attacks")


def discover(group: str, extra: list[EntryPoint] | None = None) -> dict[str, Any]:
    """Load every entry point in ``group`` (plus ``extra``) into ``{name: object}``.

    Raises:
        ConfigError: if a plugin fails to import.
    """
    if group not in GROUPS:
        raise ValueError(f"unknown plugin group {group!r}")
    found: dict[str, Any] = {}
    points = list(entry_points(group=group)) + list(extra or [])
    for point in points:
        try:
            found[point.name] = point.load()
        except Exception as exc:
            raise ConfigError(f"plugin {point.name!r} ({point.value}) failed to load: {exc}") from exc
    return found


def load_reference(reference: str) -> Any:
    """Load ``module:object`` or ``path/to/file.py:object`` (used by the ``plugins:`` config key)."""
    from agentguard.targets.python_callable import load_object

    return load_object(reference)
