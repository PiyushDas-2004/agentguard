"""Plugin discovery via Python entry points and explicit ``module:object`` references.

Entry-point groups:

* ``agentguard.targets`` — a :class:`~agentguard.targets.base.BaseTarget` subclass whose
  constructor accepts ``(config: TargetConfig)``; the entry-point name is the config ``type``;
* ``agentguard.detectors`` — a :class:`~agentguard.detectors.base.Detector` subclass;
* ``agentguard.judges`` — a :class:`~agentguard.judges.base.Judge` subclass;
* ``agentguard.attacks`` — a callable returning a list of dataset paths (attack packs).

:func:`register_detectors`, :func:`attack_pack_paths` and :func:`load_judge` load the last three
groups and check each plugin honours its contract (see ``docs/WRITING_PLUGINS.md``).
"""

from __future__ import annotations

from importlib.metadata import EntryPoint, entry_points
from pathlib import Path
from typing import TYPE_CHECKING, Any

from agentguard.core.errors import ConfigError

if TYPE_CHECKING:
    from agentguard.detectors.registry import DetectorRegistry
    from agentguard.judges.base import Judge

__all__ = ["GROUPS", "attack_pack_paths", "discover", "load_judge", "load_reference", "register_detectors"]

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


def register_detectors(registry: DetectorRegistry, extra: list[EntryPoint] | None = None) -> list[str]:
    """Register every ``agentguard.detectors`` plugin in ``registry``; return the detector ids.

    Raises:
        ConfigError: a plugin is not a :class:`~agentguard.detectors.base.Detector` subclass.
    """
    from agentguard.detectors.base import Detector

    ids: list[str] = []
    for name, cls in discover("agentguard.detectors", extra).items():
        if not (isinstance(cls, type) and issubclass(cls, Detector)):
            raise ConfigError(f"plugin detector {name!r} is not a Detector subclass")
        registry.register(cls)
        ids.append(cls.id)
    return ids


def attack_pack_paths(extra: list[EntryPoint] | None = None) -> list[Path]:
    """Call every ``agentguard.attacks`` plugin and return the dataset paths it provides.

    Raises:
        ConfigError: a pack is not callable, fails, or returns a path that does not exist.
    """
    paths: list[Path] = []
    for name, factory in discover("agentguard.attacks", extra).items():
        if not callable(factory):
            raise ConfigError(f"attack pack {name!r} must be a callable returning dataset paths")
        try:
            returned = factory()
        except Exception as exc:
            raise ConfigError(f"attack pack {name!r} failed: {exc}") from exc
        for item in [returned] if isinstance(returned, (str, Path)) else list(returned or []):
            path = Path(item)
            if not path.exists():
                raise ConfigError(f"attack pack {name!r} returned a missing dataset path: {path}")
            paths.append(path)
    return paths


def load_judge(name: str, extra: list[EntryPoint] | None = None, **kwargs: Any) -> Judge:
    """Instantiate the ``agentguard.judges`` plugin called ``name`` with ``kwargs``.

    Raises:
        ConfigError: unknown name, or the plugin does not produce a :class:`~agentguard.judges.base.Judge`.
    """
    from agentguard.judges.base import Judge

    plugins = discover("agentguard.judges", extra)
    if name not in plugins:
        raise ConfigError(f"unknown judge plugin {name!r} — hint: one of {sorted(plugins)}")
    judge = plugins[name](**kwargs)
    if not isinstance(judge, Judge):
        raise ConfigError(f"plugin judge {name!r} is not a Judge")
    return judge
