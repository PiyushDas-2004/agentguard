"""Example **attack-pack plugin**: ships extra dataset files with a Python distribution.

An attack pack is a callable registered under the ``agentguard.attacks`` entry-point group that
returns the paths of dataset YAML files (or directories of them). The files use exactly the same
schema as ``datasets/attacks/*.yaml`` (see ``docs/DATASET_AUTHORING.md``), so they can be listed
in ``suites.security.datasets`` and are validated by the same loader.

Registered as ``support_desk``.
"""

from __future__ import annotations

from importlib import resources
from pathlib import Path

__all__ = ["PACK_DIR", "support_desk_pack"]

PACK_DIR = Path(str(resources.files("agentguard_example_plugins").joinpath("packs")))


def support_desk_pack() -> list[Path]:
    """Return the dataset files of the support-desk pack."""
    return sorted(PACK_DIR.glob("*.yaml"))
