"""Every public module imports cleanly."""

from __future__ import annotations

import importlib
import pkgutil

import pytest

import agentguard

MODULES = sorted(m.name for m in pkgutil.walk_packages(agentguard.__path__, "agentguard."))


@pytest.mark.parametrize("name", MODULES)
def test_module_imports(name: str) -> None:
    importlib.import_module(name)
