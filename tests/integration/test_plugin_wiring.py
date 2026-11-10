"""Plugins are wired into the runner, judge factory and dataset linter (not only discoverable)."""

from __future__ import annotations

import asyncio
import sys
from importlib.metadata import EntryPoint
from pathlib import Path

import pytest

from agentguard.attacks.lint import lint_cases
from agentguard.attacks.loader import load_cases
from agentguard.config.loader import parse_config
from agentguard.config.models import JudgeConfig
from agentguard.core.errors import ConfigError
from agentguard.core.runner import RunOptions, Runner, build_judge

PLUGINS = Path(__file__).resolve().parents[2] / "examples" / "plugins"
PACK = PLUGINS / "agentguard_example_plugins" / "packs" / "support_desk.yaml"


@pytest.fixture(autouse=True)
def _plugins_on_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.syspath_prepend(str(PLUGINS))


def _config(tmp_path: Path, **extra: object) -> object:
    return parse_config(
        {
            "run": {"name": "plugin-wiring", "trials_per_case": 1, "concurrency": 2, "seed": 3},
            "target": {"type": "python_callable", "path": "examples/targets/vulnerable_agent.py:agent"},
            "policy": "examples/policy.yaml",
            "suites": {"security": {"datasets": [str(PACK)]}},
            "storage": {"db_path": str(tmp_path / "ag.db"), "transcripts_dir": str(tmp_path / "tr")},
            **extra,
        }
    )


def test_plugins_reference_registers_detector_in_runner(tmp_path: Path) -> None:
    config = _config(tmp_path, plugins=["agentguard_example_plugins.hostname_detector:InternalHostnameDetector"])
    runner = Runner(config, RunOptions(offline=True))  # type: ignore[arg-type]
    assert "internal_hostname" in runner.detector_registry().known()
    result = asyncio.run(runner.run())
    assert result.total_trials > 0
    assert result.total_errors == 0


def test_invalid_plugins_reference_is_rejected(tmp_path: Path) -> None:
    config = _config(tmp_path, plugins=["agentguard_example_plugins.keyword_judge:KeywordJudge"])
    with pytest.raises(ConfigError, match="not a Detector subclass"):
        Runner(config, RunOptions(offline=True)).detector_registry()  # type: ignore[arg-type]


def test_detector_entry_point_reaches_runner(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    point = EntryPoint(
        name="internal_hostname",
        value="agentguard_example_plugins.hostname_detector:InternalHostnameDetector",
        group="agentguard.detectors",
    )
    import agentguard.plugins as plugins

    real = plugins.entry_points

    def fake_entry_points(*, group: str) -> list[EntryPoint]:
        return [point] if group == "agentguard.detectors" else list(real(group=group))

    monkeypatch.setattr(plugins, "entry_points", fake_entry_points)
    runner = Runner(_config(tmp_path), RunOptions(offline=True))  # type: ignore[arg-type]
    assert "internal_hostname" in runner.detector_registry().known()


def test_judge_plugin_is_built(monkeypatch: pytest.MonkeyPatch) -> None:
    point = EntryPoint(name="keyword", value="agentguard_example_plugins.keyword_judge:KeywordJudge",
                       group="agentguard.judges")
    import agentguard.plugins as plugins

    monkeypatch.setattr(plugins, "entry_points", lambda *, group: [point] if group == "agentguard.judges" else [])
    judge = build_judge(JudgeConfig(plugin="keyword"), offline=True)
    assert judge.id == "keyword"


def test_linter_accepts_plugin_detector_ids() -> None:
    cases = load_cases([PACK]).cases
    plugin_cases = [c for c in cases if "internal_hostname" in c.detectors]
    if not plugin_cases:
        pytest.skip("example pack does not use the plugin detector")
    rejected = lint_cases(plugin_cases, enforce_minimums=False)
    accepted = lint_cases(plugin_cases, enforce_minimums=False, extra_detectors={"internal_hostname"})
    assert any("unknown detector" in e for e in rejected.errors)
    assert not any("unknown detector" in e for e in accepted.errors)


def test_examples_dir_importable() -> None:
    assert str(PLUGINS) in sys.path
