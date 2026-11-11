"""Datasets resolve to the bundled copy when the relative path does not exist locally (pip installs)."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentguard.bundled import bundled_datasets_root, resolve_bundled
from agentguard.config.loader import resolve_path


def test_bundled_root_has_attack_library() -> None:
    root = bundled_datasets_root()
    assert root is not None
    assert (root / "attacks").is_dir()
    assert (root / "rag_corpus" / "clean").is_dir()


@pytest.mark.parametrize(
    "rel",
    [
        "datasets",
        "datasets/attacks",
        "datasets/benign",
        "datasets/rag_corpus",
        "datasets/judge_gold/gold_set.jsonl",
        "datasets/quality/tasks.yaml",
    ],
)
def test_relative_dataset_paths_fall_back_to_bundle(rel: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)  # an empty project directory, as after `pip install` + `agentguard init`
    resolved = resolve_path(rel, tmp_path)
    assert resolved.is_absolute()
    assert resolved.exists()
    assert resolve_bundled(rel) == resolved


def test_local_datasets_take_precedence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "datasets" / "attacks").mkdir(parents=True)
    monkeypatch.chdir(tmp_path)
    assert resolve_path("datasets/attacks", tmp_path) == (tmp_path / "datasets" / "attacks").resolve()


@pytest.mark.parametrize("value", ["examples/policy.yaml", "/abs/datasets/x", "datasets/does-not-exist.yaml", ""])
def test_non_dataset_or_missing_paths_are_not_mapped(value: str) -> None:
    assert resolve_bundled(value) is None
