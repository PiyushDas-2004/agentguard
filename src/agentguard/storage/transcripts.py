"""Append-only gzipped JSONL transcript store (one file per run)."""

from __future__ import annotations

import gzip
import json
from collections.abc import Iterator
from pathlib import Path

from agentguard.core.errors import StorageError
from agentguard.core.types import Trial

__all__ = ["TranscriptStore"]


class TranscriptStore:
    """Stores full trials as gzipped JSON lines under ``root/<run_id>.jsonl.gz``."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)

    def path(self, run_id: str) -> Path:
        """File holding the run's transcripts."""
        return self.root / f"{run_id}.jsonl.gz"

    def append(self, trials: list[Trial]) -> None:
        """Append trials (multi-member gzip, so appends are cheap and crash-safe).

        Raises:
            StorageError: when the file cannot be written.
        """
        if not trials:
            return
        try:
            self.root.mkdir(parents=True, exist_ok=True)
            with gzip.open(self.path(trials[0].run_id), "at", encoding="utf-8") as handle:
                for trial in trials:
                    handle.write(trial.model_dump_json() + "\n")
        except OSError as exc:
            raise StorageError(f"cannot write transcripts: {exc}") from exc

    def read(self, run_id: str) -> Iterator[Trial]:
        """Yield every stored trial of ``run_id`` (empty if none)."""
        path = self.path(run_id)
        if not path.exists():
            return
        with gzip.open(path, "rt", encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    yield Trial.model_validate(json.loads(line))

    def get(self, run_id: str, trial_id: str) -> Trial | None:
        """Return one trial by id."""
        for trial in self.read(run_id):
            if trial.trial_id == trial_id:
                return trial
        return None
