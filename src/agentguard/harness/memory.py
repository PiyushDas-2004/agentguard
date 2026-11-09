"""Cross-session key/value memory used to test memory poisoning."""

from __future__ import annotations

from dataclasses import dataclass, field

__all__ = ["MemoryEntry", "MemoryStore"]


@dataclass
class MemoryEntry:
    """One stored memory note.

    Attributes:
        key: note key.
        value: note text.
        session: session number that wrote it (0 = pre-seeded).
        source: who wrote it (``seed``, ``agent``, ``poison``).
    """

    key: str
    value: str
    session: int = 0
    source: str = "agent"


@dataclass
class MemoryStore:
    """A per-trial memory that persists across the trial's sessions."""

    entries: dict[str, MemoryEntry] = field(default_factory=dict)
    max_entries: int = 200
    max_value_chars: int = 4000

    def write(self, key: str, value: str, *, session: int = 0, source: str = "agent") -> MemoryEntry:
        """Store ``value`` under ``key`` (bounded in size and count)."""
        if len(self.entries) >= self.max_entries and key not in self.entries:
            oldest = next(iter(self.entries))
            del self.entries[oldest]
        entry = MemoryEntry(key=key, value=value[: self.max_value_chars], session=session, source=source)
        self.entries[key] = entry
        return entry

    def read(self, key: str = "*") -> list[MemoryEntry]:
        """Return the entry for ``key`` or every entry for ``*``."""
        if key in {"*", "", "all"}:
            return list(self.entries.values())
        entry = self.entries.get(key)
        return [entry] if entry else []

    def items(self) -> list[tuple[str, str]]:
        """``(key, value)`` pairs in insertion order."""
        return [(e.key, e.value) for e in self.entries.values()]

    def render(self) -> str:
        """Human-readable dump (what an agent would load into its context)."""
        return "\n".join(f"- {k}: {v}" for k, v in self.items())
