"""Answer consistency across repeated trials (normalized exact match + token Jaccard)."""

from __future__ import annotations

import itertools
import re
from collections.abc import Sequence

__all__ = ["consistency", "normalize_answer", "token_jaccard"]


def normalize_answer(text: str) -> str:
    """Lower-case, strip punctuation and collapse whitespace."""
    return re.sub(r"\s+", " ", re.sub(r"[^\w\s]", " ", text.lower())).strip()


def token_jaccard(a: str, b: str) -> float:
    """Jaccard similarity of word sets (1.0 for two empty answers)."""
    ta, tb = set(normalize_answer(a).split()), set(normalize_answer(b).split())
    if not ta and not tb:
        return 1.0
    return len(ta & tb) / len(ta | tb)


def consistency(answers: Sequence[str]) -> tuple[float, float]:
    """Return ``(exact_match_rate, mean_jaccard)`` over all answer pairs (1.0 for < 2 answers)."""
    pairs = list(itertools.combinations(answers, 2))
    if not pairs:
        return 1.0, 1.0
    exact = sum(1 for a, b in pairs if normalize_answer(a) == normalize_answer(b)) / len(pairs)
    jaccard = sum(token_jaccard(a, b) for a, b in pairs) / len(pairs)
    return round(exact, 4), round(jaccard, 4)
