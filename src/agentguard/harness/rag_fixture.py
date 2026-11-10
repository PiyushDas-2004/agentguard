"""Deterministic BM25 retrieval over the bundled clean/poisoned markdown corpus."""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from pathlib import Path

from rank_bm25 import BM25Okapi

__all__ = ["RagCorpus", "RagDocument", "RagIndex", "tokenize"]

_STOP = frozenset(
    [
        "a",
        "an",
        "the",
        "and",
        "or",
        "of",
        "to",
        "in",
        "on",
        "for",
        "with",
        "is",
        "are",
        "was",
        "were",
        "be",
        "been",
        "it",
        "this",
        "that",
        "as",
        "at",
        "by",
        "from",
        "our",
        "your",
        "we",
        "you",
        "they",
        "i",
        "me",
        "my",
        "can",
        "do",
        "does",
        "how",
        "what",
        "when",
        "where",
        "which",
        "who",
        "why",
        "will",
        "would",
        "should",
        "could",
        "may",
        "might",
        "not",
        "no",
        "yes",
        "if",
        "then",
        "than",
        "so",
        "such",
        "into",
        "about",
        "over",
        "under",
        "any",
        "all",
        "each",
    ]
)


def tokenize(text: str) -> list[str]:
    """Lower-case alphanumeric tokens without stop-words."""
    return [t for t in re.findall(r"[a-z0-9]+", text.lower()) if t not in _STOP]


@dataclass(frozen=True)
class RagDocument:
    """A retrievable document.

    Attributes:
        doc_id: stable identifier (file stem).
        title: first markdown heading.
        text: full body.
        poisoned: whether this document carries an injection payload.
    """

    doc_id: str
    title: str
    text: str
    poisoned: bool = False


class RagCorpus:
    """Loads clean and poisoned documents from a corpus directory."""

    def __init__(self, clean: list[RagDocument], poisoned: list[RagDocument]) -> None:
        self.clean = clean
        self.poisoned = {d.doc_id: d for d in poisoned}

    @classmethod
    def load(cls, root: str | Path) -> RagCorpus:
        """Load ``root/clean/*.md`` and ``root/poisoned/*.md`` (missing dirs yield empty sets)."""
        base = Path(root)
        return cls(_load_dir(base / "clean", poisoned=False), _load_dir(base / "poisoned", poisoned=True))

    def poisoned_doc(self, name: str) -> RagDocument:
        """Return a poisoned document by id (``KeyError`` if unknown)."""
        key = Path(name).stem
        return self.poisoned[key]


def _load_dir(path: Path, *, poisoned: bool) -> list[RagDocument]:
    docs: list[RagDocument] = []
    if not path.is_dir():
        return docs
    for file in sorted(path.glob("*.md")):
        text = file.read_text(encoding="utf-8")
        match = re.search(r"^#\s+(.+)$", text, re.MULTILINE)
        title = match.group(1).strip() if match else file.stem
        docs.append(RagDocument(doc_id=file.stem, title=title, text=text, poisoned=poisoned))
    return docs


class RagIndex:
    """BM25 index; ties are broken by document id so results are deterministic."""

    def __init__(self, documents: list[RagDocument]) -> None:
        self.documents = list(documents)
        corpus = [tokenize(d.title + " " + d.text) or ["empty"] for d in self.documents]
        self._token_sets = [set(tokens) for tokens in corpus]
        self._bm25 = BM25Okapi(corpus) if corpus else None

    def add(self, document: RagDocument) -> RagIndex:
        """Return a new index that also contains ``document``."""
        return RagIndex([*self.documents, document])

    def render(self, variables: dict[str, str]) -> RagIndex:
        """Return a new index with ``{{VAR}}`` placeholders substituted in every document."""
        rendered = []
        for doc in self.documents:
            text = doc.text
            for key, value in variables.items():
                text = text.replace("{{" + key + "}}", value)
            rendered.append(replace(doc, text=text))
        return RagIndex(rendered)

    def search(self, query: str, k: int = 3) -> list[RagDocument]:
        """Return the top-``k`` documents for ``query`` (score desc, then id asc)."""
        if self._bm25 is None or not self.documents:
            return []
        tokens = tokenize(query)
        if not tokens:
            return []
        scores = self._bm25.get_scores(tokens)
        wanted = set(tokens)
        # BM25 IDF is negative for terms present in most documents of a tiny corpus, so relevance
        # is "shares at least one query term", ranked by score (then id for determinism).
        candidates = [i for i in range(len(self.documents)) if wanted & self._token_sets[i]]
        ranked = sorted(candidates, key=lambda i: (-round(float(scores[i]), 9), self.documents[i].doc_id))
        return [self.documents[i] for i in ranked[:k]]
