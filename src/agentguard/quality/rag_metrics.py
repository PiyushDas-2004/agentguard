"""Built-in RAG metrics: faithfulness, answer relevancy, context precision and recall."""

from __future__ import annotations

import re
from collections.abc import Sequence

from agentguard.judges.mock_judge import content_tokens, sentence_support

__all__ = ["answer_relevancy", "context_precision", "context_recall", "faithfulness", "retrieved_doc_ids"]

_DOC_MARK = re.compile(r"\[doc:([\w.\-]+)\]")


def retrieved_doc_ids(contexts: Sequence[str]) -> list[str]:
    """Doc ids in retrieval order from ``search_docs`` outputs (``[doc:<id>]`` markers)."""
    ids: list[str] = []
    for context in contexts:
        for doc in _DOC_MARK.findall(context):
            if doc not in ids:
                ids.append(doc)
    return ids


def faithfulness(answer: str, contexts: Sequence[str]) -> float:
    """Fraction of answer sentences supported by the retrieved context (1.0 if no claims)."""
    supported, total = sentence_support(answer, "\n".join(contexts))
    return round(supported / total, 4) if total else 1.0


def answer_relevancy(answer: str, question: str) -> float:
    """Fraction of the question's content terms addressed by the answer."""
    q = content_tokens(question)
    if not q:
        return 1.0
    return round(len(q & content_tokens(answer)) / len(q), 4)


def context_precision(retrieved: Sequence[str], relevant: Sequence[str]) -> float:
    """Average precision of the ranked retrieved doc ids against the relevant set."""
    relevant_set = set(relevant)
    if not retrieved or not relevant_set:
        return 0.0
    hits = 0
    total = 0.0
    for rank, doc in enumerate(retrieved, 1):
        if doc in relevant_set:
            hits += 1
            total += hits / rank
    return round(total / min(len(relevant_set), len(retrieved)), 4) if hits else 0.0


def context_recall(reference: str, contexts: Sequence[str]) -> float:
    """Fraction of reference-answer sentences attributable to the retrieved context."""
    supported, total = sentence_support(reference, "\n".join(contexts))
    return round(supported / total, 4) if total else 1.0
