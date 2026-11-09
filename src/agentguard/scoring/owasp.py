"""OWASP Top 10 for LLM Applications (2025) catalogue and coverage matrix."""

from __future__ import annotations

from collections.abc import Sequence

from agentguard.core.types import AttackCategory, CaseResult, CaseStatus, OwaspCoverageRow

__all__ = ["CATEGORY_OWASP", "OWASP_LLM_2025", "coverage_matrix", "owasp_url"]

OWASP_LLM_2025: dict[str, str] = {
    "LLM01:2025": "Prompt Injection",
    "LLM02:2025": "Sensitive Information Disclosure",
    "LLM03:2025": "Supply Chain",
    "LLM04:2025": "Data and Model Poisoning",
    "LLM05:2025": "Improper Output Handling",
    "LLM06:2025": "Excessive Agency",
    "LLM07:2025": "System Prompt Leakage",
    "LLM08:2025": "Vector and Embedding Weaknesses",
    "LLM09:2025": "Misinformation",
    "LLM10:2025": "Unbounded Consumption",
}

CATEGORY_OWASP: dict[AttackCategory, list[str]] = {
    AttackCategory.PI_DIRECT: ["LLM01:2025"],
    AttackCategory.PI_INDIRECT: ["LLM01:2025"],
    AttackCategory.JAILBREAK: ["LLM01:2025"],
    AttackCategory.SYS_PROMPT_LEAK: ["LLM07:2025", "LLM02:2025"],
    AttackCategory.DATA_EXFIL: ["LLM02:2025", "LLM01:2025"],
    AttackCategory.PII_LEAK: ["LLM02:2025"],
    AttackCategory.EXCESSIVE_AGENCY: ["LLM06:2025"],
    AttackCategory.INSECURE_OUTPUT: ["LLM05:2025"],
    AttackCategory.MEMORY_POISON: ["LLM04:2025", "LLM01:2025"],
    AttackCategory.RAG_POISON: ["LLM08:2025", "LLM04:2025"],
    AttackCategory.DENIAL_OF_WALLET: ["LLM10:2025"],
    AttackCategory.PKG_HALLUCINATION: ["LLM09:2025", "LLM03:2025"],
    AttackCategory.OVER_REFUSAL: [],
}


def owasp_url(owasp_id: str) -> str:
    """Link to the OWASP GenAI Security Project page for an item."""
    number = owasp_id.split(":", maxsplit=1)[0].removeprefix("LLM")
    slug = OWASP_LLM_2025.get(owasp_id, "").lower().replace(" ", "-")
    return f"https://genai.owasp.org/llmrisk/llm{number}{('-' + slug) if slug else ''}/"


def coverage_matrix(results: Sequence[CaseResult]) -> list[OwaspCoverageRow]:
    """One row per OWASP item with case count and pass/fail/inconclusive counts."""
    rows: list[OwaspCoverageRow] = []
    for owasp_id, title in OWASP_LLM_2025.items():
        cases = [r for r in results if owasp_id in r.owasp_llm]
        rows.append(
            OwaspCoverageRow(
                owasp_id=owasp_id,
                title=title,
                n_cases=len(cases),
                n_pass=sum(1 for r in cases if r.status == CaseStatus.passed),
                n_fail=sum(1 for r in cases if r.status == CaseStatus.failed),
                n_inconclusive=sum(1 for r in cases if r.status == CaseStatus.inconclusive),
            )
        )
    return rows
