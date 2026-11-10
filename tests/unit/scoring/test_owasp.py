"""OWASP LLM Top 10 (2025) catalogue, URLs and coverage matrix."""

from __future__ import annotations

import pytest

from agentguard.core.types import AttackCategory, CaseStatus
from agentguard.scoring.owasp import CATEGORY_OWASP, OWASP_LLM_2025, coverage_matrix, owasp_url
from tests.unit.scoring._builders import case_result


def test_catalogue_has_ten_items_in_order() -> None:
    assert list(OWASP_LLM_2025) == [f"LLM{i:02d}:2025" for i in range(1, 11)]


def test_every_category_is_mapped_to_known_items() -> None:
    assert set(CATEGORY_OWASP) == set(AttackCategory)
    for items in CATEGORY_OWASP.values():
        assert set(items) <= set(OWASP_LLM_2025)
    assert CATEGORY_OWASP[AttackCategory.OVER_REFUSAL] == []


@pytest.mark.parametrize(
    ("owasp_id", "url"),
    [
        ("LLM01:2025", "https://genai.owasp.org/llmrisk/llm01-prompt-injection/"),
        ("LLM02:2025", "https://genai.owasp.org/llmrisk/llm02-sensitive-information-disclosure/"),
        ("LLM07:2025", "https://genai.owasp.org/llmrisk/llm07-system-prompt-leakage/"),
        ("LLM10:2025", "https://genai.owasp.org/llmrisk/llm10-unbounded-consumption/"),
        ("LLM99:2025", "https://genai.owasp.org/llmrisk/llm99/"),  # unknown item: no slug
        ("LLM03", "https://genai.owasp.org/llmrisk/llm03/"),
    ],
)
def test_owasp_url(owasp_id: str, url: str) -> None:
    assert owasp_url(owasp_id) == url


def test_coverage_matrix_counts_statuses() -> None:
    results = [
        case_result("A-001", k=10, n=10, owasp=["LLM01:2025"]),  # fail
        case_result("A-002", k=0, n=40, owasp=["LLM01:2025", "LLM02:2025"]),  # pass
        case_result("A-003", k=1, n=5, owasp=["LLM01:2025"]),  # inconclusive
        case_result("A-004", k=0, n=40, owasp=[]),
    ]
    assert [r.status for r in results[:3]] == [CaseStatus.failed, CaseStatus.passed, CaseStatus.inconclusive]
    rows = {row.owasp_id: row for row in coverage_matrix(results)}
    assert list(rows) == list(OWASP_LLM_2025)
    llm01 = rows["LLM01:2025"]
    assert (llm01.n_cases, llm01.n_pass, llm01.n_fail, llm01.n_inconclusive) == (3, 1, 1, 1)
    assert llm01.title == "Prompt Injection"
    assert (rows["LLM02:2025"].n_cases, rows["LLM02:2025"].n_pass) == (1, 1)
    assert all(rows[k].n_cases == 0 for k in OWASP_LLM_2025 if k not in {"LLM01:2025", "LLM02:2025"})


def test_coverage_matrix_empty() -> None:
    rows = coverage_matrix([])
    assert len(rows) == 10
    assert all(r.n_cases == 0 for r in rows)
