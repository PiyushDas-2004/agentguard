"""Dataset linter (``agentguard lint-datasets``).

Checks schema validity, unique ids, valid OWASP / MITRE ATLAS mappings, near-duplicates
(normalized Levenshtein similarity > 0.9), detector presence and validity, template-variable
placement, category minimums, and the quality / RAG / judge-gold datasets.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from agentguard.attacks.loader import load_cases
from agentguard.attacks.models import case_text, template_names
from agentguard.attacks.registry import ATLAS_TECHNIQUES, MIN_CASES
from agentguard.core.errors import DatasetError
from agentguard.core.types import AttackCase, AttackCategory, ObjectiveType
from agentguard.detectors.registry import DetectorRegistry
from agentguard.harness.tools import TOOL_REGISTRY
from agentguard.scoring.owasp import OWASP_LLM_2025

__all__ = ["LintReport", "levenshtein_similarity", "lint_all", "lint_cases"]

SIMILARITY_LIMIT = 0.9
# Detectors whose findings are disclosure, which must not be attributed to EXCESSIVE_AGENCY.
DISCLOSURE_DETECTORS = frozenset({"canary", "system_prompt", "pii"})


@dataclass
class LintReport:
    """Linter findings."""

    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        """True when there are no errors."""
        return not self.errors


def _normalize(text: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"[^a-z0-9 ]", " ", text.lower())).strip()


def levenshtein_distance(a: str, b: str, limit: int | None = None) -> int:
    """Edit distance; returns ``limit + 1`` early when the distance exceeds ``limit``."""
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    if limit is not None and len(a) - len(b) > limit:
        return limit + 1
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        row_min = i
        for j, cb in enumerate(b, 1):
            value = min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb))
            current.append(value)
            row_min = min(row_min, value)
        if limit is not None and row_min > limit:
            return limit + 1
        previous = current
    return previous[-1]


def levenshtein_similarity(a: str, b: str) -> float:
    """``1 - distance / max(len)`` on normalized text (1.0 = identical)."""
    na, nb = _normalize(a), _normalize(b)
    longest = max(len(na), len(nb))
    if longest == 0:
        return 1.0
    return 1.0 - levenshtein_distance(na, nb) / longest


def _bigrams(text: str) -> set[str]:
    return {text[i : i + 2] for i in range(len(text) - 1)}


def find_near_duplicates(cases: list[AttackCase], limit: float = SIMILARITY_LIMIT) -> list[tuple[str, str, float]]:
    """Return pairs of case ids whose normalized texts are more similar than ``limit``."""
    prepared = [(c.id, _normalize(case_text(c))) for c in cases]
    grams = [_bigrams(t) for _, t in prepared]
    pairs: list[tuple[str, str, float]] = []
    for i in range(len(prepared)):
        for j in range(i + 1, len(prepared)):
            a, b = prepared[i][1], prepared[j][1]
            longest = max(len(a), len(b)) or 1
            if min(len(a), len(b)) / longest < limit:
                continue
            union = grams[i] | grams[j]
            if union and len(grams[i] & grams[j]) / len(union) < 0.6:
                continue
            max_distance = int((1 - limit) * longest)
            distance = levenshtein_distance(a, b, limit=max_distance)
            similarity = 1 - distance / longest
            if similarity > limit:
                pairs.append((prepared[i][0], prepared[j][0], round(similarity, 3)))
    return pairs


def lint_cases(
    cases: list[AttackCase], *, enforce_minimums: bool = True, extra_detectors: set[str] | None = None
) -> LintReport:
    """Lint already-loaded cases (``extra_detectors`` adds plugin detector ids)."""
    report = LintReport()
    known_detectors = DetectorRegistry().known() | (extra_detectors or set())
    for case in cases:
        where = f"{case.id}"
        if case.category != AttackCategory.OVER_REFUSAL and not case.owasp_llm:
            report.errors.append(f"{where}: owasp_llm must list at least one OWASP LLM 2025 id")
        for owasp in case.owasp_llm:
            if owasp not in OWASP_LLM_2025:
                report.errors.append(f"{where}: unknown OWASP id {owasp!r}")
        for atlas in case.mitre_atlas:
            if atlas not in ATLAS_TECHNIQUES:
                report.errors.append(f"{where}: unknown MITRE ATLAS id {atlas!r}")
        if not case.detectors:
            report.errors.append(f"{where}: needs at least one detector")
        for detector in case.detectors:
            if detector not in known_detectors:
                report.errors.append(f"{where}: unknown detector {detector!r}")
        if case.category == AttackCategory.EXCESSIVE_AGENCY:
            if "tool_policy" not in case.detectors:
                report.errors.append(f"{where}: EXCESSIVE_AGENCY cases must use the 'tool_policy' detector")
            for detector in set(case.detectors) & DISCLOSURE_DETECTORS:
                report.errors.append(
                    f"{where}: '{detector}' measures disclosure, not agency; use a DATA_EXFIL/PII_LEAK/"
                    "SYS_PROMPT_LEAK case so findings land in the right category"
                )
        if case.category == AttackCategory.OVER_REFUSAL:
            if "refusal" not in case.detectors:
                report.errors.append(f"{where}: OVER_REFUSAL cases must use the 'refusal' detector")
        elif "refusal" in case.detectors:
            report.errors.append(f"{where}: 'refusal' detector is only valid for OVER_REFUSAL cases")
        for turn in case.turns:
            names = template_names(turn.content)
            if "CANARY" in names:
                report.errors.append(f"{where}: {{{{CANARY}}}} may only appear in poison content, not user turns")
            for name in names:
                if name not in {"CANARY", "ATTACKER_ACCOUNT", "EXFIL_URL", "ATTACKER_EMAIL"}:
                    report.errors.append(f"{where}: unknown template variable {{{{{name}}}}}")
        if case.objective.type == ObjectiveType.tool_call and case.objective.tool not in TOOL_REGISTRY:
            report.errors.append(f"{where}: objective tool {case.objective.tool!r} does not exist")
        if not case.id.startswith(_prefix(case.category)):
            report.warnings.append(f"{where}: id prefix does not match category {case.category.value}")
    ids = Counter(c.id for c in cases)
    for case_id, count in ids.items():
        if count > 1:
            report.errors.append(f"{case_id}: duplicate id ({count} occurrences)")
    for a, b, sim in find_near_duplicates(cases):
        report.errors.append(f"near-duplicate cases {a} and {b} (similarity {sim} > {SIMILARITY_LIMIT})")
    per_category = Counter(c.category for c in cases)
    report.counts = {cat.value: per_category.get(cat, 0) for cat in AttackCategory}
    if enforce_minimums:
        for category, minimum in MIN_CASES.items():
            if per_category.get(category, 0) < minimum:
                report.errors.append(f"{category.value}: {per_category.get(category, 0)} cases < required {minimum}")
    return report


def _prefix(category: AttackCategory) -> str:
    from agentguard.attacks.registry import CATEGORY_INFO

    return CATEGORY_INFO[category].prefix + "-"


def _lint_quality(root: Path, report: LintReport) -> None:
    tasks_path = root / "quality" / "tasks.yaml"
    rag_path = root / "quality" / "rag_qa.yaml"
    corpus = root / "rag_corpus"
    gold_path = root / "judge_gold" / "gold_set.jsonl"
    if tasks_path.exists():
        from agentguard.quality.datasets import load_tasks

        try:
            tasks = load_tasks(tasks_path)
            report.counts["quality_tasks"] = len(tasks)
            if len(tasks) < 30:
                report.errors.append(f"{tasks_path}: {len(tasks)} tasks < required 30")
            for task in tasks:
                for step in task.expected_trajectory:
                    if step.tool not in TOOL_REGISTRY:
                        report.errors.append(f"{task.id}: unknown tool {step.tool!r} in expected_trajectory")
        except DatasetError as exc:
            report.errors.append(str(exc))
    else:
        report.errors.append(f"missing {tasks_path}")
    clean_ids = {p.stem for p in (corpus / "clean").glob("*.md")}
    poisoned_ids = {p.stem for p in (corpus / "poisoned").glob("*.md")}
    report.counts["rag_corpus_clean"] = len(clean_ids)
    report.counts["rag_corpus_poisoned"] = len(poisoned_ids)
    if len(clean_ids) < 30:
        report.errors.append(f"{corpus / 'clean'}: {len(clean_ids)} docs < required 30")
    if len(poisoned_ids) < 10:
        report.errors.append(f"{corpus / 'poisoned'}: {len(poisoned_ids)} docs < required 10")
    if rag_path.exists():
        from agentguard.quality.datasets import load_rag_questions

        try:
            questions = load_rag_questions(rag_path)
            report.counts["rag_questions"] = len(questions)
            if len(questions) < 20:
                report.errors.append(f"{rag_path}: {len(questions)} questions < required 20")
            for question in questions:
                for doc in question.relevant_docs:
                    if doc not in clean_ids:
                        report.errors.append(f"{question.id}: relevant doc {doc!r} not in the clean corpus")
        except DatasetError as exc:
            report.errors.append(str(exc))
    else:
        report.errors.append(f"missing {rag_path}")
    if gold_path.exists():
        from agentguard.judges.calibration import load_gold_set

        try:
            gold = load_gold_set(gold_path)
            report.counts["judge_gold"] = len(gold)
            if len(gold) < 120:
                report.errors.append(f"{gold_path}: {len(gold)} examples < required 120")
            by_rubric: dict[str, list[bool]] = {}
            for item in gold:
                by_rubric.setdefault(item.rubric, []).append(item.label)
            for rubric, labels in by_rubric.items():
                share = sum(labels) / len(labels)
                if not 0.35 <= share <= 0.65:
                    report.errors.append(f"{gold_path}: rubric {rubric} is unbalanced ({share:.0%} violated)")
        except DatasetError as exc:
            report.errors.append(str(exc))
    else:
        report.errors.append(f"missing {gold_path}")
    for path in sorted((corpus / "poisoned").glob("*.md")):
        text = path.read_text(encoding="utf-8")
        for name in template_names(text):
            if name not in {"CANARY", "ATTACKER_ACCOUNT", "EXFIL_URL", "ATTACKER_EMAIL"}:
                report.errors.append(f"{path}: unknown template variable {{{{{name}}}}}")


def lint_all(root: str | Path = "datasets", *, enforce_minimums: bool = True) -> LintReport:
    """Lint every dataset under ``root`` (attacks, benign, quality, RAG, judge gold)."""
    base = Path(root)
    report = LintReport()
    paths = [p for p in (base / "attacks", base / "benign") if p.exists()]
    if not paths:
        report.errors.append(f"no attack datasets found under {base}")
        return report
    try:
        loaded = load_cases(paths, strict=False)
    except DatasetError as exc:
        report.errors.append(str(exc))
        return report
    report.errors.extend(w for w in loaded.warnings)
    from agentguard.plugins import register_detectors

    plugin_detectors = set(register_detectors(DetectorRegistry()))
    case_report = lint_cases(loaded.cases, enforce_minimums=enforce_minimums, extra_detectors=plugin_detectors)
    report.errors.extend(case_report.errors)
    report.warnings.extend(case_report.warnings)
    report.counts.update(case_report.counts)
    report.counts["total_attack_cases"] = sum(
        v for k, v in case_report.counts.items() if k != AttackCategory.OVER_REFUSAL.value
    )
    _lint_quality(base, report)
    return report
