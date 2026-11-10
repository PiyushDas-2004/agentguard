"""Calibration metrics vs hand-computed confusion matrices, gold-set loading, real calibration."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from agentguard.core.errors import DatasetError
from agentguard.judges.base import Judge, JudgeRequest, JudgeResult
from agentguard.judges.calibration import (
    KAPPA_TARGET,
    binary_metrics,
    calibrate,
    cohen_kappa,
    load_gold_set,
)
from agentguard.judges.mock_judge import MockJudge

GOLD = Path("datasets/judge_gold/gold_set.jsonl")


class TestCohenKappa:
    def test_hand_computed(self) -> None:
        # tp=20 fp=5 tn=15 fn=10, n=50: po=0.7, pe=0.5*0.6+0.5*0.4=0.5 → kappa=0.4
        assert cohen_kappa(20, 5, 15, 10) == pytest.approx(0.4)

    def test_perfect_and_chance(self) -> None:
        assert cohen_kappa(10, 0, 10, 0) == 1.0
        assert cohen_kappa(5, 5, 5, 5) == pytest.approx(0.0)
        assert cohen_kappa(0, 10, 0, 10) == pytest.approx(-1.0)

    def test_degenerate(self) -> None:
        assert cohen_kappa(0, 0, 0, 0) == 0.0
        assert cohen_kappa(7, 0, 0, 0) == 1.0  # both raters always "yes": expected == 1
        assert cohen_kappa(0, 0, 9, 0) == 1.0


class TestBinaryMetrics:
    def test_hand_computed(self) -> None:
        pairs = [(True, True)] * 3 + [(True, False)] * 1 + [(False, False)] * 4 + [(False, True)] * 2
        m = binary_metrics(pairs)
        assert (m.n, m.tp, m.fp, m.tn, m.fn) == (10, 3, 1, 4, 2)
        assert m.accuracy == 0.7
        assert m.precision == 0.75
        assert m.recall == 0.6
        assert m.f1 == round(2 * 0.75 * 0.6 / 1.35, 4)
        # po=0.7, pe=0.4*0.5+0.6*0.5=0.5 → 0.4
        assert m.kappa == 0.4

    def test_empty_and_zero_division(self) -> None:
        m = binary_metrics([])
        assert (m.n, m.accuracy, m.precision, m.recall, m.f1, m.kappa) == (0, 0.0, 0.0, 0.0, 0.0, 0.0)
        m = binary_metrics([(False, False), (False, False)])
        assert m.precision == 0.0 and m.recall == 0.0 and m.f1 == 0.0 and m.accuracy == 1.0


def _line(**overrides: object) -> str:
    data = {"id": "G-1", "rubric": "jailbreak", "user_input": "u", "response": "r", "label": True}
    data.update(overrides)
    return json.dumps(data)


class TestLoadGoldSet:
    def test_real(self) -> None:
        gold = load_gold_set(GOLD)
        assert len(gold) >= 120
        assert {g.rubric for g in gold} <= {"jailbreak", "task_success", "faithfulness", "refusal"}

    def test_missing(self, tmp_path: Path) -> None:
        with pytest.raises(DatasetError, match="gold set not found"):
            load_gold_set(tmp_path / "x.jsonl")

    def test_bad_json_line_number(self, tmp_path: Path) -> None:
        f = tmp_path / "g.jsonl"
        f.write_text(_line() + "\n\n{oops\n")
        with pytest.raises(DatasetError, match=r"g\.jsonl:3:"):
            load_gold_set(f)

    def test_schema_error(self, tmp_path: Path) -> None:
        f = tmp_path / "g.jsonl"
        f.write_text(_line(extra_field=1) + "\n")
        with pytest.raises(DatasetError, match=r"g\.jsonl:1:"):
            load_gold_set(f)

    def test_duplicate_ids(self, tmp_path: Path) -> None:
        f = tmp_path / "g.jsonl"
        f.write_text(_line() + "\n" + _line() + "\n")
        with pytest.raises(DatasetError, match="duplicate example ids"):
            load_gold_set(f)

    def test_blank_lines_skipped(self, tmp_path: Path) -> None:
        f = tmp_path / "g.jsonl"
        f.write_text("\n" + _line() + "\n   \n" + _line(id="G-2", label=False) + "\n")
        assert [g.id for g in load_gold_set(f)] == ["G-1", "G-2"]


class ScriptedJudge(Judge):
    id = "scripted"

    def __init__(self, answers: list[bool | None]) -> None:
        self.answers = list(answers)

    async def judge(self, request: JudgeRequest) -> JudgeResult:
        value = self.answers.pop(0)
        return JudgeResult(judge_id=self.id, rubric=request.rubric, violated=value, inconclusive=value is None)


class TestCalibrate:
    def _gold(self, tmp_path: Path) -> list:
        f = tmp_path / "g.jsonl"
        rows = [
            _line(id="A", rubric="jailbreak", label=True),
            _line(id="B", rubric="jailbreak", label=False),
            _line(id="C", rubric="refusal", label=True),
            _line(id="D", rubric="refusal", label=False),
        ]
        f.write_text("\n".join(rows))
        return load_gold_set(f)

    def test_inconclusive_counts_as_wrong(self, tmp_path: Path) -> None:
        report = asyncio.run(calibrate(ScriptedJudge([True, None, None, False]), self._gold(tmp_path)))
        assert report.inconclusive == 2
        assert report.disagreements == ["B", "C"]
        assert (report.overall.tp, report.overall.fp, report.overall.tn, report.overall.fn) == (1, 1, 1, 1)
        assert report.overall.kappa == 0.0
        assert not report.meets_target
        assert list(report.per_rubric) == ["jailbreak", "refusal"]
        assert report.per_rubric["jailbreak"].n == 2
        assert report.kappa_target == KAPPA_TARGET

    def test_perfect(self, tmp_path: Path) -> None:
        report = asyncio.run(calibrate(ScriptedJudge([True, False, True, False]), self._gold(tmp_path)))
        assert report.overall.kappa == 1.0 and report.meets_target and report.disagreements == []
        assert report.judge_id == "scripted"

    def test_mock_judge_on_real_gold_set(self) -> None:
        report = asyncio.run(calibrate(MockJudge(), load_gold_set(GOLD)))
        assert report.overall.n >= 120
        assert report.inconclusive == 0
        o = report.overall
        assert o.tp + o.fp + o.tn + o.fn == o.n
        assert len(report.disagreements) == o.fp + o.fn
        assert report.meets_target is (o.kappa >= KAPPA_TARGET)
        assert set(report.per_rubric) == {"jailbreak", "task_success", "faithfulness", "refusal"}
        assert sum(m.n for m in report.per_rubric.values()) == o.n
        assert sum(m.tp for m in report.per_rubric.values()) == o.tp
        # the rule-based judge agrees with the gold labels better than chance on clear-cut jailbreaks
        assert report.per_rubric["jailbreak"].kappa > 0
