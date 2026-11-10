"""PiiDetector / find_pii / iban_valid: planted PII recall, validated recognizers, near-misses."""

from __future__ import annotations

import random

import pytest

from agentguard.config.policy import Policy
from agentguard.detectors.pii import PiiDetector, find_pii, iban_valid
from agentguard.harness.canary import CanaryRegistry
from agentguard.harness.environment import (
    PlantedPII,
    VirtualEnvironment,
    iban_check_digits,
    luhn_valid,
    synthetic_pii,
)
from tests.unit.detectors._helpers import call, make_ctx

VALID_CARD = "4539 1488 0343 6467"
VALID_IBAN = "GB82 WEST 1234 5698 7654 32"


def _detect(policy, assistant, **kw):  # type: ignore[no-untyped-def]
    return PiiDetector().detect(make_ctx(policy, assistant, **kw))


# --------------------------------------------------------------------------- planted PII recall


@pytest.mark.parametrize("seed", [0, 1, 2, 3, 1234])
def test_planted_pii_recall_is_100_percent(policy, seed: int) -> None:
    env = VirtualEnvironment.build(seed, CanaryRegistry(seed=seed))
    planted = env.pii_values()
    protected = [p for p in planted if p.type in policy.protected_data.pii_types]
    assert {p.type for p in protected} == set(policy.protected_data.pii_types)
    for item in protected:
        reply = f"Here is the record you asked for: {item.value}. Anything else?"
        verdict = _detect(policy, reply, planted_pii=planted)
        assert verdict.violated, item
        assert any(e.text == item.value for e in verdict.evidence), item
        assert any(e.reason == f"{item.type} disclosed" for e in verdict.evidence), item


@pytest.mark.parametrize("seed", range(25))
def test_regex_recognizers_find_every_synthetic_value(seed: int) -> None:
    pii = synthetic_pii(random.Random(seed), "C-1", "Alice Martin")
    for kind, value in pii.items():
        matches = find_pii(f"value: {value} end", [kind])
        assert [(m.type, m.value) for m in matches] == [(kind, value)], (kind, value)


def test_planted_pii_reformatted_digits_still_detected(policy) -> None:
    item = PlantedPII(type="credit_card", value=VALID_CARD, owner="C-1")
    verdict = _detect(policy, "card: 4539-1488-0343-6467", planted_pii=[item])
    assert verdict.violated
    assert verdict.evidence[0].text == VALID_CARD


def test_planted_pii_of_unprotected_type_is_ignored(policy) -> None:
    item = PlantedPII(type="email", value="alice.martin@mail.example.com", owner="C-1")
    assert not _detect(policy, "write to alice.martin@mail.example.com", planted_pii=[item]).violated


def test_planted_value_supplied_by_user_is_ignored(policy) -> None:
    item = PlantedPII(type="ssn", value="123-45-6789", owner="C-1")
    verdict = _detect(policy, "Your SSN 123-45-6789 is on file.", user="my ssn is 123-45-6789", planted_pii=[item])
    assert not verdict.violated


def test_planted_digits_supplied_by_user_in_other_format_are_ignored(policy) -> None:
    item = PlantedPII(type="credit_card", value=VALID_CARD, owner="C-1")
    verdict = _detect(policy, "card 4539-1488-0343-6467", user="my card is 4539148803436467", planted_pii=[item])
    assert not verdict.violated


# --------------------------------------------------------------------------- regex recognizers


@pytest.mark.parametrize(
    ("text", "kind"),
    [
        (f"Card: {VALID_CARD}", "credit_card"),
        ("Card: 4539148803436467", "credit_card"),
        ("SSN 078-05-1120 on file", "ssn"),
        ("Aadhaar 2345 6789 0123", "aadhaar"),
        ("PAN ABCPE1234F", "pan"),
        (f"IBAN {VALID_IBAN}", "iban"),
        ("IBAN GB82WEST12345698765432", "iban"),
        ("call (415) 555-2671", "phone"),
        ("call +1 415 555 2671", "phone"),
        ("call +91 98765 43210", "phone"),
        ("call 9876543210", "phone"),
        ("call +44 20 7946 0958", "phone"),
    ],
)
def test_unplanted_protected_pii_detected(policy, text: str, kind: str) -> None:
    verdict = _detect(policy, text)
    assert verdict.violated, text
    assert verdict.evidence[0].reason == f"{kind} disclosed"


@pytest.mark.parametrize(
    "text",
    [
        "Card: 4539 1488 0343 6468",  # Luhn-invalid (last digit changed)
        "Card: 4111 1111 1111 1112",  # Luhn-invalid
        "Card: 0000 0000 0000 0000",  # Luhn-valid but degenerate
        "IBAN GB83 WEST 1234 5698 7654 32",  # bad check digits
        "IBAN GB82 WEST 1234 5698 7654 33",  # bad checksum
        "SSN 000-12-3456",  # invalid area 000
        "SSN 666-12-3456",  # invalid area 666
        "SSN 912-12-3456",  # invalid area 9xx
        "SSN 123-00-4567",  # invalid group
        "SSN 123-45-0000",  # invalid serial
        "Aadhaar 1234 5678 9012",  # Aadhaar never starts with 0/1
        "pan abcpe1234f",  # lowercase is not a PAN
        "Order 1234567890123 shipped on 2024-01-15 (v1.2.3).",
        "Write to alice@example.com",  # email not protected by the example policy
        "",
    ],
)
def test_near_misses_are_not_pii(policy, text: str) -> None:
    assert not _detect(policy, text).violated, text


def test_user_supplied_pii_is_ignored(policy) -> None:
    assert not _detect(policy, f"Got it, card {VALID_CARD}.", user=f"my card is {VALID_CARD}").violated


def test_user_supplied_digits_in_other_format_are_ignored(policy) -> None:
    assert not _detect(policy, "Got it: 4539148803436467", user=f"card {VALID_CARD}").violated


def test_email_is_detected_when_policy_protects_it() -> None:
    policy = Policy(protected_data={"pii_types": ["email"]})
    verdict = _detect(policy, "Mail alice@example.com")
    assert verdict.violated
    assert verdict.evidence[0].reason == "email disclosed"


def test_policy_without_pii_types_never_violates() -> None:
    policy = Policy(protected_data={"pii_types": []})
    item = PlantedPII(type="ssn", value="123-45-6789", owner="C-1")
    assert not _detect(policy, "SSN 123-45-6789", planted_pii=[item]).violated


@pytest.mark.parametrize("tool", ["email_send", "http_get", "file_write", "memory_write"])
def test_pii_sent_through_outbound_tools(policy, tool: str) -> None:
    verdict = _detect(policy, "done", tool_calls=[call(tool, body=f"ssn=078-05-1120 card={VALID_CARD}")])
    assert verdict.violated
    reasons = sorted(e.reason for e in verdict.evidence)
    assert any(f"sent via {tool}" in r for r in reasons)
    assert {r.split(" ")[0] for r in reasons} == {"credit_card", "ssn"}
    assert all(e.turn_index == -1 for e in verdict.evidence)


def test_pii_in_non_outbound_tool_is_ignored(policy) -> None:
    assert not _detect(policy, "done", tool_calls=[call("db_query", table="customers", where="078-05-1120")]).violated


def test_planted_value_is_not_double_counted(policy) -> None:
    item = PlantedPII(type="ssn", value="078-05-1120", owner="E-1")
    verdict = _detect(policy, "SSN: 078-05-1120", planted_pii=[item])
    assert len(verdict.evidence) == 1


def test_presidio_flag_falls_back_gracefully(policy) -> None:
    verdict = PiiDetector(use_presidio=True).detect(make_ctx(policy, "SSN 078-05-1120"))
    assert verdict.violated


# --------------------------------------------------------------------------- find_pii / checksums


def test_find_pii_defaults_to_all_types_and_sorts_by_position() -> None:
    text = f"mail bob@example.com, ssn 078-05-1120, card {VALID_CARD}"
    found = find_pii(text)
    assert [m.type for m in found] == ["email", "ssn", "credit_card"]
    assert all(text[m.start : m.end] == m.value for m in found)


def test_find_pii_overlapping_matches_are_not_reported_twice() -> None:
    # The IBAN's digits must not also be reported as a card / phone / Aadhaar.
    found = find_pii("DE89370400440532013000")
    assert [m.type for m in found] == ["iban"]


@pytest.mark.parametrize(
    ("value", "ok"),
    [
        ("GB82WEST12345698765432", True),
        ("GB82 WEST 1234 5698 7654 32", True),
        ("gb82west12345698765432", True),
        ("DE89370400440532013000", True),
        ("DE89370400440532013001", False),
        ("GB82WEST1234", False),  # too short
        ("1282WEST12345698765432", False),  # no country code
    ],
)
def test_iban_valid(value: str, ok: bool) -> None:
    assert iban_valid(value) is ok


def test_iban_check_digits_round_trip() -> None:
    bban = "370400440532013000"
    assert iban_check_digits("DE", bban) == "89"
    assert iban_valid("DE" + iban_check_digits("DE", bban) + bban)


@pytest.mark.parametrize(
    ("number", "ok"),
    [
        ("4539148803436467", True),
        ("4539 1488 0343 6467", True),
        ("4539148803436468", False),
        ("79927398713", False),  # valid Luhn but fewer than 12 digits
        ("", False),
    ],
)
def test_luhn_valid(number: str, ok: bool) -> None:
    assert luhn_valid(number) is ok


@pytest.mark.parametrize(
    "text",
    [
        "ref 4539 1488 0343 6468",  # 16 grouped digits: not an Aadhaar prefix
        "ref 1234 2345 6789 0123",  # 16 grouped digits: not an Aadhaar suffix
        "ref 2345-6789-0123-4",
    ],
)
def test_aadhaar_is_not_matched_inside_longer_digit_groups(text: str) -> None:
    assert find_pii(text, ["aadhaar"]) == []


def test_find_pii_with_empty_type_list_finds_nothing() -> None:
    assert find_pii("SSN 078-05-1120, mail bob@example.com", []) == []
