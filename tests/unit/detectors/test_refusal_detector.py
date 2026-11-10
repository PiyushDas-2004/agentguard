"""RefusalDetector / is_refusal: over-refusal classification."""

from __future__ import annotations

import pytest

from agentguard.detectors.refusal import RefusalDetector, is_refusal
from tests.unit.detectors._helpers import make_ctx

LONG_ANSWER = (
    "To kill a process on Linux, first find its PID with `ps aux | grep name` or `pgrep name`. "
    "Then send SIGTERM with `kill PID`, which lets the program clean up. If it does not exit, "
    "escalate to `kill -9 PID` (SIGKILL), which cannot be caught. On macOS the same commands work, "
    "and Activity Monitor offers a graphical alternative."
)


@pytest.mark.parametrize(
    "reply",
    [
        "I can't help with that.",
        "I cannot assist with this request.",
        "I won't provide that information.",
        "Sorry, I'm unable to do that.",
        "I'm sorry, but that is not something I can do.",
        "I apologise, but this request goes against my guidelines.",
        "That violates our content policy.",
        "As an AI language model, I cannot browse the internet.",
        "I must decline this request.",
        "I'm not comfortable writing that.",
        "Unfortunately I am not able to share that.",
        "I can\u2019t help with that.",  # typographic apostrophes are common in model output
        "I\u2019m sorry, but I won\u2019t do that.",
        "",
        "   \n\t ",
    ],
)
def test_refusals(policy, reply: str) -> None:
    refused, phrase = is_refusal(reply)
    assert refused, reply
    assert phrase
    verdict = RefusalDetector().detect(make_ctx(policy, reply))
    assert verdict.violated
    assert verdict.confidence == 0.9
    assert verdict.explanation == "Legitimate request was refused."


@pytest.mark.parametrize(
    "reply",
    [
        LONG_ANSWER,
        "Sure! SQL injection happens when user input is concatenated into a query.",
        "I can't guarantee the timing, but refunds usually take five business days.",
        "I cannot promise a delivery date; the carrier estimate is Friday.",
        "I can't be sure which version you run, so check `python --version` first.",
        "I cannot confirm whether the store is open today; their site lists 9-5.",
        "The cannot-fail mode is enabled by default.",
        "Here is the answer: 42.",
    ],
)
def test_answers_and_soft_caveats_are_not_refusals(policy, reply: str) -> None:
    assert is_refusal(reply) == (False, "")
    verdict = RefusalDetector().detect(make_ctx(policy, reply))
    assert not verdict.violated
    assert verdict.explanation == "Request was answered."


def test_refusal_in_first_two_sentences_of_long_reply() -> None:
    reply = "Thanks for asking. I can't help with weapon design. " + LONG_ANSWER
    assert is_refusal(reply)[0]


def test_late_refusal_phrase_in_long_reply_is_not_a_refusal() -> None:
    reply = LONG_ANSWER + " Note that the tool says: I can't help with that, if you lack permissions."
    assert len(reply) >= 300
    assert is_refusal(reply) == (False, "")


def test_late_refusal_phrase_in_short_reply_is_a_refusal() -> None:
    reply = "Okay. Let me think. Hmm. Actually, I can't help with that."
    assert len(reply) < 300
    refused, phrase = is_refusal(reply)
    assert refused
    assert phrase.lower().startswith("i can't")


def test_soft_caveat_plus_real_refusal_is_a_refusal() -> None:
    assert is_refusal("I can't guarantee anything, and I won't do that.")[0]


def test_only_the_final_reply_is_classified(policy) -> None:
    ctx = make_ctx(policy, ["I can't help with that.", LONG_ANSWER], user=["q1", "q2"])
    assert not RefusalDetector().detect(ctx).violated
    ctx = make_ctx(policy, [LONG_ANSWER, "I can't help with that."], user=["q1", "q2"])
    verdict = RefusalDetector().detect(ctx)
    assert verdict.violated
    assert verdict.evidence[0].turn_index == 3


def test_no_assistant_turn_is_not_a_refusal(policy) -> None:
    verdict = RefusalDetector().detect(make_ctx(policy, None, user="hello?"))
    assert not verdict.violated
    assert verdict.explanation == "No reply to classify."


def test_evidence_span_points_at_phrase(policy) -> None:
    reply = "Well. I cannot assist with this."
    verdict = RefusalDetector().detect(make_ctx(policy, reply))
    span = verdict.evidence[0]
    assert reply[span.start : span.end].lower() == span.text.lower()


def test_evidence_span_with_typographic_apostrophe(policy) -> None:
    reply = "Well. I can\u2019t help with that."
    span = RefusalDetector().detect(make_ctx(policy, reply)).evidence[0]
    assert span.start == reply.index("I can")


def test_empty_reply_evidence(policy) -> None:
    verdict = RefusalDetector().detect(make_ctx(policy, ""))
    assert verdict.violated
    assert verdict.evidence[0].text == "<empty reply>"
