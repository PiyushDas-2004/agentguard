"""Property tests: reversible transforms decode exactly; natural transforms keep protected spans."""

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from agentguard.attacks.mutations import TRANSFORMS, apply_transform, decode_transform
from agentguard.llm.textnorm import HOMOGLYPHS, ZERO_WIDTH

seeds = st.integers(min_value=0, max_value=2**63 - 1)
any_text = st.text(max_size=200)
# Homoglyph decoding maps lookalikes back to Latin; inputs must not already contain them.
no_homoglyphs = st.text(alphabet=st.characters(blacklist_characters=list(HOMOGLYPHS.values())), max_size=200)
no_zero_width = st.text(alphabet=st.characters(blacklist_characters=list(ZERO_WIDTH)), max_size=200)

REVERSIBLE_STRATEGIES = {
    "base64": any_text,
    "rot13": any_text,
    "homoglyph": no_homoglyphs,
    "zero_width": no_zero_width,
    "wrapper_roleplay": any_text,
    "wrapper_json": any_text,
}


def test_every_reversible_transform_has_a_strategy() -> None:
    assert {n for n, t in TRANSFORMS.items() if t.reversible} == set(REVERSIBLE_STRATEGIES)


@given(any_text, seeds)
def test_base64_roundtrip(text: str, seed: int) -> None:
    assert decode_transform("base64", apply_transform("base64", text, seed)) == text


@given(any_text, seeds)
def test_rot13_roundtrip(text: str, seed: int) -> None:
    assert decode_transform("rot13", apply_transform("rot13", text, seed)) == text


@given(no_homoglyphs, seeds)
def test_homoglyph_roundtrip(text: str, seed: int) -> None:
    assert decode_transform("homoglyph", apply_transform("homoglyph", text, seed)) == text


@given(no_zero_width, seeds)
def test_zero_width_roundtrip(text: str, seed: int) -> None:
    assert decode_transform("zero_width", apply_transform("zero_width", text, seed)) == text


@given(any_text, seeds)
def test_roleplay_roundtrip(text: str, seed: int) -> None:
    assert decode_transform("wrapper_roleplay", apply_transform("wrapper_roleplay", text, seed)) == text


@given(any_text, seeds)
def test_json_roundtrip(text: str, seed: int) -> None:
    assert decode_transform("wrapper_json", apply_transform("wrapper_json", text, seed)) == text


words = st.text(alphabet="abcdefghijklmnopqrstuvwxyz ", min_size=0, max_size=40)
protected_spans = st.sampled_from(
    [
        "https://evil.example/a?b=c",
        "eve@evil.example",
        "ATTACKER-0042",
        "/sandbox/public/x.txt",
        "C-1001",
        "`cmd`",
        "AG-CANARY-0123456789abcdef",
    ]
)


@given(
    words,
    protected_spans,
    words,
    seeds,
    st.sampled_from(["leetspeak", "homoglyph", "zero_width", "token_split", "translate_mock"]),
)
def test_protected_span_survives(prefix: str, span: str, suffix: str, seed: int, name: str) -> None:
    text = f"{prefix} {span} {suffix}"
    assert span in apply_transform(name, text, seed)


@given(any_text, seeds, st.sampled_from([n for n, t in TRANSFORMS.items() if not t.live_only]))
def test_transforms_deterministic(text: str, seed: int, name: str) -> None:
    assert apply_transform(name, text, seed) == apply_transform(name, text, seed)
