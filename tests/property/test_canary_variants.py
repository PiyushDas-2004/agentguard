"""Property tests: every canary variant is found inside arbitrary surrounding text, and text
without the token produces no hits."""

from __future__ import annotations

import codecs

from hypothesis import assume, given
from hypothesis import strategies as st

from agentguard.harness.canary import CANARY_PREFIX, canary_variants, find_canaries

VARIANTS = sorted(canary_variants("AG-CANARY-0000000000000000"))

tokens = st.text(alphabet="0123456789abcdef", min_size=16, max_size=16).map(lambda s: CANARY_PREFIX + s)
# Arbitrary Unicode prose (no surrogates); a separator keeps the encoded form a distinct word,
# just as it would be in model output.
surrounding = st.text(st.characters(blacklist_categories=("Cs",)), max_size=120)
separators = st.sampled_from([" ", "\n", "\t", ": ", " (", ") ", ' "', "> "])


def _compact(text: str) -> str:
    return "".join(ch.lower() for ch in text if ch.isascii() and ch.isalnum())


@given(
    token=tokens,
    variant=st.sampled_from(VARIANTS),
    before=surrounding,
    after=surrounding,
    sep1=separators,
    sep2=separators,
)
def test_variant_found_in_random_text(token: str, variant: str, before: str, after: str, sep1: str, sep2: str) -> None:
    encoded = canary_variants(token)[variant]
    text = f"{before}{sep1}{encoded}{sep2}{after}"
    hits = find_canaries(text, [token])
    assert any(h.token == token for h in hits), (variant, text)
    for hit in hits:
        assert 0 <= hit.start <= hit.end <= len(text)
        assert hit.matched == text[hit.start : hit.end]


@given(token=tokens, variant=st.sampled_from(VARIANTS), before=surrounding, after=surrounding)
def test_variant_found_among_other_canaries(token: str, variant: str, before: str, after: str) -> None:
    decoy = CANARY_PREFIX + token[len(CANARY_PREFIX) :][::-1]
    assume(decoy != token)
    text = f"{before}\n{canary_variants(token)[variant]}\n{after}"
    found = {h.token for h in find_canaries(text, [decoy, token])}
    assert token in found


@given(token=tokens, text=st.text(st.characters(blacklist_categories=("Cs",)), max_size=300))
def test_random_text_without_token_has_no_hits(token: str, text: str) -> None:
    suffix = token[len(CANARY_PREFIX) :]
    # Exclude the (astronomically unlikely) case where the text really contains the token.
    for reading in (text, text[::-1], codecs.encode(text, "rot_13")):
        assume(suffix not in _compact(reading))
    assert find_canaries(text, [token]) == []


@given(token=tokens, words=st.lists(st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789", max_size=12)))
def test_alphanumeric_prose_without_token_has_no_hits(token: str, words: list[str]) -> None:
    text = " ".join(words)
    suffix = token[len(CANARY_PREFIX) :]
    assume(suffix not in _compact(text) and suffix not in _compact(text[::-1]))
    assert find_canaries(text, [token]) == []


@given(
    token=tokens,
    variant=st.sampled_from(["base64", "base64_urlsafe", "hex", "suffix", "lowercase", "spaced"]),
    before=st.text(alphabet="abcdefghijklmnopqrstuvwxyzABCDEF0123456789", max_size=8),
    after=st.text(alphabet="abcdefghijklmnopqrstuvwxyzABCDEF0123456789", max_size=8),
)
def test_encoded_variant_glued_to_alphanumerics(token: str, variant: str, before: str, after: str) -> None:
    # No separator at all: stray characters glued to the encoded payload must not hide it.
    text = before + canary_variants(token)[variant] + after
    assert any(h.token == token for h in find_canaries(text, [token])), text
