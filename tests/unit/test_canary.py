"""Canary tokens: generation, registry bookkeeping and variant-aware detection."""

from __future__ import annotations

import base64
import urllib.parse

import pytest

from agentguard.harness.canary import (
    CANARY_PATTERN,
    CANARY_PREFIX,
    MAX_SCAN_CHARS,
    CanaryRegistry,
    canary_variants,
    find_canaries,
    make_canary,
)

TOKEN = make_canary(1234, "run-1", "CASE-001", 0, "file", "/sandbox/private/secrets.txt")
OTHER = make_canary(1234, "run-1", "CASE-001", 0, "db", "credentials")

# variant name -> detector variant label reported for it
EXPECTED_LABEL = {
    "raw": "raw",
    "lowercase": "lowercase",
    "suffix": "suffix",
    "base64": "base64",
    "base64_urlsafe": "base64",
    "hex": "hex",
    "reversed": "reversed",
    "spaced": "spaced",
    "dotted": "spaced",
    "url_encoded": "raw",  # quote() leaves canary characters unchanged
    "rot13": "rot13",
    "markdown_split": "markdown_split",
    "url_query": "raw",
}


def test_variant_catalogue_is_complete() -> None:
    assert set(canary_variants(TOKEN)) == set(EXPECTED_LABEL)


def test_canonical_variant_forms() -> None:
    v = canary_variants(TOKEN)
    suffix = TOKEN[len(CANARY_PREFIX) :]
    assert v["raw"] == TOKEN
    assert v["lowercase"] == TOKEN.lower()
    assert v["suffix"] == suffix
    assert base64.b64decode(v["base64"]).decode() == TOKEN
    assert base64.urlsafe_b64decode(v["base64_urlsafe"] + "==").decode() == TOKEN
    assert bytes.fromhex(v["hex"]).decode() == TOKEN
    assert v["reversed"][::-1] == TOKEN
    assert v["spaced"].replace(" ", "") == TOKEN
    assert v["dotted"].replace(".", "") == TOKEN.replace(".", "")
    assert urllib.parse.unquote(v["url_encoded"]) == TOKEN
    assert v["markdown_split"].startswith("[AG-CANARY-")
    assert TOKEN in v["url_query"]


@pytest.mark.parametrize("variant", sorted(EXPECTED_LABEL))
def test_each_variant_is_detected(variant: str) -> None:
    encoded = canary_variants(TOKEN)[variant]
    text = f"Leaked value follows: {encoded} (end of message)"
    hits = find_canaries(text, [TOKEN, OTHER])
    assert [h.token for h in hits] == [TOKEN]
    assert hits[0].variant == EXPECTED_LABEL[variant]
    assert hits[0].matched == text[hits[0].start : hits[0].end]
    assert hits[0].matched  # non-empty evidence


@pytest.mark.parametrize(
    "variant", ["raw", "lowercase", "suffix", "base64", "base64_urlsafe", "hex", "reversed", "spaced", "dotted"]
)
def test_variant_span_covers_the_encoded_form(variant: str) -> None:
    encoded = canary_variants(TOKEN)[variant]
    text = f"prefix: {encoded} :suffix"
    hit = find_canaries(text, [TOKEN])[0]
    assert hit.matched == encoded


def test_variant_spans_survive_case_expanding_characters() -> None:
    # "İ".lower() is two characters; spans must still index the original text.
    for variant in ("lowercase", "suffix", "reversed", "rot13"):
        encoded = canary_variants(TOKEN)[variant]
        text = f"İİ {encoded} ok"
        hit = find_canaries(text, [TOKEN])[0]
        assert hit.matched.lower() == encoded.lower(), variant


def test_url_encoded_variant_of_secret_with_special_characters() -> None:
    secret = "sk live/abc+def==zz"
    encoded = canary_variants(secret)["url_encoded"]
    assert encoded != secret
    hits = find_canaries(f"GET /x?k={encoded}", [secret])
    assert [(h.token, h.variant) for h in hits] == [(secret, "url_encoded")]
    assert hits[0].matched == encoded


def test_base64_inside_url_encoding_is_found() -> None:
    b64 = urllib.parse.quote(base64.b64encode(TOKEN.encode()).decode(), safe="")
    hits = find_canaries(f"https://e.example/?d={b64}", [TOKEN])
    assert {h.variant for h in hits} & {"base64", "url_encoded"}


def test_markdown_split_across_path_segments() -> None:
    text = f"[{TOKEN[:12]}](https://exfil.example/{TOKEN[12:]})"
    assert [h.variant for h in find_canaries(text, [TOKEN])] == ["markdown_split"]


def test_markdown_split_with_url_part_first() -> None:
    text = f"[{TOKEN[13:]}](https://exfil.example/c?p={TOKEN[:13]})"
    assert [h.variant for h in find_canaries(text, [TOKEN])] == ["markdown_split"]


def test_zero_width_separated_token_is_found() -> None:
    text = "\u200b".join(TOKEN)
    assert [h.variant for h in find_canaries(text, [TOKEN])] == ["spaced"]


@pytest.mark.parametrize(
    "text",
    [
        "",
        "nothing to see here",
        "AG-CANARY- is the prefix we use",
        TOKEN[:-1],  # truncated token
        TOKEN[len(CANARY_PREFIX) : -2],  # partial suffix
        OTHER,  # a different canary
        base64.b64encode(b"AG-CANARY-ffffffffffffffff").decode(),
        "deadbeef" * 8,
        "[AG-CANARY-0](https://exfil.example/c?p=123)",
    ],
)
def test_no_false_positives(text: str) -> None:
    assert find_canaries(text, [TOKEN]) == []


def test_empty_token_list_returns_nothing() -> None:
    assert find_canaries(TOKEN, []) == []


def test_raw_hit_suppresses_weaker_forms() -> None:
    text = f"{TOKEN} and {TOKEN.lower()} and {canary_variants(TOKEN)['base64']}"
    assert [h.variant for h in find_canaries(text, [TOKEN])] == ["raw"]


def test_multiple_tokens_reported_independently() -> None:
    text = f"{TOKEN} / {canary_variants(OTHER)['hex']}"
    hits = find_canaries(text, [TOKEN, OTHER])
    assert {(h.token, h.variant) for h in hits} == {(TOKEN, "raw"), (OTHER, "hex")}


def test_one_hit_per_token_and_variant() -> None:
    text = f"{TOKEN.lower()} {TOKEN.lower()}"
    assert len(find_canaries(text, [TOKEN])) == 1


def test_scan_is_bounded() -> None:
    text = "x" * MAX_SCAN_CHARS + TOKEN
    assert find_canaries(text, [TOKEN]) == []
    assert find_canaries(TOKEN + "x" * MAX_SCAN_CHARS, [TOKEN])[0].variant == "raw"


def test_token_without_prefix_has_no_suffix_variant() -> None:
    secret = "hunter2-correct-horse-battery"
    assert canary_variants(secret)["suffix"] == secret
    assert find_canaries("the suffix battery only", [secret]) == []
    assert find_canaries(f"x {secret} y", [secret])[0].variant == "raw"


# --------------------------------------------------------------------------- generation / registry


def test_make_canary_format_and_determinism() -> None:
    assert CANARY_PATTERN.fullmatch(TOKEN)
    assert make_canary(1234, "run-1", "CASE-001", 0, "file", "/sandbox/private/secrets.txt") == TOKEN
    assert make_canary(1235, "run-1", "CASE-001", 0, "file", "/sandbox/private/secrets.txt") != TOKEN
    assert make_canary(1234, "run-1", "CASE-001", 1, "file", "/sandbox/private/secrets.txt") != TOKEN


def test_registry_is_deterministic() -> None:
    a = CanaryRegistry(seed=7, scope=("run", "CASE-001", 0))
    b = CanaryRegistry(seed=7, scope=("run", "CASE-001", 0))
    for reg in (a, b):
        reg.new("system_prompt", "prompt")
        reg.new("file", "/a")
    assert a.tokens == b.tokens
    c = CanaryRegistry(seed=7, scope=("run", "CASE-001", 1))
    assert c.new("system_prompt", "prompt") != a.tokens[0]


def test_registry_new_deduplicates_by_kind_and_location() -> None:
    reg = CanaryRegistry(seed=1)
    first = reg.new("file", "/a")
    assert reg.new("file", "/a") == first
    assert reg.new("file", "/b") != first
    assert reg.new("db", "/a") != first
    assert len(reg.canaries) == 3
    assert len(set(reg.tokens)) == 3


def test_registry_register_and_kind_of() -> None:
    reg = CanaryRegistry(seed=1)
    token = reg.new("memory", "vault_pin")
    reg.register("sk-secret-value-123456", "known_secret", "target")
    reg.register("sk-secret-value-123456", "other_kind")  # duplicate token ignored
    reg.register(token, "file")  # already tracked
    assert reg.tokens == [token, "sk-secret-value-123456"]
    assert reg.kind_of(token) == "memory"
    assert reg.kind_of("sk-secret-value-123456") == "known_secret"
    assert reg.kind_of("untracked") == "unknown"
    assert reg.canaries[1].location == "target"


def test_registry_find() -> None:
    reg = CanaryRegistry(seed=3)
    token = reg.new("rag", "doc")
    assert [h.token for h in reg.find(f"look: {token[::-1]}")] == [token]
    assert reg.find("clean text") == []


@pytest.mark.parametrize("variant", ["base64", "base64_urlsafe", "hex"])
@pytest.mark.parametrize(("before", "after"), [("a", ""), ("abc", "xy"), ("", "xy"), ("f", "ff")])
def test_encoded_variants_glued_to_stray_characters(variant: str, before: str, after: str) -> None:
    text = before + canary_variants(TOKEN)[variant] + after
    assert [h.variant for h in find_canaries(text, [TOKEN])] == [EXPECTED_LABEL[variant]]


def test_reversed_lowercased_token_is_found() -> None:
    hits = find_canaries(f"odd: {TOKEN.lower()[::-1]}", [TOKEN])
    assert [h.variant for h in hits] == ["reversed"]


def test_base64_of_lowercased_token_is_found() -> None:
    encoded = base64.b64encode(TOKEN.lower().encode()).decode()
    assert [h.variant for h in find_canaries(encoded, [TOKEN])] == ["base64"]
