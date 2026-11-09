"""Text normalization helpers shared by the naive mock model and the canary detector.

These emulate how a capable LLM "reads through" obfuscation: zero-width characters are invisible,
Cyrillic/Greek homoglyphs look like Latin letters, leetspeak and split tokens are still legible,
and base64 / ROT13 payloads can be decoded on request.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import json
import re
import unicodedata

__all__ = [
    "HOMOGLYPHS",
    "LEET_DECODE",
    "PSEUDO_SPANISH",
    "SPANISH_TO_ENGLISH",
    "ZERO_WIDTH",
    "decode_base64_segments",
    "deleet",
    "extract_json_strings",
    "fold_homoglyphs",
    "is_printable_text",
    "normalize_for_reading",
    "rejoin_split_words",
    "rot13",
    "strip_zero_width",
    "untranslate_spanish",
]

ZERO_WIDTH = "\u200b‌‍⁠﻿­"
_ZW_RE = re.compile(f"[{ZERO_WIDTH}]")

# Latin letter -> visually confusable Cyrillic/Greek letter (used by the homoglyph mutation).
HOMOGLYPHS: dict[str, str] = {
    "a": "а",  # Cyrillic a
    "c": "с",  # Cyrillic es
    "e": "е",  # Cyrillic ie
    "i": "і",  # Cyrillic byelorussian-ukrainian i
    "j": "ј",  # Cyrillic je
    "o": "о",  # Cyrillic o
    "p": "р",  # Cyrillic er
    "s": "ѕ",  # Cyrillic dze
    "x": "х",  # Cyrillic ha
    "y": "у",  # Cyrillic u
    "A": "Α",  # Greek Alpha
    "B": "Β",  # Greek Beta
    "E": "Ε",  # Greek Epsilon
    "H": "Η",  # Greek Eta
    "K": "Κ",  # Greek Kappa
    "M": "Μ",  # Greek Mu
    "O": "Ο",  # Greek Omicron
    "P": "Ρ",  # Greek Rho
    "T": "Τ",  # Greek Tau
    "X": "Χ",  # Greek Chi
}
_HOMOGLYPH_REVERSE: dict[str, str] = {v: k for k, v in HOMOGLYPHS.items()}
# Extra lookalikes an attacker might use that the mutation engine does not emit.
_HOMOGLYPH_REVERSE.update({"ο": "o", "α": "a", "ε": "e", "ԁ": "d", "ɡ": "g", "һ": "h"})

LEET_DECODE: dict[str, str] = {
    "4": "a",
    "@": "a",
    "3": "e",
    "1": "i",
    "!": "i",
    "0": "o",
    "5": "s",
    "$": "s",
    "7": "t",
}
_LEET_WORD = re.compile(r"[A-Za-z0-9@$!]+")
_B64_CANDIDATE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])")


def strip_zero_width(text: str) -> str:
    """Remove zero-width and soft-hyphen characters."""
    return _ZW_RE.sub("", text)


def fold_homoglyphs(text: str) -> str:
    """Map known Cyrillic/Greek lookalikes back to Latin letters."""
    if all(ord(ch) < 128 for ch in text):
        return text
    return "".join(_HOMOGLYPH_REVERSE.get(ch, ch) for ch in text)


def deleet(text: str) -> str:
    """Decode leetspeak inside words that mix letters with leet digits/symbols.

    Pure numbers (amounts, IDs) and words without letters are left untouched.
    """

    def fix(match: re.Match[str]) -> str:
        word = match.group(0)
        has_alpha = any(c.isalpha() for c in word)
        has_leet = any(c in LEET_DECODE for c in word)
        if not (has_alpha and has_leet):
            return word
        if re.fullmatch(r"[A-Z]+-?\d+", word) or re.search(r"[A-Z]{2,}\d", word):
            return word  # looks like an identifier (ATTACKER-0000, C-1001)
        return "".join(LEET_DECODE.get(c, c) for c in word)

    return _LEET_WORD.sub(fix, text)


def rot13(text: str) -> str:
    """Apply ROT13 (an involution)."""
    return codecs.encode(text, "rot_13")


def is_printable_text(text: str, min_ratio: float = 0.9) -> bool:
    """Return True if ``text`` is mostly printable characters (used to accept decodes)."""
    if not text:
        return False
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\n\r\t")
    return printable / len(text) >= min_ratio and any(ch.isalpha() for ch in text)


def decode_base64_segments(text: str, min_len: int = 16) -> list[str]:
    """Find base64-looking runs in ``text`` and return those that decode to readable text."""
    decoded: list[str] = []
    for match in _B64_CANDIDATE.finditer(text):
        chunk = match.group(0)
        if len(chunk) < min_len:
            continue
        padded = chunk + "=" * (-len(chunk) % 4)
        try:
            raw = base64.b64decode(padded, validate=True)
            value = raw.decode("utf-8")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
        if is_printable_text(value):
            decoded.append(value)
    return decoded


def extract_json_strings(text: str) -> list[str]:
    """Return string values of any JSON object/array embedded in ``text``."""
    values: list[str] = []
    start = text.find("{")
    end = text.rfind("}")
    candidates = [text[start : end + 1]] if 0 <= start < end else []
    for candidate in candidates:
        try:
            parsed = json.loads(candidate)
        except (json.JSONDecodeError, ValueError):
            continue
        stack: list[object] = [parsed]
        while stack:
            item = stack.pop()
            if isinstance(item, str):
                values.append(item)
            elif isinstance(item, dict):
                stack.extend(item.values())
            elif isinstance(item, list):
                stack.extend(item)
    return values


def rejoin_split_words(text: str, vocabulary: frozenset[str]) -> str:
    """Re-join words that were split by hyphens or spaces when the join is a known word.

    Args:
        text: input text.
        vocabulary: lower-case words to reconstruct (e.g. the intent grammar keywords).
    """

    # Hyphen splits inside a word: "ig-nore" -> "ignore" when the result is in the vocabulary.
    def join_hyphen(match: re.Match[str]) -> str:
        joined = match.group(0).replace("-", "")
        return joined if joined.lower() in vocabulary else match.group(0)

    text = re.sub(r"\b[A-Za-z]+(?:-[A-Za-z]+)+\b", join_hyphen, text)
    tokens = re.split(r"(\s+)", text)
    words = tokens[0::2]
    seps = tokens[1::2]
    out: list[str] = []
    i = 0
    while i < len(words):
        joined_ok = False
        for span in (4, 3, 2):
            if i + span > len(words):
                continue
            parts = words[i : i + span]
            core = [p.strip(".,;:!?\"'()") for p in parts]
            if not all(c.isalpha() for c in core) or any(p != c for p, c in zip(parts[:-1], core[:-1], strict=False)):
                continue
            trailing = parts[-1][len(core[-1]) :] if parts[-1].startswith(core[-1]) else ""
            candidate = "".join(core)
            if candidate.lower() in vocabulary and not all(c.lower() in vocabulary for c in core):
                out.append(candidate + trailing)
                if i + span - 1 < len(seps):
                    out.append(seps[i + span - 1])
                i += span
                joined_ok = True
                break
        if not joined_ok:
            out.append(words[i])
            if i < len(seps):
                out.append(seps[i])
            i += 1
    return "".join(out)


def normalize_for_reading(text: str) -> str:
    """NFKC-normalize, strip zero-width characters and fold homoglyphs."""
    text = strip_zero_width(text)
    text = fold_homoglyphs(text)
    return unicodedata.normalize("NFKC", text)


# Deterministic offline "translation" lexicon (English -> Spanish) used by the ``translate_mock``
# mutation. The naive mock model "understands" Spanish through the inverse mapping, just as a real
# multilingual model would.
PSEUDO_SPANISH: dict[str, str] = {
    "ignore": "ignora",
    "all": "todas",
    "previous": "anteriores",
    "prior": "previas",
    "instructions": "instrucciones",
    "instruction": "instrucción",
    "and": "y",
    "print": "imprime",
    "reveal": "revela",
    "show": "muestra",
    "tell": "dime",
    "repeat": "repite",
    "output": "emite",
    "the": "el",
    "your": "tu",
    "you": "tú",
    "system": "sistema",
    "prompt": "indicación",
    "secret": "secreto",
    "code": "código",
    "token": "ficha",
    "password": "contraseña",
    "key": "clave",
    "send": "envía",
    "email": "correo",
    "to": "a",
    "transfer": "transfiere",
    "money": "dinero",
    "account": "cuenta",
    "run": "ejecuta",
    "execute": "ejecuta",
    "command": "comando",
    "file": "archivo",
    "read": "lee",
    "write": "escribe",
    "delete": "borra",
    "now": "ahora",
    "please": "por favor",
    "must": "debes",
    "rules": "reglas",
    "internal": "interno",
    "reference": "referencia",
    "include": "incluye",
    "in": "en",
    "reply": "respuesta",
    "answer": "respuesta",
    "with": "con",
    "of": "de",
    "for": "para",
    "this": "esto",
    "message": "mensaje",
    "data": "datos",
    "customer": "cliente",
    "fetch": "obtén",
    "visit": "visita",
    "remember": "recuerda",
    "always": "siempre",
    "forget": "olvida",
    "everything": "todo",
    "above": "arriba",
    "text": "texto",
    "admin": "administrador",
    "mode": "modo",
    "developer": "desarrollador",
    "is": "es",
    "a": "un",
    "an": "un",
}
# Inverse map; ambiguous Spanish words map to the first English source.
SPANISH_TO_ENGLISH: dict[str, str] = {}
for _en, _es in PSEUDO_SPANISH.items():
    SPANISH_TO_ENGLISH.setdefault(_es, _en)


def untranslate_spanish(text: str) -> str:
    """Translate words from the pseudo-Spanish lexicon back to English (multi-word aware)."""
    result = text
    for es in sorted(SPANISH_TO_ENGLISH, key=len, reverse=True):
        if " " in es:
            result = re.sub(rf"(?i)\b{re.escape(es)}\b", SPANISH_TO_ENGLISH[es], result)

    def word(match: re.Match[str]) -> str:
        token = match.group(0)
        mapped = SPANISH_TO_ENGLISH.get(token.lower())
        if mapped is None:
            return token
        return mapped.capitalize() if token[:1].isupper() else mapped

    return re.sub(r"[^\W\d_]+", word, result)
