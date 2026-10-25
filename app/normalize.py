"""
normalize.py – Text preprocessing before detector scans.
Applies: Unicode NFKC, zero-width char removal, spaced-letter collapse,
leetspeak mapping, and base64 / ROT13 decode attempts.
Returns both original and normalised text so both can be scanned.
"""
from __future__ import annotations

import base64
import codecs
import re
import unicodedata


# ── Leetspeak substitution map ──────────────────────────────────────────────
_LEET_MAP: dict[str, str] = {
    "0": "o",
    "1": "i",
    "3": "e",
    "4": "a",
    "5": "s",
    "6": "g",
    "7": "t",
    "@": "a",
    "$": "s",
    "|": "l",
    "!": "i",
    "(": "c",
}

# Zero-width and invisible Unicode characters
_ZERO_WIDTH_PATTERN = re.compile(
    r"[\u200b\u200c\u200d\u200e\u200f\ufeff\u00ad\u2060\u2061\u2062\u2063\u2064]"
)

# Spaced letters: "i g n o r e" → "ignore"
_SPACED_LETTERS_PATTERN = re.compile(r"\b([a-zA-Z])(?: [a-zA-Z]){2,}\b")


def _collapse_spaced_letters(text: str) -> str:
    """'i g n o r e  m e' → 'ignore me'."""
    def _join(m: re.Match) -> str:
        return m.group(0).replace(" ", "")
    return _SPACED_LETTERS_PATTERN.sub(_join, text)


def _apply_leet(text: str) -> str:
    return "".join(_LEET_MAP.get(ch, ch) for ch in text)


def _try_base64(text: str) -> str | None:
    """Try to decode text as base64; return decoded string or None."""
    stripped = text.strip().replace("\n", "").replace(" ", "")
    # Must look like base64 (only valid chars, reasonable length)
    if not re.fullmatch(r"[A-Za-z0-9+/=]{16,}", stripped):
        return None
    try:
        decoded = base64.b64decode(stripped + "==").decode("utf-8", errors="replace")
        # Only return if it contains printable ASCII
        if decoded.isprintable() or any(c.isalpha() for c in decoded):
            return decoded
    except Exception:
        pass
    return None


def _try_rot13(text: str) -> str:
    """ROT13 decode."""
    return codecs.decode(text, "rot_13")


def normalize(text: str) -> str:
    """
    Canonical normalisation pipeline.

    1. Unicode NFKC normalisation.
    2. Strip zero-width / invisible characters.
    3. Collapse spaced-out letters.
    4. Apply leetspeak substitution.
    5. Lowercase.
    """
    # 1. NFKC
    result = unicodedata.normalize("NFKC", text)
    # 2. Zero-width chars
    result = _ZERO_WIDTH_PATTERN.sub("", result)
    # 3. Leetspeak substitution (maps e.g. 0->o, 3->e so spaced letter collapsing catches I G N 0 R 3)
    result = _apply_leet(result)
    # 4. Spaced letters
    result = _collapse_spaced_letters(result)
    # 5. Lowercase
    result = result.lower()
    return result


def get_texts_to_scan(text: str) -> list[str]:
    """
    Return a deduplicated list of text variants to scan:
    - original
    - normalised
    - base64 decoded (if applicable)
    - ROT13 decoded
    The ensemble scans ALL variants; INJECTION on any → block.
    """
    variants: list[str] = [text]

    normalised = normalize(text)
    if normalised != text.lower():
        variants.append(normalised)

    # Base64 attempt
    b64 = _try_base64(text)
    if b64 and b64 not in variants:
        variants.append(b64)

    # ROT13 attempt (always cheap, add normalised version)
    rot = _try_rot13(text)
    rot_norm = normalize(rot)
    if rot_norm not in variants:
        variants.append(rot_norm)

    return variants
