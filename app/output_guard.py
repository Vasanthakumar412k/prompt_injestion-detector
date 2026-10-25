"""
output_guard.py – Post-generation output protection.

Three layers applied in order:
  1. Canary token detection  – if ANY canary string appears in the answer, block it.
  2. N-gram overlap check    – compare answer against text from docs the user cannot
     see; block if normalised overlap exceeds threshold.
  3. Secret redaction        – mask API-key-like strings and email addresses that are
     NOT present in the user's allowed documents.

Configuration lives in app/config.py (output_guard_* settings).
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import List, Optional

logger = logging.getLogger(__name__)

# ── Canary tokens ─────────────────────────────────────────────────────────────
# Seeded into confidential documents and the system prompt.
# Add any new canaries here; they will be picked up automatically.
CANARY_TOKENS: list[str] = [
    "CANARY-HR-7f3a",
    "CANARY-SYS-2b9c",
]

# ── Secret patterns ──────────────────────────────────────────────────────────
_SECRET_PATTERNS: list[tuple[str, str]] = [
    # API-key-like: long alphanum with dashes/underscores
    (r"[A-Za-z0-9_\-]{32,}", "[REDACTED-TOKEN]"),
    # Email addresses
    (r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", "[REDACTED-EMAIL]"),
    # Private keys / Bearer tokens
    (r"(?i)\b(sk-[A-Za-z0-9]{20,}|Bearer\s+[A-Za-z0-9._\-]{20,})", "[REDACTED-SECRET]"),
]

# ── Safe refusal ──────────────────────────────────────────────────────────────
_SAFE_REFUSAL = (
    "[BLOCKED] The answer was withheld because it was detected to contain "
    "information you are not authorised to access."
)


@dataclass
class GuardResult:
    answer: str                  # final (possibly redacted / replaced) answer
    triggered: bool = False      # True if any guard fired
    trigger_type: Optional[str] = None   # "canary" | "ngram_overlap" | "secret_redact"
    matched_value: Optional[str] = None  # sanitised excerpt of what matched
    redacted_count: int = 0      # how many secret patterns were redacted


def _normalise(text: str) -> str:
    """Lowercase, collapse whitespace, remove punctuation for comparison."""
    text = text.lower()
    text = re.sub(r"[^\w\s]", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def _ngrams(text: str, n: int) -> set[str]:
    words = text.split()
    return {" ".join(words[i: i + n]) for i in range(len(words) - n + 1)}


def _overlap_score(answer_norm: str, forbidden_norm: str, n: int = 4) -> float:
    """Return Jaccard overlap of n-grams between answer and forbidden text."""
    a_grams = _ngrams(answer_norm, n)
    f_grams = _ngrams(forbidden_norm, n)
    if not f_grams:
        return 0.0
    intersection = a_grams & f_grams
    union = a_grams | f_grams
    return len(intersection) / len(union) if union else 0.0


def check_canary(answer: str) -> GuardResult:
    """Block answer if any canary token appears in it."""
    for token in CANARY_TOKENS:
        if token in answer:
            logger.warning("Output guard: canary token %r found in answer", token)
            return GuardResult(
                answer=_SAFE_REFUSAL,
                triggered=True,
                trigger_type="canary",
                matched_value=token,
            )
    return GuardResult(answer=answer)


def check_ngram_overlap(
    answer: str,
    forbidden_texts: list[str],
    threshold: float = 0.15,
    ngram_size: int = 4,
) -> GuardResult:
    """
    Block answer if n-gram overlap with any forbidden document chunk exceeds threshold.
    forbidden_texts: raw text of chunks the current user is NOT allowed to read.
    """
    if not forbidden_texts:
        return GuardResult(answer=answer)

    answer_norm = _normalise(answer)
    for forbidden in forbidden_texts:
        score = _overlap_score(answer_norm, _normalise(forbidden), n=ngram_size)
        if score >= threshold:
            excerpt = forbidden[:80].replace("\n", " ")
            logger.warning(
                "Output guard: n-gram overlap %.3f >= %.3f with forbidden chunk (excerpt: %r)",
                score, threshold, excerpt,
            )
            return GuardResult(
                answer=_SAFE_REFUSAL,
                triggered=True,
                trigger_type="ngram_overlap",
                matched_value=f"overlap={score:.3f}; forbidden_excerpt={excerpt!r}",
            )
    return GuardResult(answer=answer)


def redact_secrets(
    answer: str,
    allowed_texts: list[str],
) -> GuardResult:
    """
    Redact API-key-like strings and email addresses that do not appear in
    the user's allowed documents. Returns a non-triggered GuardResult with
    the redacted answer and a count of substitutions made.
    """
    allowed_blob = " ".join(allowed_texts).lower()
    redacted = answer
    count = 0

    for pattern, replacement in _SECRET_PATTERNS:
        def _replace(m: re.Match) -> str:  # noqa: ANN202
            nonlocal count
            value = m.group(0)
            if value.lower() in allowed_blob:
                return value  # it's in the allowed docs – keep it
            count += 1
            return replacement

        redacted = re.sub(pattern, _replace, redacted)

    return GuardResult(answer=redacted, triggered=False, redacted_count=count)


def run_output_guard(
    answer: str,
    allowed_texts: list[str],
    forbidden_texts: list[str],
    ngram_threshold: float = 0.15,
) -> GuardResult:
    """
    Run all output guard checks in order.
    Returns GuardResult; if triggered, answer is replaced with a safe refusal.
    """
    # 1. Canary check
    result = check_canary(answer)
    if result.triggered:
        return result

    # 2. N-gram overlap
    result = check_ngram_overlap(answer, forbidden_texts, threshold=ngram_threshold)
    if result.triggered:
        return result

    # 3. Secret redaction (non-blocking, modifies answer in place)
    result = redact_secrets(answer, allowed_texts)
    return result
