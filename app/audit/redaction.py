"""
app/audit/redaction.py – Pre-audit redaction pipeline.

Guarantees that sensitive data (restricted document chunks, secrets,
canary tokens, emails, real user IDs) is stripped BEFORE anything leaves
the platform or reaches an external auditor LLM.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, List, Optional, Set, Tuple


_EMAIL_REGEX = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
_CANARY_REGEX = re.compile(r"CANARY-[A-Za-z0-9_-]+")
_SECRET_REGEX = re.compile(
    r"(?:gsk_[a-zA-Z0-9]{20,}|AQ\.[a-zA-Z0-9_-]{20,}|AIza[a-zA-Z0-9_-]{30,}|eyJ[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{10,}|Bearer\s+[a-zA-Z0-9_\-\.]{15,})"
)


def pseudonymize_user_id(user_id: Optional[int]) -> str:
    """Deterministic pseudonym for a user ID."""
    if user_id is None:
        return "USER_ANON"
    h = hashlib.sha256(f"salt_user_{user_id}".encode("utf-8")).hexdigest()[:6]
    return f"USER_{h}"


def redact_text(
    text: str,
    restricted_phrases: Optional[List[str]] = None,
) -> Tuple[str, Dict[str, int]]:
    """
    Redact text before sending to auditor LLM.
    Returns: (redacted_text, counts_dict)
    """
    if not text:
        return "", {"emails": 0, "canaries": 0, "secrets": 0, "restricted_phrases": 0}

    counts = {
        "emails": 0,
        "canaries": 0,
        "secrets": 0,
        "restricted_phrases": 0,
    }

    # 1. Redact restricted phrases (e.g. text from documents user was not allowed to read)
    redacted = text
    if restricted_phrases:
        for phrase in restricted_phrases:
            if not phrase or len(phrase.strip()) < 4:
                continue
            clean_phrase = phrase.strip()
            if clean_phrase in redacted:
                occurrences = redacted.count(clean_phrase)
                counts["restricted_phrases"] += occurrences
                redacted = redacted.replace(clean_phrase, "[RESTRICTED_CHUNK_REDACTED]")

    # 2. Redact secrets / API keys / Bearer tokens
    def _sub_secret(m):
        counts["secrets"] += 1
        return "[SECRET_REDACTED]"

    redacted = _SECRET_REGEX.sub(_sub_secret, redacted)

    # 3. Redact canary tokens
    def _sub_canary(m):
        counts["canaries"] += 1
        return "[CANARY_REDACTED]"

    redacted = _CANARY_REGEX.sub(_sub_canary, redacted)

    # 4. Redact emails
    def _sub_email(m):
        counts["emails"] += 1
        return "[EMAIL_REDACTED]"

    redacted = _EMAIL_REGEX.sub(_sub_email, redacted)

    return redacted, counts


def redact_log_item(
    log_type: str,
    item_dict: Dict[str, Any],
    restricted_phrases: Optional[List[str]] = None,
) -> Tuple[Dict[str, Any], Dict[str, int]]:
    """
    Produce a completely sanitized, pseudonymized log dictionary ready for auditor consumption.
    """
    total_counts = {"emails": 0, "canaries": 0, "secrets": 0, "restricted_phrases": 0, "user_pseudonyms": 0}

    sanitized = item_dict.copy()

    # Pseudonymize user_id
    if "user_id" in sanitized:
        raw_uid = sanitized["user_id"]
        sanitized["user_id"] = pseudonymize_user_id(raw_uid)
        total_counts["user_pseudonyms"] += 1

    # Redact text preview fields
    for field in ("text_preview", "question_preview", "answer_preview", "matched_value"):
        if field in sanitized and sanitized[field]:
            r_text, counts = redact_text(str(sanitized[field]), restricted_phrases)
            sanitized[field] = r_text
            for k, v in counts.items():
                total_counts[k] += v

    sanitized["_log_type"] = log_type
    return sanitized, total_counts
