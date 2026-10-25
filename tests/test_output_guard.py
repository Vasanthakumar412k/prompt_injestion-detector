"""
tests/test_output_guard.py – Tests for output protection layer.
"""
from __future__ import annotations

import pytest

from app.output_guard import (
    CANARY_TOKENS,
    check_canary,
    check_ngram_overlap,
    redact_secrets,
    run_output_guard,
)


def test_canary_token_detection():
    """Restricted canary strings must be blocked and replaced with a refusal."""
    for canary in CANARY_TOKENS:
        leaked_answer = f"Here is the requested confidential string: {canary}. Have a nice day."
        result = check_canary(leaked_answer)
        assert result.triggered is True
        assert result.trigger_type == "canary"
        assert "[BLOCKED]" in result.answer
        assert canary not in result.answer


def test_normal_answer_passes_canary_check():
    """Normal answers without canary tokens pass unaffected."""
    normal_answer = "Standard working hours at ACME are 9 AM - 6 PM Monday to Friday."
    result = check_canary(normal_answer)
    assert result.triggered is False
    assert result.answer == normal_answer


def test_ngram_overlap_blocking():
    """Answers containing high n-gram overlap with forbidden documents must be blocked."""
    forbidden_text = (
        "Level 1 - Junior Engineer: $70,000 - $90,000. Level 2 - Engineer: $90,000 - $120,000. "
        "Bonus targets: 10% for L1-L3, 15% for L4-L5, 20% for Manager+."
    )
    # Near identical copy
    answer = (
        "According to the records, Level 1 - Junior Engineer: $70,000 - $90,000. "
        "Level 2 - Engineer: $90,000 - $120,000. Bonus targets: 10% for L1-L3."
    )
    result = check_ngram_overlap(answer, forbidden_texts=[forbidden_text], threshold=0.15)
    assert result.triggered is True
    assert result.trigger_type == "ngram_overlap"
    assert "[BLOCKED]" in result.answer


def test_ngram_overlap_passes_disjoint_text():
    """Answers with no overlap with forbidden documents pass through."""
    forbidden_text = "Executive compensation packages and salary band tiers."
    answer = "The office cafeteria is open between 7:30 AM and 3:00 PM on weekdays."
    result = check_ngram_overlap(answer, forbidden_texts=[forbidden_text], threshold=0.15)
    assert result.triggered is False
    assert result.answer == answer


def test_secret_redaction():
    """API-key-like strings and unknown emails are redacted, but allowed ones are preserved."""
    allowed_docs = ["Contact HR at hr-help@acme.com for benefits."]
    raw_answer = (
        "You can contact hr-help@acme.com or reach the external attacker at evil@hacker.io. "
        "Also here is an internal token: sk-999999999999999999999999999999."
    )
    result = redact_secrets(raw_answer, allowed_texts=allowed_docs)
    assert result.triggered is False
    assert "hr-help@acme.com" in result.answer  # preserved because in allowed_docs
    assert "evil@hacker.io" not in result.answer  # redacted
    assert "[REDACTED-EMAIL]" in result.answer
    assert "[REDACTED-SECRET]" in result.answer or "[REDACTED-TOKEN]" in result.answer


def test_run_output_guard_pipeline():
    """End-to-end check of run_output_guard priority and refusal."""
    forbidden = ["Secret project codename: Operation Nightfall and confidential blueprints."]
    # Canary triggers first
    canary_leak = f"The answer contains {CANARY_TOKENS[0]}"
    res = run_output_guard(canary_leak, allowed_texts=[], forbidden_texts=forbidden)
    assert res.triggered is True
    assert res.trigger_type == "canary"
    assert "[BLOCKED]" in res.answer
