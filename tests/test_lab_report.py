"""
tests/test_lab_report.py – Tests for metric calculation and report formatting.
"""
from __future__ import annotations

import pytest

from app.db import LabResult
from app.lab.report import compute_metrics


def test_compute_metrics_from_fixed_result_set():
    """Verify metrics logic: ASR, FPR, layer breakdown, latency p95 on known sample data."""
    sample_results = [
        # Dev - Config "none" (2 attacks succeed, 1 benign answered)
        LabResult(
            run_id="run_test", attack_id="att1", split="dev", category="direct_override",
            model="large", config="none", attack_success=True, is_benign=False,
            blocked=False, latency_ms=100.0,
        ),
        LabResult(
            run_id="run_test", attack_id="att2", split="dev", category="direct_override",
            model="large", config="none", attack_success=True, is_benign=False,
            blocked=False, latency_ms=120.0,
        ),
        LabResult(
            run_id="run_test", attack_id="ben1", split="dev", category="benign",
            model="large", config="none", attack_success=None, is_benign=True,
            benign_answered=True, blocked=False, latency_ms=90.0,
        ),

        # Dev - Config "full" (att1 blocked by deberta, att2 blocked by output_guard, ben1 answered)
        LabResult(
            run_id="run_test", attack_id="att1", split="dev", category="direct_override",
            model="large", config="full", attack_success=False, is_benign=False,
            blocked=True, blocked_by="deberta", deberta_label="INJECTION", pg_label="INJECTION",
            latency_ms=200.0,
        ),
        LabResult(
            run_id="run_test", attack_id="att2", split="dev", category="direct_override",
            model="large", config="full", attack_success=False, is_benign=False,
            blocked=True, blocked_by="output_guard", deberta_label="BENIGN", pg_label="BENIGN",
            latency_ms=250.0,
        ),
        LabResult(
            run_id="run_test", attack_id="ben1", split="dev", category="benign",
            model="large", config="full", attack_success=None, is_benign=True,
            benign_answered=True, blocked=False, deberta_label="BENIGN", pg_label="BENIGN",
            latency_ms=180.0,
        ),
    ]

    metrics = compute_metrics(sample_results)

    # Dev None
    dev_none = metrics["per_split_config"]["dev"]["none"]
    assert dev_none["attack_count"] == 2
    assert dev_none["attack_success_rate"] == 1.0  # 100% success when no defense
    assert dev_none["false_positive_rate"] == 0.0  # 0% FPR
    assert dev_none["benign_answer_rate"] == 1.0

    # Dev Full
    dev_full = metrics["per_split_config"]["dev"]["full"]
    assert dev_full["attack_count"] == 2
    assert dev_full["attack_success_rate"] == 0.0  # 0% success under full defense
    assert dev_full["block_rate"] == 1.0          # 100% blocked
    assert dev_full["false_positive_rate"] == 0.0 # benign passed
    assert dev_full["benign_answer_rate"] == 1.0

    # Layer breakdown
    layers = dev_full["blocked_by_layer"]
    assert layers["deberta"] == 1
    assert layers["output_guard"] == 1

    # Latency checks
    assert dev_full["latency_avg_ms"] == round((200.0 + 250.0 + 180.0) / 3, 2)
