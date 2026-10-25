"""
ensemble.py – Decision logic combining DeBERTa, PromptGuard, and Gemini judge.

Flow:
  1. Normalize text → scan all variants with DeBERTa + PromptGuard.
  2. Both INJECTION → BLOCK ("both_agree_injection").
  3. Both BENIGN   → ALLOW ("both_agree_benign").
  4. Disagree      → Gemini judge for final verdict.
  5. Error handling: fail-open for user prompts (configurable), fail-closed for docs.
"""
from __future__ import annotations

import dataclasses
import logging
import time
from typing import Literal

from app.config import settings
from app.diagnostics import trace_step
from app.detectors.base import DetectorResult
from app.detectors.deberta import DeBERTaDetector
from app.detectors.gemini_judge import gemini_judge
from app.detectors.promptguard import PromptGuardDetector
from app.normalize import get_texts_to_scan

logger = logging.getLogger(__name__)

# Singleton detector instances (loaded once per process)
_deberta = DeBERTaDetector()
_promptguard = PromptGuardDetector()


@dataclasses.dataclass
class EnsembleResult:
    """Full audit-trail result from the ensemble."""

    final_label: Literal["INJECTION", "BENIGN", "UNKNOWN"]
    final_reason: str
    deberta: DetectorResult = dataclasses.field(default_factory=DetectorResult)
    promptguard: DetectorResult = dataclasses.field(default_factory=DetectorResult)
    gemini_used: bool = False
    gemini: DetectorResult = dataclasses.field(default_factory=DetectorResult)

    @property
    def is_injection(self) -> bool:
        return self.final_label == "INJECTION"


def _scan_worst_variant(
    text: str,
    detector,
) -> DetectorResult:
    """
    Scan all normalised variants of the text through the detector.
    Return the most alarming result (INJECTION beats BENIGN beats UNKNOWN).
    """
    variants = get_texts_to_scan(text)
    worst: DetectorResult | None = None

    for variant in variants:
        result = detector.scan(variant)
        if worst is None:
            worst = result
            continue
        # Priority: INJECTION > BENIGN > UNKNOWN > error
        if result.label == "INJECTION":
            worst = result
            break  # can't get worse
        if worst.label != "INJECTION" and result.label == "BENIGN":
            worst = result

    return worst or DetectorResult(label="UNKNOWN", error="No variants scanned")


def run_ensemble(
    text: str,
    source: Literal["prompt", "document"] = "prompt",
) -> EnsembleResult:
    """
    Run the full ensemble on text and return an EnsembleResult.

    source: "prompt" (user input) or "document" (retrieved chunk).
    Failure behaviour differs:
      - "document": fail-closed → treat errors as INJECTION (quarantine).
      - "prompt": configurable via settings.user_prompt_fail_open.
    """
    fail_closed = (source == "document") or (not settings.user_prompt_fail_open)
    trace_step("detector_ensemble", "start", source=source, fail_closed=fail_closed)

    # ── Step 1: DeBERTa ──────────────────────────────────────────────────
    started = time.perf_counter()
    trace_step("detector_deberta", "start", source=source)
    deberta_res = _scan_worst_variant(text, _deberta)
    trace_step("detector_deberta", "complete", source=source, verdict=deberta_res.label,
               failed=deberta_res.failed, duration_ms=round((time.perf_counter() - started) * 1000, 1))

    # ── Step 2: PromptGuard ───────────────────────────────────────────────
    started = time.perf_counter()
    trace_step("detector_promptguard", "start", source=source)
    pg_res = _scan_worst_variant(text, _promptguard)
    trace_step("detector_promptguard", "complete", source=source, verdict=pg_res.label,
               failed=pg_res.failed, duration_ms=round((time.perf_counter() - started) * 1000, 1))

    # Effective labels (treat UNKNOWN as BENIGN for comparison only)
    deb_label = deberta_res.label if not deberta_res.failed else "UNKNOWN"
    pg_label = pg_res.label if not pg_res.failed else "UNKNOWN"

    both_failed = deberta_res.failed and pg_res.failed

    # ── Step 3: Decision tree ─────────────────────────────────────────────
    if both_failed:
        if fail_closed:
            trace_step("ensemble_decision", "complete", verdict="INJECTION", reason="both_detectors_failed_fail_closed")
            logger.warning(
                "Both detectors failed; source=%s → fail-closed INJECTION", source
            )
            return EnsembleResult(
                final_label="INJECTION",
                final_reason="both_detectors_failed_fail_closed",
                deberta=deberta_res,
                promptguard=pg_res,
            )
        else:
            trace_step("ensemble_decision", "complete", verdict="BENIGN", reason="both_detectors_failed_fail_open")
            logger.warning(
                "Both detectors failed; source=%s → fail-open BENIGN (logged)", source
            )
            return EnsembleResult(
                final_label="BENIGN",
                final_reason="both_detectors_failed_fail_open_warning",
                deberta=deberta_res,
                promptguard=pg_res,
            )

    # Handle single-detector failure by using the other's result
    if deberta_res.failed:
        logger.warning("DeBERTa failed; using PromptGuard only for source=%s", source)
        deb_label = pg_label  # treat as agreement

    if pg_res.failed:
        logger.warning("PromptGuard failed; using DeBERTa only for source=%s", source)
        pg_label = deb_label  # treat as agreement

    if deb_label == "INJECTION" and pg_label == "INJECTION":
        trace_step("ensemble_decision", "complete", verdict="INJECTION", reason="both_agree")
        return EnsembleResult(
            final_label="INJECTION",
            final_reason="both_agree_injection",
            deberta=deberta_res,
            promptguard=pg_res,
        )

    if deb_label == "BENIGN" and pg_label == "BENIGN":
        trace_step("ensemble_decision", "complete", verdict="BENIGN", reason="both_agree")
        return EnsembleResult(
            final_label="BENIGN",
            final_reason="both_agree_benign",
            deberta=deberta_res,
            promptguard=pg_res,
        )

    # ── Step 4: Disagreement → Gemini judge ───────────────────────────────
    logger.info(
        "Detector disagreement (deberta=%s, pg=%s); calling Gemini judge for source=%s",
        deb_label, pg_label, source,
    )
    started = time.perf_counter()
    trace_step("detector_gemini", "start", source=source)
    gemini_res = gemini_judge(text)
    trace_step("detector_gemini", "complete", source=source, verdict=gemini_res.label,
               failed=gemini_res.failed, duration_ms=round((time.perf_counter() - started) * 1000, 1))

    if gemini_res.failed or gemini_res.label == "UNKNOWN":
        logger.warning("Gemini judge failed/unknown for source=%s", source)
        if fail_closed:
            trace_step("ensemble_decision", "complete", verdict="INJECTION", reason="gemini_failed_fail_closed")
            return EnsembleResult(
                final_label="INJECTION",
                final_reason="gemini_failed_fail_closed",
                deberta=deberta_res,
                promptguard=pg_res,
                gemini_used=True,
                gemini=gemini_res,
            )
        else:
            trace_step("ensemble_decision", "complete", verdict="BENIGN", reason="gemini_failed_fail_open")
            return EnsembleResult(
                final_label="BENIGN",
                final_reason="gemini_failed_fail_open_warning",
                deberta=deberta_res,
                promptguard=pg_res,
                gemini_used=True,
                gemini=gemini_res,
            )

    reason = f"gemini_verdict:{gemini_res.label.lower()}"
    trace_step("ensemble_decision", "complete", verdict=gemini_res.label, reason="gemini_verdict")
    if gemini_res.raw and isinstance(gemini_res.raw, dict) and gemini_res.raw.get("judge") == "groq_fallback":
        reason = f"gemini_verdict:{gemini_res.label.lower()}:judge=groq_fallback"

    return EnsembleResult(
        final_label=gemini_res.label,  # type: ignore[arg-type]
        final_reason=reason,
        deberta=deberta_res,
        promptguard=pg_res,
        gemini_used=True,
        gemini=gemini_res,
    )
