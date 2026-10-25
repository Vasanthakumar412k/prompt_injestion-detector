"""
detectors/deberta.py – Local DeBERTa-based prompt-injection detector.
Model: protectai/deberta-v3-base-prompt-injection-v2
Loaded once at import time via a transformers pipeline.
"""
from __future__ import annotations

import logging
import time
from typing import Any

from app.config import settings
from app.detectors.base import BaseDetector, DetectorResult

logger = logging.getLogger(__name__)

_pipeline: Any = None


def _load_pipeline() -> Any:
    """Lazy-load the transformers pipeline (heavy; load once)."""
    global _pipeline
    if _pipeline is None:
        try:
            from transformers import pipeline  # type: ignore

            logger.info("Loading DeBERTa model: %s", settings.deberta_model)
            _pipeline = pipeline(
                "text-classification",
                model=settings.deberta_model,
                truncation=True,
                max_length=512,
            )
            logger.info("DeBERTa model loaded.")
        except Exception as exc:
            logger.error("Failed to load DeBERTa model: %s", exc)
            _pipeline = None
    return _pipeline


class DeBERTaDetector(BaseDetector):
    """
    Runs protectai/deberta-v3-base-prompt-injection-v2 locally.
    Returns INJECTION if the model label is INJECTION and score >= threshold.
    """

    name = "deberta"

    def __init__(self, eager_load: bool = False) -> None:
        self._pipe = _load_pipeline() if eager_load else None

    def scan(self, text: str) -> DetectorResult:
        if self._pipe is None:
            # Attempt reload once per call in case environment changed
            self._pipe = _load_pipeline()
        if self._pipe is None:
            return DetectorResult(
                label="UNKNOWN",
                error="DeBERTa pipeline not available",
            )

        t0 = time.monotonic()
        try:
            results = self._pipe(text[:2048])  # truncate to avoid OOM
            latency_ms = (time.monotonic() - t0) * 1000

            # Pipeline returns list of {label, score}
            top = results[0] if isinstance(results, list) else results
            raw_label: str = top["label"].upper()
            score: float = float(top["score"])

            if raw_label == "INJECTION" and score >= settings.deberta_threshold:
                label = "INJECTION"
            else:
                label = "BENIGN"

            return DetectorResult(
                label=label,
                score=score,
                raw=top,
                latency_ms=latency_ms,
            )
        except Exception as exc:
            latency_ms = (time.monotonic() - t0) * 1000
            logger.error("DeBERTa scan error: %s", exc)
            return DetectorResult(
                label="UNKNOWN",
                latency_ms=latency_ms,
                error=str(exc),
            )
