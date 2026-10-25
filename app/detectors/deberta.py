"""
detectors/deberta.py – Local DeBERTa-based prompt-injection detector.
Model: protectai/deberta-v3-base-prompt-injection-v2
Loaded once at import time via a transformers pipeline.
"""
from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any

from app.config import settings
from app.detectors.base import BaseDetector, DetectorResult

logger = logging.getLogger(__name__)

_pipeline: Any = None


def _load_pipeline() -> Any:
    """Lazy-load the transformers pipeline (heavy; load once)."""
    global _pipeline
    if _pipeline is None:
        from transformers import (  # type: ignore
            AutoModelForSequenceClassification,
            AutoTokenizer,
            pipeline,
        )

        model_path = Path(settings.deberta_model_path).expanduser()
        reference = str(model_path) if model_path.is_dir() else settings.deberta_model
        logger.info("Loading local-only DeBERTa model: %s", reference)
        try:
            tokenizer = AutoTokenizer.from_pretrained(
                reference,
                local_files_only=True,
            )
            model = AutoModelForSequenceClassification.from_pretrained(
                reference,
                local_files_only=True,
            )
            _pipeline = pipeline(
                "text-classification",
                model=model,
                tokenizer=tokenizer,
            )
        except Exception as exc:
            raise RuntimeError(
                "The local DeBERTa detector model is unavailable. Run "
                "`python scripts/download_models.py` before starting the app."
            ) from exc
        logger.info("DeBERTa model loaded from local files.")
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
            self._pipe = _load_pipeline()

        t0 = time.monotonic()
        try:
            results = self._pipe(text[:2048], truncation=True, max_length=512)
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
