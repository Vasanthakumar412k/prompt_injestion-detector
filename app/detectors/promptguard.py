"""
detectors/promptguard.py – Groq-hosted Prompt Guard detector.
Model: meta-llama/llama-prompt-guard-2-86m (or -22m via config).
The model returns a float score as the message content.
"""
from __future__ import annotations

import logging
import os
import time

from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from app.config import settings
from app.detectors.base import BaseDetector, DetectorResult

logger = logging.getLogger(__name__)


def _get_groq_client():
    """Lazily create the Groq client."""
    try:
        from groq import Groq  # type: ignore

        return Groq()  # picks up GROQ_API_KEY from env
    except Exception as exc:
        logger.error("Failed to create Groq client: %s", exc)
        return None


class PromptGuardDetector(BaseDetector):
    """
    Uses Groq's meta-llama/llama-prompt-guard-2-86m.
    The model returns a float in [0, 1] as the completion text.
    Score >= promptguard_threshold → INJECTION.
    """

    name = "promptguard"

    def __init__(self, model: str | None = None) -> None:
        self._model = model or settings.promptguard_model
        self._client = _get_groq_client()

    def _call_api(self, text: str) -> float:
        """Call Groq Prompt Guard and return the raw float score."""
        completion = self._client.chat.completions.create(
            model=self._model,
            messages=[{"role": "user", "content": text}],
            temperature=1,
            max_completion_tokens=1,
            top_p=1,
            stream=False,
            timeout=settings.detector_timeout,
        )
        raw = completion.choices[0].message.content
        return float(raw.strip())

    # Retry on rate limits only
    @retry(
        retry=retry_if_exception_type(Exception),
        stop=stop_after_attempt(settings.groq_retry_attempts),
        wait=wait_exponential(
            min=settings.groq_retry_wait_min,
            max=settings.groq_retry_wait_max,
        ),
        reraise=True,
    )
    def _call_with_retry(self, text: str) -> float:
        return self._call_api(text)

    def scan(self, text: str) -> DetectorResult:
        if self._client is None:
            self._client = _get_groq_client()
        if self._client is None:
            return DetectorResult(label="UNKNOWN", error="Groq client unavailable")

        t0 = time.monotonic()
        try:
            score = self._call_with_retry(text)
            latency_ms = (time.monotonic() - t0) * 1000

            label = "INJECTION" if score >= settings.promptguard_threshold else "BENIGN"
            return DetectorResult(
                label=label,
                score=score,
                raw=score,
                latency_ms=latency_ms,
            )
        except Exception as exc:
            latency_ms = (time.monotonic() - t0) * 1000
            logger.error("PromptGuard scan error: %s", exc)
            return DetectorResult(
                label="UNKNOWN",
                latency_ms=latency_ms,
                error=str(exc),
            )
