"""
detectors/base.py – Detector interface and shared result type.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class DetectorResult:
    """Standardised result from any detector."""

    label: str = "UNKNOWN"           # "INJECTION" | "BENIGN" | "UNKNOWN"
    score: float = 0.0               # confidence for the returned label
    raw: Any = None                  # raw model output (for debugging)
    latency_ms: float = 0.0
    error: Optional[str] = None      # non-None means the detector failed

    @property
    def is_injection(self) -> bool:
        return self.label == "INJECTION"

    @property
    def failed(self) -> bool:
        return self.error is not None


class BaseDetector:
    """Abstract interface every detector must implement."""

    name: str = "base"

    def scan(self, text: str) -> DetectorResult:  # pragma: no cover
        raise NotImplementedError
