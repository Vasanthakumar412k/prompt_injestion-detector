"""Safe, request-correlated progress logging for local troubleshooting."""
from __future__ import annotations

import contextvars
import logging
import re
import uuid
from typing import Any

_request_id: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="startup")
_logger = logging.getLogger("app.trace")
_safe_key = re.compile(r"^[a-z][a-z0-9_]{0,40}$")
_sensitive = ("prompt", "question", "text", "answer", "token", "password", "secret", "key", "content", "filename", "username", "email", "raw")


def new_request_id() -> str:
    return uuid.uuid4().hex[:12]


def set_request_id(value: str):
    return _request_id.set(value)


def reset_request_id(token: contextvars.Token[str]) -> None:
    _request_id.reset(token)


def current_request_id() -> str:
    return _request_id.get()


def trace_step(step: str, state: str, request_id: str | None = None, **details: Any) -> None:
    """Log a step and safe metadata; reject content-like fields by default."""
    fields = []
    for key, value in details.items():
        if not _safe_key.fullmatch(key) or any(term in key.lower() for term in _sensitive):
            continue
        if isinstance(value, bool):
            rendered = str(value).lower()
        elif isinstance(value, (int, float)):
            rendered = str(value)
        elif isinstance(value, str):
            rendered = re.sub(r"[^A-Za-z0-9_.:/ -]", "?", value)[:80]
        else:
            continue
        fields.append(f"{key}={rendered}")
    suffix = " " + " ".join(fields) if fields else ""
    _logger.info("TRACE request_id=%s step=%s state=%s%s", request_id or current_request_id(), step, state, suffix)
