"""
app/audit/collector.py – Selects and redacts traffic logs for audit.

Follows the design:
  - Takes chat_logs and scan_logs since last audit cursor.
  - Always includes blocked, dropped, disagreed, and output-guard events.
  - Samples normal traffic (configurable %).
  - Applies strict redaction to each item before returning.
"""
from __future__ import annotations

import json
import logging
import random
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from app.audit.redaction import redact_log_item
from app.db import ChatLog, Chunk, Document, OutputLeakLog, Permission, ScanLog, User
from app.rbac import get_inaccessible_document_ids

logger = logging.getLogger(__name__)


def _get_restricted_phrases_for_user(user_id: Optional[int], db: Session) -> List[str]:
    """
    Find text snippets from documents that the given user does not have permission to read.
    """
    if user_id is None:
        # If user is anonymous or unknown, all documents with permissions are restricted
        docs = db.query(Document).all()
        doc_ids = [d.id for d in docs]
    else:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return []
        doc_ids = get_inaccessible_document_ids(user, db)

    phrases = []
    if doc_ids:
        chunks = db.query(Chunk).filter(Chunk.document_id.in_(doc_ids)).all()
        for c in chunks:
            text = c.text_content or c.text_preview
            if text:
                # Add sentences or key phrases from the preview
                phrases.append(text)
                for part in text.split("\n"):
                    part = part.strip()
                    if len(part) > 10:
                        phrases.append(part)
    return phrases


def collect_and_redact_logs(
    db: Session,
    last_chat_id: int = 0,
    last_scan_id: int = 0,
    sampling_rate: float = 0.1,
    include_lab: bool = False,
) -> Tuple[List[Dict[str, Any]], Tuple[int, int], Dict[str, int]]:
    """
    Collects new logs, applies redactions, and returns:
    (redacted_items, (new_last_chat_id, new_last_scan_id), total_redactions_count)
    """
    chat_q = db.query(ChatLog).filter(ChatLog.id > last_chat_id)
    scan_q = db.query(ScanLog).filter(ScanLog.id > last_scan_id)

    if not include_lab:
        chat_q = chat_q.filter((ChatLog.source_type == "live") | (ChatLog.source_type.is_(None)))
        scan_q = scan_q.filter((ScanLog.source_type == "live") | (ScanLog.source_type.is_(None)))

    new_chats = chat_q.order_by(ChatLog.id.asc()).all()
    new_scans = scan_q.order_by(ScanLog.id.asc()).all()

    max_chat_id = max([c.id for c in new_chats], default=last_chat_id)
    max_scan_id = max([s.id for s in new_scans], default=last_scan_id)

    selected_chats: List[ChatLog] = []
    for c in new_chats:
        dropped = json.loads(c.chunks_dropped or "[]")
        # Flagged if prompt was blocked or chunks were dropped
        if c.prompt_blocked or len(dropped) > 0:
            selected_chats.append(c)
        elif random.random() < sampling_rate:
            selected_chats.append(c)

    selected_scans: List[ScanLog] = []
    for s in new_scans:
        # Flagged if injection, disagreed, or gemini used
        disagreed = (s.deberta_label != s.promptguard_label) and (s.deberta_label is not None and s.promptguard_label is not None)
        if s.final_label == "INJECTION" or disagreed or s.gemini_used:
            selected_scans.append(s)
        elif random.random() < sampling_rate:
            selected_scans.append(s)

    # Perform redactions on each selected item
    redacted_items: List[Dict[str, Any]] = []
    combined_redactions = {"emails": 0, "canaries": 0, "secrets": 0, "restricted_phrases": 0, "user_pseudonyms": 0}

    for c in selected_chats:
        restricted_phrases = _get_restricted_phrases_for_user(c.user_id, db)
        item = {
            "id": f"chat:{c.id}",
            "raw_id": c.id,
            "user_id": c.user_id,
            "question_preview": c.question_preview,
            "answer_preview": c.answer_preview,
            "model_used": c.model_used,
            "prompt_blocked": c.prompt_blocked,
            "chunks_used_count": len(json.loads(c.chunks_used or "[]")),
            "chunks_dropped_count": len(json.loads(c.chunks_dropped or "[]")),
            "created_at": str(c.created_at),
        }
        sanitized, counts = redact_log_item("chat", item, restricted_phrases)
        redacted_items.append(sanitized)
        for k, v in counts.items():
            combined_redactions[k] += v

    for s in selected_scans:
        restricted_phrases = _get_restricted_phrases_for_user(s.user_id, db)
        item = {
            "id": f"scan:{s.id}",
            "raw_id": s.id,
            "user_id": s.user_id,
            "source": s.source,
            "text_preview": s.text_preview,
            "deberta_label": s.deberta_label,
            "promptguard_label": s.promptguard_label,
            "gemini_used": s.gemini_used,
            "final_label": s.final_label,
            "final_reason": s.final_reason,
            "created_at": str(s.created_at),
        }
        sanitized, counts = redact_log_item("scan", item, restricted_phrases)
        redacted_items.append(sanitized)
        for k, v in counts.items():
            combined_redactions[k] += v

    return redacted_items, (max_chat_id, max_scan_id), combined_redactions
