"""
app/audit/scheduler.py – In-process scheduler for offline audits.

Supports:
  - Fixed interval triggering (every N hours)
  - Event-count triggering (when N flagged events accumulate or time limit passes)
  - Unit-testable with customizable time and event evaluation
"""
from __future__ import annotations

import datetime
import json
import logging
import threading
import time
from typing import Callable, Optional

from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.audit.service import execute_audit_run, get_or_init_audit_state
from app.db import AuditRun, AuditState, ChatLog, ScanLog, SessionLocal

logger = logging.getLogger(__name__)

_stop_event = threading.Event()
_scheduler_thread: Optional[threading.Thread] = None


def count_flagged_events_since(
    db: Session,
    last_chat_id: int,
    last_scan_id: int,
) -> int:
    """Count high-priority security events since the specified log cursors."""
    flagged_chats = (
        db.query(ChatLog)
        .filter(
            ChatLog.id > last_chat_id,
            or_(
                ChatLog.prompt_blocked == True,
                ChatLog.chunks_dropped != "[]",
                ChatLog.chunks_dropped.isnot(None),
            ),
        )
        .count()
    )

    flagged_scans = (
        db.query(ScanLog)
        .filter(
            ScanLog.id > last_scan_id,
            or_(
                ScanLog.final_label == "INJECTION",
                ScanLog.gemini_used == True,
            ),
        )
        .count()
    )

    return flagged_chats + flagged_scans


def should_trigger_audit(
    state: AuditState,
    db: Session,
    current_time: Optional[datetime.datetime] = None,
) -> bool:
    """
    Pure evaluation function: returns True if an audit should be triggered.
    """
    now = current_time or datetime.datetime.now(datetime.timezone.utc)

    # If never run, run immediately if any logs exist
    if not state.last_run_at:
        return True

    # Make state.last_run_at timezone-aware for clean comparison
    last_run = state.last_run_at
    if last_run.tzinfo is None:
        last_run = last_run.replace(tzinfo=datetime.timezone.utc)

    elapsed_hours = (now - last_run).total_seconds() / 3600.0

    if state.schedule_mode == "interval":
        return elapsed_hours >= (state.interval_hours or 24.0)

    elif state.schedule_mode == "event_count":
        # Check event threshold
        flagged_count = count_flagged_events_since(db, state.last_chat_log_id, state.last_scan_log_id)
        if flagged_count >= (state.event_threshold or 20):
            return True
        # Flexible fallback: time limit passed
        if elapsed_hours >= (state.interval_hours or 24.0):
            return True
        return False

    return False


def run_scheduler_tick(
    db: Session,
    now_fn: Optional[Callable[[], datetime.datetime]] = None,
) -> Optional[AuditRun]:
    """
    Evaluates current state against scheduler rules and executes an audit if triggered.
    """
    state = get_or_init_audit_state(db)
    current_time = now_fn() if now_fn else datetime.datetime.now(datetime.timezone.utc)

    if should_trigger_audit(state, db, current_time=current_time):
        logger.info("Scheduler triggered audit (mode=%s, last_run=%s)", state.schedule_mode, state.last_run_at)
        return execute_audit_run(db, auditor_model=state.auditor_model)
    return None


def _background_scheduler_loop(interval_seconds: int = 60):
    while not _stop_event.is_set():
        try:
            db = SessionLocal()
            try:
                run_scheduler_tick(db)
            finally:
                db.close()
        except Exception as exc:
            logger.debug("Scheduler tick error: %s", exc)
        _stop_event.wait(interval_seconds)


def start_scheduler():
    global _scheduler_thread, _stop_event
    if _scheduler_thread is not None and _scheduler_thread.is_alive():
        return
    _stop_event.clear()
    _scheduler_thread = threading.Thread(target=_background_scheduler_loop, daemon=True, name="AuditScheduler")
    _scheduler_thread.start()
    logger.info("Audit scheduler background thread started.")


def stop_scheduler():
    global _stop_event, _scheduler_thread
    _stop_event.set()
    if _scheduler_thread:
        _scheduler_thread.join(timeout=2.0)
        _scheduler_thread = None
