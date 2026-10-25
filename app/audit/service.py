"""
app/audit/service.py – Orchestrator for the Offline Security Auditor.

Coordinates collection, redaction, analysis, validation, and report generation.
"""
from __future__ import annotations

import datetime
import json
import logging
import uuid
from typing import Optional

from sqlalchemy.orm import Session

from app.audit.analyzer import analyze_redacted_logs
from app.audit.collector import collect_and_redact_logs
from app.audit.reporter import build_audit_summary
from app.audit.validator import validate_findings
from app.db import AuditFinding, AuditRun, AuditState

logger = logging.getLogger(__name__)


def get_or_init_audit_state(db: Session) -> AuditState:
    """Retrieve the single persistent AuditState row or create default."""
    state = db.query(AuditState).first()
    if not state:
        state = AuditState(
            id=1,
            last_chat_log_id=0,
            last_scan_log_id=0,
            schedule_mode="interval",
            interval_hours=24.0,
            event_threshold=20,
            sampling_rate=0.1,
            auditor_model="openai/gpt-oss-120b",
            webhook_url="",
        )
        db.add(state)
        db.commit()
        db.refresh(state)
    return state


def execute_audit_run(
    db: Session,
    auditor_model: Optional[str] = None,
    force: bool = False,
    include_lab: bool = False,
) -> AuditRun:
    """
    Executes a complete offline audit cycle:
    1. Collects un-audited logs with redactions applied.
    2. Runs analysis via the auditor LLM (or deterministic fallback).
    3. Validates suspected attacks against the lab runner.
    4. Compiles summary reports and updates audit cursors.
    """
    state = get_or_init_audit_state(db)
    model = auditor_model or state.auditor_model or "openai/gpt-oss-120b"

    run_id = f"audit_{uuid.uuid4().hex[:12]}"

    # Step 1: Collect and redact
    redacted_items, (new_chat_id, new_scan_id), redactions = collect_and_redact_logs(
        db=db,
        last_chat_id=state.last_chat_log_id,
        last_scan_id=state.last_scan_log_id,
        sampling_rate=state.sampling_rate,
        include_lab=include_lab,
    )

    if not redacted_items and not force:
        logger.info("No new logs to audit (chat_cursor=%d, scan_cursor=%d)", state.last_chat_log_id, state.last_scan_log_id)
        # Create a benign empty audit run record
        run = AuditRun(
            run_id=run_id,
            status="completed",
            total_logs_analyzed=0,
            redactions_count=json.dumps(redactions),
            summary=json.dumps({
                "run_id": run_id,
                "total_logs_analyzed": 0,
                "total_findings": 0,
                "severity_counts": {"high": 0, "medium": 0, "low": 0},
                "status_counts": {"confirmed": 0, "not_reproduced": 0, "suspected": 0},
                "top_recommendations": ["No traffic anomalies detected in current period."],
                "false_positive_candidates": [],
                "redactions_applied": redactions,
            }),
            auditor_model=model,
        )
        db.add(run)
        db.commit()
        db.refresh(run)
        return run

    # Step 2: Create AuditRun record
    run = AuditRun(
        run_id=run_id,
        status="running",
        total_logs_analyzed=len(redacted_items),
        redactions_count=json.dumps(redactions),
        auditor_model=model,
    )
    db.add(run)
    db.commit()
    db.refresh(run)

    try:
        # Step 3: LLM Analysis
        raw_findings = analyze_redacted_logs(redacted_items, model_name=model)

        # Step 4: Persist findings as suspected
        db_findings = []
        for rf in raw_findings:
            finding = AuditFinding(
                audit_run_id=run.id,
                finding_uid=rf.get("finding_id") or f"FIND-{len(db_findings)+1:03d}",
                severity=rf.get("severity", "medium"),
                category=rf.get("category", "other"),
                status="suspected",
                evidence_log_ids=json.dumps(rf.get("evidence", [])),
                explanation=rf.get("explanation"),
                suggested_action=rf.get("suggested_action"),
                confidence=float(rf.get("confidence", 0.8)),
            )
            db.add(finding)
            db_findings.append(finding)

        db.commit()
        for f in db_findings:
            db.refresh(f)

        # Step 5: Validation against lab
        validate_findings(run, db_findings, db)

        # Step 6: Summary & finalize
        summary = build_audit_summary(run, db_findings, db)
        run.summary = json.dumps(summary)
        run.status = "completed"

        # Update cursor
        state.last_chat_log_id = new_chat_id
        state.last_scan_log_id = new_scan_id
        state.last_run_at = datetime.datetime.now(datetime.timezone.utc)
        db.commit()

        # Optional webhook dispatch (off by default)
        if state.webhook_url:
            try:
                import urllib.request
                req = urllib.request.Request(
                    state.webhook_url,
                    data=json.dumps(summary).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                urllib.request.urlopen(req, timeout=5)
            except Exception as hook_err:
                logger.warning("Audit webhook failed (non-fatal): %s", hook_err)

        logger.info("Audit run %s completed with %d findings", run_id, len(db_findings))
        return run

    except Exception as exc:
        logger.error("Audit run %s failed: %s", run_id, exc)
        db.rollback()
        run = db.query(AuditRun).filter(AuditRun.run_id == run_id).first()
        if run:
            run.status = "error"
            run.error = str(exc)
            db.commit()
        raise exc
