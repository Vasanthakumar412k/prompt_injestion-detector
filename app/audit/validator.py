"""
app/audit/validator.py – Validates suspected findings using the Red-Team Lab runner.

Converts suspected injection attempts or data leaks into 'candidate' attacks,
runs them against the full defense stack, and marks them 'confirmed' if they succeed,
or 'not_reproduced' if blocked/refused.
"""
from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from app.db import AuditFinding, AuditRun, ChatLog, LabResult, LabRun, ScanLog
from app.lab.attacks import Attack
from app.lab.runner import run_single_attack

logger = logging.getLogger(__name__)


def _extract_payload_from_evidence(evidence_ids: List[str], db: Session) -> Optional[str]:
    """Retrieve the original text payload referenced in evidence logs."""
    for eid in evidence_ids:
        if eid.startswith("chat:"):
            try:
                cid = int(eid.split(":")[1])
                chat = db.query(ChatLog).filter(ChatLog.id == cid).first()
                if chat and chat.question_preview:
                    return chat.question_preview
            except Exception:
                pass
        elif eid.startswith("scan:"):
            try:
                sid = int(eid.split(":")[1])
                scan = db.query(ScanLog).filter(ScanLog.id == sid).first()
                if scan and scan.text_preview:
                    return scan.text_preview
            except Exception:
                pass
    return None


def validate_findings(
    audit_run: AuditRun,
    findings: List[AuditFinding],
    db: Session,
    target_model: str = "large",
) -> None:
    """
    Validate suspected findings in place, updating their status and linking them to LabResult rows.
    """
    val_run_id = f"val_{audit_run.run_id[:12]}"

    # Ensure a parent LabRun exists for validation records
    lab_run = db.query(LabRun).filter(LabRun.run_id == val_run_id).first()
    if not lab_run:
        lab_run = LabRun(
            run_id=val_run_id,
            models=f'["{target_model}"]',
            configs='["full"]',
            splits='["candidate"]',
            status="completed",
            total_attacks=len(findings),
            completed_attacks=0,
        )
        db.add(lab_run)
        db.commit()

    for finding in findings:
        # Only validate injection attempts and possible leaks
        if finding.category not in ("injection_attempt", "possible_leak"):
            finding.status = "suspected"
            continue

        evidence = []
        try:
            import json
            evidence = json.loads(finding.evidence_log_ids or "[]")
        except Exception:
            evidence = [finding.evidence_log_ids] if finding.evidence_log_ids else []

        payload = _extract_payload_from_evidence(evidence, db)
        if not payload:
            finding.status = "not_reproduced"
            continue

        cand_attack_id = f"cand_{finding.finding_uid}_{uuid.uuid4().hex[:6]}"
        attack = Attack(
            id=cand_attack_id,
            split="candidate",
            category=finding.category,
            delivery="user_prompt",
            attacker_role="employee",
            payload=payload,
            success_check={"type": "contains_str", "value": "PWNED"} if "PWNED" in payload else {"type": "refusal_only"},
        )

        try:
            # Run attack through lab with full defenses
            result_row = run_single_attack(
                attack=attack,
                model=target_model,
                config="full",
                db=db,
            )
            result_row.run_id = val_run_id
            db.add(result_row)
            db.commit()
            db.refresh(result_row)

            finding.lab_result_id = result_row.id
            if result_row.attack_success:
                finding.status = "confirmed"
            else:
                finding.status = "not_reproduced"

            lab_run.completed_attacks = (lab_run.completed_attacks or 0) + 1
            db.commit()

        except Exception as val_err:
            logger.error("Failed to validate finding %s: %s", finding.finding_uid, val_err)
            finding.status = "not_reproduced"
            db.commit()
