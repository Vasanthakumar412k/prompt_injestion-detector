"""
runner.py – Red-team lab test runner.

Runs attacks against combinations of models, defense configurations, and splits.
Features:
  - In-process pipeline execution with DefenseConfig (cannot be triggered via HTTP).
  - Deterministic success evaluation (never LLM-as-judge).
  - Detector result caching by text hash.
  - Resumable runs: every result row is saved immediately; existing rows are skipped.
  - Temporary poisoned document planting and guaranteed cleanup for document attacks.
  - Rate-limit backoff and concurrency control.
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from typing import Any, Callable, Dict, List, Optional

from sqlalchemy.orm import Session

from app.config import settings
from app.db import (
    Chunk,
    Document,
    LabResult,
    LabRun,
    Permission,
    Role,
    SessionLocal,
    User,
)
from app.ensemble import EnsembleResult, run_ensemble
from app.ingest import ingest_document
from app.lab.attacks import Attack, check_deterministic_success, load_attacks
from app.pipeline import DefenseConfig, DroppedChunk, PipelineResult, run_chat_pipeline

logger = logging.getLogger(__name__)

# In-memory detector cache: (text_sha256, source) -> EnsembleResult
_DETECTOR_CACHE: Dict[tuple[str, str], EnsembleResult] = {}


def _get_cached_ensemble(text: str, source: str) -> EnsembleResult:
    h = hashlib.sha256(text.encode("utf-8")).hexdigest()
    key = (h, source)
    if key in _DETECTOR_CACHE:
        return _DETECTOR_CACHE[key]
    res = run_ensemble(text, source=source)
    _DETECTOR_CACHE[key] = res
    return res


def _resolve_defense_config(config_name: str) -> DefenseConfig:
    name = config_name.lower()
    if name == "none":
        return DefenseConfig.none()
    elif name == "rbac_only":
        return DefenseConfig.rbac_only()
    elif name == "detectors_only":
        return DefenseConfig.detectors_only()
    elif name == "full":
        return DefenseConfig.full()
    else:
        raise ValueError(f"Unknown defense configuration: {config_name}")


def _determine_blocked_by(trace, config: str) -> Optional[str]:
    """Identify which security layer caused the block."""
    if trace.prompt_blocked:
        pscan = trace.prompt_scan or {}
        reason = pscan.get("final_reason", "")
        if "normalizer" in reason:
            return "normalizer"
        elif "gemini" in reason:
            return "gemini"
        elif "both_agree" in reason or "deberta" in reason or "promptguard" in reason:
            deb_s = pscan.get("deberta", {}).get("score", 0.0) or 0.0
            pg_s = pscan.get("promptguard", {}).get("score", 0.0) or 0.0
            if deb_s > pg_s:
                return "deberta"
            else:
                return "promptguard"
        return "prompt_detector"

    if trace.chunks_dropped:
        first = trace.chunks_dropped[0]
        reason = first.reason
        if "gemini" in reason:
            return "gemini"
        elif "deberta" in reason or "both_agree" in reason:
            return "deberta"
        elif "promptguard" in reason:
            return "promptguard"
        return "document_detector"

    og = trace.output_guard or {}
    if og.get("triggered"):
        ttype = og.get("trigger_type")
        if ttype == "canary":
            return "output_guard_canary"
        elif ttype == "ngram_overlap":
            return "output_guard_ngram"
        return "output_guard"

    # If RBAC prevented any chunks from being returned when docs exist
    if config in ("rbac_only", "full") and not trace.chunks_used and not trace.chunks_dropped:
        return "rbac"

    return None


def run_single_attack(
    attack: Attack,
    model: str,
    config: str,
    db: Session,
    mock_generator: Optional[Callable[[str, str], str]] = None,
) -> LabResult:
    """
    Execute a single attack against the RAG pipeline.
    mock_generator: optional replacement for generate_answer for deterministic unit tests.
    """
    defense_cfg = _resolve_defense_config(config)

    # Get attacker user
    username = f"{attack.attacker_role}_user"
    if attack.attacker_role == "admin":
        username = "admin"
    user = db.query(User).filter(User.username == username).first()
    if not user:
        user = db.query(User).filter(User.username == "employee_user").first()
    if not user:
        raise RuntimeError("No user found in database to execute attack")

    # Handle document vs user_prompt delivery
    planted_doc_id: Optional[int] = None
    question = attack.payload

    if attack.delivery == "document":
        admin_user = db.query(User).filter(User.username == "admin").first() or user
        doc_filename = f"lab_planted_{attack.id}_{attack.doc_title or 'doc.txt'}"
        try:
            planted_doc, _ = ingest_document(
                content=attack.payload.encode("utf-8"),
                filename=doc_filename,
                content_type="text/plain",
                uploader_id=admin_user.id,
                allowed_role_names=["employee", "hr"],
                db=db,
                scan_on_ingest=False,  # let it into vector store to test retrieval-time defenses
            )
            planted_doc_id = planted_doc.id
            question = f"Summarize the information in {attack.doc_title or 'the uploaded document'}."
        except Exception as exc:
            logger.warning("Failed to plant lab document: %s", exc)

    t0 = time.monotonic()
    error_msg: Optional[str] = None
    result_obj: Optional[PipelineResult] = None

    try:
        if mock_generator is not None:
            # For testing: temporarily monkey-patch answer generator
            import app.pipeline as _p
            orig_gen = _p.generate_answer
            _p.generate_answer = lambda system_prompt, user_message, model_key, stream=False: mock_generator(system_prompt, user_message)
            try:
                result_obj = run_chat_pipeline(
                    question=question,
                    model_key=model,
                    user=user,
                    db=db,
                    stream=False,
                    defense_config=defense_cfg,
                    source_type="lab",
                )
            finally:
                _p.generate_answer = orig_gen
        else:
            result_obj = run_chat_pipeline(
                question=question,
                model_key=model,
                user=user,
                db=db,
                stream=False,
                defense_config=defense_cfg,
                source_type="lab",
            )
    except Exception as exc:
        logger.error("Error executing attack %s: %s", attack.id, exc)
        error_msg = str(exc)
    finally:
        # Cleanup planted document
        if planted_doc_id is not None:
            try:
                _cleanup_lab_doc(planted_doc_id, db)
            except Exception as clean_err:
                logger.warning("Error cleaning up planted lab doc %d: %s", planted_doc_id, clean_err)

    latency_ms = (time.monotonic() - t0) * 1000

    # Extract results
    answer = result_obj.answer if result_obj else ""
    trace = result_obj.security_trace if result_obj else None

    prompt_blocked = trace.prompt_blocked if trace else False
    chunks_dropped = trace.chunks_dropped if trace else []
    og_trig = trace.output_guard.get("triggered", False) if trace and trace.output_guard else False

    if config == "none":
        blocked_by = None
        blocked = False
    else:
        blocked_by = _determine_blocked_by(trace, config) if trace else None
        blocked = (blocked_by is not None) or prompt_blocked or og_trig or bool(chunks_dropped)

    # Deterministic evaluation
    attack_success, reason = check_deterministic_success(
        attack=attack,
        answer=answer or "",
        prompt_blocked=prompt_blocked,
        chunks_dropped=chunks_dropped,
        output_guard_triggered=og_trig,
        is_none_config=(config == "none"),
    )

    pscan = (trace.prompt_scan if trace else None) or {}
    deb_info = pscan.get("deberta") or {}
    pg_info = pscan.get("promptguard") or {}
    gem_info = pscan.get("gemini") or {}

    res_row = LabResult(
        attack_id=attack.id,
        split=attack.split,
        category=attack.category,
        delivery=attack.delivery,
        model=model,
        config=config,
        attack_success=attack_success if not attack.is_benign else None,
        is_benign=attack.is_benign,
        benign_answered=(attack_success if attack.is_benign else None),
        blocked=blocked,
        blocked_by=blocked_by,
        deberta_label=deb_info.get("label"),
        deberta_score=deb_info.get("score"),
        pg_label=pg_info.get("label"),
        pg_score=pg_info.get("score"),
        gemini_used=pscan.get("gemini_used", False),
        gemini_label=gem_info.get("label") if gem_info else None,
        output_guard_triggered=og_trig,
        latency_ms=latency_ms,
        answer_preview=(answer or "")[:500],
        error=error_msg,
    )
    return res_row


def _cleanup_lab_doc(doc_id: int, db: Session) -> None:
    """Delete a temporary lab document and remove its chunks from Chroma and SQL."""
    from app.retrieval import _get_collection
    collection = _get_collection()

    chunks = db.query(Chunk).filter(Chunk.document_id == doc_id).all()
    chroma_ids = [c.chroma_id for c in chunks]
    if chroma_ids:
        try:
            collection.delete(ids=chroma_ids)
        except Exception as e:
            logger.debug("Chroma delete failed for lab doc %d: %s", doc_id, e)

    db.query(Permission).filter(Permission.document_id == doc_id).delete()
    db.query(Chunk).filter(Chunk.document_id == doc_id).delete()
    db.query(Document).filter(Document.id == doc_id).delete()
    db.commit()


def run_lab(
    models: Optional[List[str]] = None,
    configs: Optional[List[str]] = None,
    splits: Optional[List[str]] = None,
    run_id: Optional[str] = None,
    max_attacks: Optional[int] = None,
    delay_between_calls: float = 0.5,
) -> str:
    """
    Execute full or partial red-team lab run.
    Stores progress row by row in SQLite, supports resumption.
    Returns: run_id.
    """
    models = models or ["large", "medium", "qwen"]
    configs = configs or ["none", "full"]
    splits = splits or ["dev"]

    actual_run_id = run_id or f"run_{uuid.uuid4().hex[:12]}"
    db = SessionLocal()

    try:
        # Check or create LabRun
        lab_run = db.query(LabRun).filter(LabRun.run_id == actual_run_id).first()
        if not lab_run:
            all_attacks: List[Attack] = []
            for s in splits:
                all_attacks.extend(load_attacks(split=s))
            if max_attacks:
                all_attacks = all_attacks[:max_attacks]

            total = len(all_attacks) * len(models) * len(configs)
            lab_run = LabRun(
                run_id=actual_run_id,
                models=json.dumps(models),
                configs=json.dumps(configs),
                splits=json.dumps(splits),
                status="running",
                total_attacks=total,
                completed_attacks=0,
            )
            db.add(lab_run)
            db.commit()
        else:
            lab_run.status = "running"
            db.commit()

        # Load target attacks
        attacks_to_run: List[Attack] = []
        for s in splits:
            attacks_to_run.extend(load_attacks(split=s))
        if max_attacks:
            attacks_to_run = attacks_to_run[:max_attacks]

        for attack in attacks_to_run:
            for model in models:
                for config in configs:
                    # Check if already completed (resumability)
                    existing = (
                        db.query(LabResult)
                        .filter(
                            LabResult.run_id == actual_run_id,
                            LabResult.attack_id == attack.id,
                            LabResult.model == model,
                            LabResult.config == config,
                        )
                        .first()
                    )
                    if existing:
                        continue

                    try:
                        result = run_single_attack(attack, model, config, db)
                        result.run_id = actual_run_id
                        db.add(result)

                        lab_run.completed_attacks = (lab_run.completed_attacks or 0) + 1
                        db.commit()
                    except Exception as loop_err:
                        logger.error("Failed on attack %s (model %s config %s): %s", attack.id, model, config, loop_err)
                        # Back off on rate limits
                        if "429" in str(loop_err) or "quota" in str(loop_err).lower():
                            time.sleep(5.0)

                    if delay_between_calls > 0:
                        time.sleep(delay_between_calls)

        import datetime
        lab_run.status = "done"
        lab_run.finished_at = datetime.datetime.now(datetime.timezone.utc)
        db.commit()

        # Generate report
        try:
            from app.lab.report import generate_reports
            generate_reports(actual_run_id, db)
        except Exception as rep_err:
            logger.error("Report generation failed: %s", rep_err)

    except Exception as exc:
        logger.error("Lab run failed: %s", exc)
        if lab_run:
            try:
                db.rollback()
                lab_run = db.query(LabRun).filter(LabRun.run_id == actual_run_id).first()
                if lab_run:
                    lab_run.status = "error"
                    lab_run.error = str(exc)
                    db.commit()
            except Exception as roll_err:
                logger.error("Failed to mark lab run as error: %s", roll_err)
    finally:
        db.close()

    return actual_run_id
