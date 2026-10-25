"""
pipeline.py – Full RAG request pipeline for POST /chat.

Flow:
  1. Authenticate user (done in router; user passed in).
  2. Scan user prompt → block if INJECTION.
  3. Retrieve top-k role-filtered chunks.
  4. Scan each chunk → drop + quarantine flagged chunks.
  5. Build LLM prompt with UNTRUSTED REFERENCE DATA delimiters.
  6. Generate answer (streaming or not).
  7. Return answer + security trace + log everything.
"""
from __future__ import annotations

import json
import logging
import datetime
import time
from dataclasses import dataclass, field
from typing import Any, Generator, List, Literal, Optional

from sqlalchemy.orm import Session

from app.config import settings
from app.db import ChatLog, Chunk, Document, ScanLog, User
from app.ensemble import EnsembleResult, run_ensemble
from app.llm import build_rag_system_prompt, generate_answer
from app.output_guard import GuardResult, run_output_guard
from app.rbac import get_inaccessible_document_ids
from app.retrieval import RetrievedChunk, explain_empty_retrieval, retrieve_chunks
from app.diagnostics import current_request_id, trace_step

logger = logging.getLogger(__name__)


@dataclass
class DroppedChunk:
    chroma_id: str
    reason: str
    deberta_score: Optional[float] = None
    promptguard_score: Optional[float] = None


@dataclass
class SecurityTrace:
    prompt_scan: Optional[dict] = None
    chunks_used: List[str] = field(default_factory=list)       # chroma_ids
    chunks_dropped: List[DroppedChunk] = field(default_factory=list)
    retrieval_status: Optional[str] = None
    retrieval_counts: dict[str, int] = field(default_factory=dict)
    prompt_blocked: bool = False
    block_reason: Optional[str] = None
    output_guard: Optional[dict] = None   # result from run_output_guard


@dataclass
class DefenseConfig:
    """In-process configuration for defense evaluation (used only by red-team lab)."""
    scan_prompt: bool = True
    rbac_filter: bool = True
    scan_chunks: bool = True
    output_guard: bool = True
    collection_override: Any = None

    @classmethod
    def full(cls) -> "DefenseConfig":
        return cls(scan_prompt=True, rbac_filter=True, scan_chunks=True, output_guard=True)

    @classmethod
    def none(cls) -> "DefenseConfig":
        return cls(scan_prompt=False, rbac_filter=False, scan_chunks=False, output_guard=False)

    @classmethod
    def rbac_only(cls) -> "DefenseConfig":
        return cls(scan_prompt=False, rbac_filter=True, scan_chunks=False, output_guard=False)

    @classmethod
    def detectors_only(cls) -> "DefenseConfig":
        return cls(scan_prompt=True, rbac_filter=False, scan_chunks=True, output_guard=False)


@dataclass
class PipelineResult:
    answer: Optional[str]
    security_trace: SecurityTrace
    stream: Optional[Generator[str, None, None]] = None


def _ensemble_to_dict(res: EnsembleResult) -> dict:
    return {
        "final_label": res.final_label,
        "final_reason": res.final_reason,
        "deberta": {"label": res.deberta.label, "score": res.deberta.score, "error": res.deberta.error},
        "promptguard": {"label": res.promptguard.label, "score": res.promptguard.score, "error": res.promptguard.error},
        "gemini_used": res.gemini_used,
        "gemini": {"label": res.gemini.label, "confidence": res.gemini.score} if res.gemini_used else None,
    }


def _log_scan_to_db(
    db: Session,
    text: str,
    result: EnsembleResult,
    source: str,
    user_id: Optional[int] = None,
    chunk_id: Optional[int] = None,
    source_type: str = "live",
) -> None:
    log = ScanLog(
        source=source,
        source_type=source_type,
        text_preview=text[:500],
        deberta_label=result.deberta.label,
        deberta_score=result.deberta.score,
        deberta_latency_ms=result.deberta.latency_ms,
        deberta_error=result.deberta.error,
        promptguard_label=result.promptguard.label,
        promptguard_score=result.promptguard.score,
        promptguard_latency_ms=result.promptguard.latency_ms,
        promptguard_error=result.promptguard.error,
        gemini_used=result.gemini_used,
        gemini_label=result.gemini.label if result.gemini_used else None,
        gemini_reason=(result.gemini.raw.get("reason") if result.gemini_used and isinstance(result.gemini.raw, dict) else None),
        gemini_confidence=result.gemini.score if result.gemini_used else None,
        gemini_error=result.gemini.error if result.gemini_used else None,
        final_label=result.final_label,
        final_reason=result.final_reason,
        chunk_id=chunk_id,
        user_id=user_id,
    )
    db.add(log)


def run_chat_pipeline(
    question: str,
    model_key: str,
    user: User,
    db: Session,
    stream: bool = False,
    defense_config: Optional[DefenseConfig] = None,
    source_type: str = "live",
    now: datetime.datetime | None = None,
    conversation_history: list[dict[str, str]] | None = None,
) -> PipelineResult:
    """
    Execute the secure RAG pipeline.
    defense_config controls which defense layers are active (used by red-team lab).
    Normal requests always use DefenseConfig.full().
    """
    cfg = defense_config or DefenseConfig.full()
    trace = SecurityTrace()
    safe_model = model_key if model_key in ("large", "medium", "qwen") else "custom"
    trace_step("rag_pipeline", "start", user_id=user.id, role_id=user.role_id,
               source_type=source_type, model=safe_model, streaming=stream)

    # ── Step 2: Scan user prompt ──────────────────────────────────────────
    if cfg.scan_prompt:
        started = time.perf_counter()
        trace_step("prompt_scan", "start", user_id=user.id)
        try:
            prompt_scan = run_ensemble(question, source="prompt")
        except Exception as exc:
            trace_step("prompt_scan", "error", user_id=user.id, error_type=type(exc).__name__)
            raise
        trace_step("prompt_scan", "complete", user_id=user.id, verdict=prompt_scan.final_label,
                   blocked=prompt_scan.is_injection, duration_ms=round((time.perf_counter() - started) * 1000, 1))
        trace.prompt_scan = _ensemble_to_dict(prompt_scan)
        _log_scan_to_db(db, question, prompt_scan, source="prompt", user_id=user.id, source_type=source_type)

        if prompt_scan.is_injection:
            trace_step("rag_pipeline", "blocked", step_name="prompt_scan", user_id=user.id)
            trace.prompt_blocked = True
            trace.block_reason = prompt_scan.final_reason

            # Log chat attempt
            chat_log = ChatLog(
                user_id=user.id,
                question_preview=question[:500],
                model_used=model_key,
                prompt_blocked=True,
                source_type=source_type,
                answer_preview="[BLOCKED: prompt injection detected]",
            )
            db.add(chat_log)
            db.commit()
            trace_step("rag_pipeline", "complete", user_id=user.id, blocked=True, used_chunks=0)

            return PipelineResult(
                answer="[BLOCKED] Your request was identified as a potential prompt injection attempt.",
                security_trace=trace,
            )

    else:
        trace_step("prompt_scan", "skipped", reason="disabled_by_defense_config")

    # ── Step 3: Retrieve chunks ───────────────────────────────────────────
    started = time.perf_counter()
    trace_step("retrieval", "start", user_id=user.id, rbac_enabled=cfg.rbac_filter)
    retrieval_stats: dict[str, int | str] = {}
    retrieved = retrieve_chunks(
        question,
        user,
        db,
        rbac_filter=cfg.rbac_filter,
        collection_override=cfg.collection_override,
        now=now,
        stats=retrieval_stats,
    )
    trace.retrieval_status = str(retrieval_stats.get("status", "unknown"))
    trace.retrieval_counts = {
        key: int(value)
        for key, value in retrieval_stats.items()
        if key != "status" and isinstance(value, int)
    }
    trace_step("retrieval", "complete", user_id=user.id, retrieved_chunks=len(retrieved),
               distinct_documents=len({chunk.doc_id for chunk in retrieved}),
               duration_ms=round((time.perf_counter() - started) * 1000, 1))

    # ── Step 4: Scan each retrieved chunk ─────────────────────────────────
    clean_chunks: List[RetrievedChunk] = []
    for chunk in retrieved:
        if chunk.is_quarantined:
            trace_step("retrieved_chunk", "dropped", doc_id=chunk.doc_id,
                       chunk_id=chunk.sql_chunk_id or 0, reason="quarantined_or_pending")
            trace.chunks_dropped.append(
                DroppedChunk(
                    chroma_id=chunk.chroma_id,
                    reason="quarantined",
                )
            )
            continue

        if cfg.scan_chunks:
            started = time.perf_counter()
            trace_step("retrieved_chunk_scan", "start", doc_id=chunk.doc_id,
                       chunk_id=chunk.sql_chunk_id or 0, chunk_index=chunk.chunk_index)
            try:
                chunk_scan = run_ensemble(chunk.text, source="document")
            except Exception as exc:
                trace_step("retrieved_chunk_scan", "error", doc_id=chunk.doc_id,
                           chunk_id=chunk.sql_chunk_id or 0, error_type=type(exc).__name__)
                raise
            trace_step("retrieved_chunk_scan", "complete", doc_id=chunk.doc_id,
                       chunk_id=chunk.sql_chunk_id or 0, verdict=chunk_scan.final_label,
                       duration_ms=round((time.perf_counter() - started) * 1000, 1))
            chunk_id = chunk.sql_chunk_id

            _log_scan_to_db(db, chunk.text, chunk_scan, source="document", user_id=user.id, chunk_id=chunk_id, source_type=source_type)

            if chunk_scan.is_injection:
                trace_step("retrieved_chunk", "dropped", doc_id=chunk.doc_id,
                           chunk_id=chunk.sql_chunk_id or 0, decision=chunk_scan.final_reason)
                dropped = DroppedChunk(
                    chroma_id=chunk.chroma_id,
                    reason=chunk_scan.final_reason,
                    deberta_score=chunk_scan.deberta.score,
                    promptguard_score=chunk_scan.promptguard.score,
                )
                trace.chunks_dropped.append(dropped)

                if chunk_id:
                    sql_chunk = db.query(Chunk).filter(Chunk.id == chunk_id).first()
                    if sql_chunk:
                        reason = chunk_scan.final_reason

                        # Confirmed injection: BOTH detectors agree OR judge explicitly confirms INJECTION
                        if reason == "both_agree_injection" or reason.startswith("gemini_verdict:injection"):
                            sql_chunk.is_quarantined = True
                            sql_chunk.status = "quarantined"
                            sql_chunk.quarantine_reason = reason
                            sql_chunk.flagged_for_review = False
                            parent_doc = db.query(Document).filter(Document.id == chunk.doc_id).first()
                            if parent_doc:
                                parent_doc.is_quarantined = True
                                if reason not in (parent_doc.quarantine_reason or ""):
                                    parent_doc.quarantine_reason = (
                                        (parent_doc.quarantine_reason or "")
                                        + f"Chunk {chunk.chunk_index} flagged: {reason}. "
                                    )
                        else:
                            # Transient error (e.g. Gemini 429/timeout) or unconfirmed fail-closed:
                            # Hold ONLY this chunk as pending_judge without hard-quarantining parent document.
                            logger.info(
                                "Chunk %s held as pending_judge (doc %d NOT quarantined) reason=%s",
                                chunk.chroma_id, chunk.doc_id, reason,
                            )
                            sql_chunk.status = "pending_judge"
                            sql_chunk.flagged_for_review = True
                            if reason not in (sql_chunk.flag_reason or ""):
                                sql_chunk.flag_reason = (
                                    (sql_chunk.flag_reason or "") + reason + " "
                                )

                logger.warning(
                    "Dropped chunk %s from doc %d: %s",
                    chunk.chroma_id, chunk.doc_id, chunk_scan.final_reason,
                )
            else:
                # Benign chunk: clear any stale pending/flagged status
                if chunk_id:
                    sql_chunk = db.query(Chunk).filter(Chunk.id == chunk_id).first()
                    if sql_chunk and (sql_chunk.flagged_for_review or sql_chunk.status == "pending_judge"):
                        sql_chunk.flagged_for_review = False
                        sql_chunk.flag_reason = None
                        sql_chunk.status = "active"
                clean_chunks.append(chunk)
                trace.chunks_used.append(chunk.chroma_id)
                trace_step("retrieved_chunk", "accepted", doc_id=chunk.doc_id,
                           chunk_id=chunk.sql_chunk_id or 0)
        else:
            clean_chunks.append(chunk)
            trace.chunks_used.append(chunk.chroma_id)
            trace_step("retrieved_chunk_scan", "skipped", doc_id=chunk.doc_id,
                       chunk_id=chunk.sql_chunk_id or 0, reason="disabled_by_defense_config")

    # ── Step 5: Build LLM prompt ──────────────────────────────────────────
    context_blocks: List[str] = []
    remaining_context_chars = settings.max_context_chars
    for chunk in clean_chunks:
        if remaining_context_chars <= 0:
            break
        context = chunk.text[:remaining_context_chars]
        if context:
            context_blocks.append(context)
            remaining_context_chars -= len(context)
    if not context_blocks:
        answer = explain_empty_retrieval(question, user, db)
        if "pending security review" in answer:
            explanation_category = "pending_approval"
        elif "doesn't have access" in answer:
            explanation_category = "access_denied"
        elif "couldn't find a document" in answer:
            explanation_category = "not_found"
        elif "quarantined" in answer:
            explanation_category = "quarantined"
        else:
            explanation_category = "no_relevant_context"
            system_prompt = build_rag_system_prompt([], no_relevant_documents=True)
            trace_step("rag_prompt_build", "complete", user_id=user.id, context_chunks=0,
                       retrieval_status="no_relevant_chunks_above_threshold")
            answer = generate_answer(
                system_prompt=system_prompt,
                user_message=question,
                model_key=model_key,
                stream=False,
                conversation_history=conversation_history,
            )
            if not isinstance(answer, str):
                raise RuntimeError("The no-context response unexpectedly returned a stream.")
        trace_step("rag_empty_context", "complete", user_id=user.id, user_role=user.role.name,
                   explanation_category=explanation_category)
        _save_chat_log(db, user.id, question, model_key, trace, answer, source_type=source_type)
        db.commit()
        return PipelineResult(answer=answer, security_trace=trace)

    system_prompt = build_rag_system_prompt(context_blocks)
    trace_step("rag_prompt_build", "complete", user_id=user.id, context_chunks=len(context_blocks))

    # ── Step 6: Generate answer ───────────────────────────────────────────
    started = time.perf_counter()
    trace_step("answer_generation", "start", user_id=user.id, model=safe_model,
               context_chunks=len(context_blocks), streaming=stream)
    try:
        output = generate_answer(
            system_prompt=system_prompt,
            user_message=question,
            model_key=model_key,
            stream=stream,
            conversation_history=conversation_history,
        )
    except Exception as exc:
        logger.error("LLM generation failed: %s", exc)
        trace_step("answer_generation", "error", user_id=user.id, model=safe_model,
                   error_type=type(exc).__name__)
        db.commit()
        trace_step("rag_pipeline", "complete", user_id=user.id, outcome="generation_error")
        return PipelineResult(
            answer=f"[ERROR] Answer generation failed: {exc}",
            security_trace=trace,
        )

    # ── Step 7: Log and return ────────────────────────────────────────────
    if stream:
        stream_request_id = current_request_id()
        stream_user_id = user.id
        stream_db_bind = db.get_bind()
        trace_step("answer_generation", "stream_ready", user_id=user.id,
                   duration_ms=round((time.perf_counter() - started) * 1000, 1))
        def _streaming_with_log():
            collected = []
            stream_db = Session(bind=stream_db_bind)
            try:
                for token in output:  # type: ignore[union-attr]
                    collected.append(token)
                    yield token
                answer_text = "".join(collected)
                _save_chat_log(stream_db, stream_user_id, question, model_key, trace, answer_text)
                stream_db.commit()
                trace_step("answer_generation", "stream_complete", request_id=stream_request_id,
                           user_id=stream_user_id, output_chars=len(answer_text))
                trace_step("rag_pipeline", "complete", request_id=stream_request_id,
                           user_id=stream_user_id, streamed=True,
                           used_chunks=len(trace.chunks_used), dropped_chunks=len(trace.chunks_dropped))
            except Exception as exc:
                trace_step("answer_generation", "stream_error", request_id=stream_request_id,
                           user_id=stream_user_id, error_type=type(exc).__name__)
                raise
            finally:
                stream_db.close()

        db.commit()
        return PipelineResult(answer=None, security_trace=trace, stream=_streaming_with_log())

    answer_text = str(output)
    trace_step("answer_generation", "complete", user_id=user.id,
               output_chars=len(answer_text), duration_ms=round((time.perf_counter() - started) * 1000, 1))

    # ── Step 6b: Output guard ───────────────────────────────────────────
    if cfg.output_guard:
        try:
            from app.config import settings as _cfg
            started = time.perf_counter()
            trace_step("output_guard", "start", user_id=user.id, allowed_chunks=len(clean_chunks))
            forbidden_doc_ids = get_inaccessible_document_ids(user, db)
            forbidden_texts: list[str] = []
            for doc_id in forbidden_doc_ids:
                rows = db.query(Chunk).filter(Chunk.document_id == doc_id).all()
                for row in rows:
                    if row.text_content:
                        forbidden_texts.append(row.text_content)
                    elif row.text_preview:
                        forbidden_texts.append(row.text_preview)

            allowed_texts = [c.text for c in clean_chunks]

            guard_result = run_output_guard(
                answer=answer_text,
                allowed_texts=allowed_texts,
                forbidden_texts=forbidden_texts,
                ngram_threshold=getattr(_cfg, "output_guard_ngram_threshold", 0.15),
            )
            trace_step("output_guard", "complete", user_id=user.id,
                       triggered=guard_result.triggered, trigger_type=guard_result.trigger_type or "none",
                       redacted_count=guard_result.redacted_count,
                       restricted_documents=len(forbidden_doc_ids),
                       duration_ms=round((time.perf_counter() - started) * 1000, 1))
            trace.output_guard = {
                "triggered": guard_result.triggered,
                "trigger_type": guard_result.trigger_type,
                "matched_value": guard_result.matched_value,
                "redacted_count": guard_result.redacted_count,
            }
            answer_text = guard_result.answer

            if guard_result.triggered:
                from app.db import OutputLeakLog
                leak_log = OutputLeakLog(
                    user_id=user.id,
                    trigger_type=guard_result.trigger_type or "unknown",
                    matched_value=(guard_result.matched_value or "")[:256],
                    answer_preview=answer_text[:500],
                )
                db.add(leak_log)
        except Exception as guard_exc:
            logger.error("Output guard error (non-fatal): %s", guard_exc)
            trace_step("output_guard", "error", user_id=user.id, error_type=type(guard_exc).__name__)
    else:
        trace.output_guard = {"triggered": False, "skipped": True}
        trace_step("output_guard", "skipped", reason="disabled_by_defense_config")


    _save_chat_log(db, user.id, question, model_key, trace, answer_text, source_type=source_type)
    db.commit()

    trace_step("rag_pipeline", "complete", user_id=user.id, blocked=False,
               used_chunks=len(trace.chunks_used), dropped_chunks=len(trace.chunks_dropped))

    return PipelineResult(answer=answer_text, security_trace=trace)


def _save_chat_log(
    db: Session, user_id: int, question: str, model_key: str, trace: SecurityTrace, answer: str, source_type: str = "live"
) -> None:
    chat_log = ChatLog(
        user_id=user_id,
        question_preview=question[:500],
        model_used=model_key,
        chunks_used=json.dumps(trace.chunks_used),
        chunks_dropped=json.dumps(
            [{"chroma_id": d.chroma_id, "reason": d.reason} for d in trace.chunks_dropped]
        ),
        answer_preview=answer[:500],
        prompt_blocked=trace.prompt_blocked,
        source_type=source_type,
    )
    db.add(chat_log)


def reconcile_quarantined_documents(db: Session) -> None:
    """Ensure parent documents are quarantined if and only if they have confirmed quarantined chunks."""
    docs = db.query(Document).all()
    for doc in docs:
        confirmed_count = (
            db.query(Chunk)
            .filter(Chunk.document_id == doc.id, Chunk.is_quarantined == True)
            .count()
        )
        if confirmed_count > 0:
            doc.is_quarantined = True
        else:
            doc.is_quarantined = False
            # If doc had quarantine reason solely from unconfirmed flags, clean it
            if doc.quarantine_reason and "both_agree_injection" not in doc.quarantine_reason and "gemini_verdict:injection" not in doc.quarantine_reason:
                doc.quarantine_reason = None
    db.commit()


def retry_judge_for_chunk(db: Session, chunk: Chunk) -> dict:
    """Re-run the judge (with Groq fallback) on a chunk that was held as pending_judge."""
    from app.detectors.gemini_judge import gemini_judge
    res = gemini_judge(chunk.text_preview or "")
    if res.label == "BENIGN":
        chunk.status = "active"
        chunk.flagged_for_review = False
        chunk.flag_reason = None
        chunk.is_quarantined = False
        chunk.quarantine_reason = None
        reconcile_quarantined_documents(db)
        db.commit()
        return {"status": "cleared", "verdict": "BENIGN", "chunk_id": chunk.id}
    elif res.label == "INJECTION":
        chunk.status = "quarantined"
        chunk.is_quarantined = True
        chunk.quarantine_reason = f"judge_confirmed_injection: {res.raw.get('reason', '') if isinstance(res.raw, dict) else ''}"
        chunk.flagged_for_review = False
        reconcile_quarantined_documents(db)
        db.commit()
        return {"status": "quarantined", "verdict": "INJECTION", "chunk_id": chunk.id}
    else:
        chunk.status = "pending_judge"
        chunk.flagged_for_review = True
        db.commit()
        return {"status": "pending_judge", "verdict": "UNKNOWN", "chunk_id": chunk.id, "error": res.error}
