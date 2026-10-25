"""
retrieval.py – Retrieve top-k chunks filtered by user role BEFORE similarity search,
then re-verify each chunk against SQL permissions.
"""
from __future__ import annotations

import logging
import datetime
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, List, Optional

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.config import settings
from app.db import Chunk, Document, User
from app.rbac import can_read, get_accessible_document_ids, role_name
from app.diagnostics import trace_step

logger = logging.getLogger(__name__)

_collection = None


def _get_collection():
    global _collection
    if _collection is None:
        import chromadb  # type: ignore
        from chromadb.utils import embedding_functions  # type: ignore

        client = chromadb.PersistentClient(path=settings.chroma_persist_dir)
        ef = embedding_functions.SentenceTransformerEmbeddingFunction(
            model_name=settings.embedding_model
        )
        _collection = client.get_or_create_collection(
            name=settings.chroma_collection,
            embedding_function=ef,
        )
    return _collection


@dataclass
class RetrievedChunk:
    chroma_id: str
    text: str
    doc_id: int
    chunk_index: int
    distance: float
    sql_chunk_id: Optional[int] = None
    is_quarantined: bool = False


def retrieve_chunks(
    query: str,
    user: User,
    db: Session,
    top_k: int | None = None,
    rbac_filter: bool = True,
    collection_override: Any = None,
    now: datetime.datetime | None = None,
) -> List[RetrievedChunk]:
    """
    Retrieve top-k relevant chunks.
    If rbac_filter is True (default), filters by user's role before and after search.
    If rbac_filter is False (used in lab 'none' or 'detectors_only'), skips RBAC checks.
    """
    k = top_k or settings.retrieval_top_k
    started = time.perf_counter()
    user_role = role_name(user.role)
    trace_step("vector_retrieval", "start", user_id=user.id, user_role=user_role,
               rbac_enabled=rbac_filter, top_k=k)

    accessible_set: set[int] = set()
    if rbac_filter:
        accessible_doc_ids = get_accessible_document_ids(user, db, now=now)
        accessible_set = set(int(d) for d in accessible_doc_ids)
        candidate_document_ids = {
            row[0] for row in db.query(Chunk.document_id).distinct().all()
        }
        excluded_documents = (
            db.query(Document)
            .filter(Document.id.in_(candidate_document_ids - accessible_set))
            .all()
            if candidate_document_ids - accessible_set
            else []
        )
        logger.info(
            "Retrieval filters user_id=%d role=%s filters=%s candidate_documents_before=%d "
            "candidate_documents_after=%d",
            user.id,
            user_role,
            {
                "document_id_filter": "accessible SQL document IDs",
                "accessible_document_count": len(accessible_set),
                "quarantined": "excluded",
                "pending_judge": "excluded",
            },
            len(candidate_document_ids),
            len(candidate_document_ids & accessible_set),
        )
        status_rows = (
            db.query(
                Chunk.document_id,
                Chunk.status,
                Chunk.is_quarantined,
                func.count(Chunk.id),
            )
            .group_by(Chunk.document_id, Chunk.status, Chunk.is_quarantined)
            .all()
        )
        statuses_by_document: dict[int, list[str]] = {}
        for document_id, chunk_status, is_quarantined, _count in status_rows:
            status = "quarantined" if is_quarantined else (chunk_status or "active")
            statuses_by_document.setdefault(document_id, []).append(status)
        for document in excluded_documents:
            statuses = sorted(set(statuses_by_document.get(document.id, ["no_chunks"])))
            logger.info(
                "Retrieval excluded document_id=%d department=%s confidentiality=%s "
                "document_quarantined=%s chunk_statuses=%s reason=%s",
                document.id,
                document.department.name if document.department else None,
                document.confidentiality,
                document.is_quarantined,
                statuses,
                "document_quarantined" if document.is_quarantined else "access_denied",
            )
        trace_step(
            "vector_prefilter",
            "complete",
            user_id=user.id,
            user_role=user_role,
            candidate_documents_before=len(candidate_document_ids),
            candidate_documents_after=len(candidate_document_ids & accessible_set),
            accessible_documents=len(accessible_set),
            filters_applied=True,
        )
        if not accessible_doc_ids:
            logger.info("User id=%d role=%s has no accessible documents.", user.id, user_role)
            trace_step("vector_retrieval", "complete", user_id=user.id, retrieved_chunks=0,
                       duration_ms=round((time.perf_counter() - started) * 1000, 1))
            return []
    else:
        logger.info("Retrieval filters user_id=%d role=%s filters=none (RBAC disabled)", user.id, user_role)
        trace_step("vector_prefilter", "skipped", user_id=user.id, user_role=user_role,
                   reason="rbac_filter_disabled")

    try:
        collection = collection_override if collection_override is not None else _get_collection()
    except Exception as exc:
        logger.error("Could not initialize the vector store: %s", exc)
        trace_step("vector_store", "error", error_type=type(exc).__name__)
        trace_step("vector_retrieval", "complete", user_id=user.id, retrieved_chunks=0,
                   duration_ms=round((time.perf_counter() - started) * 1000, 1))
        return []

    # ── Step 2: ChromaDB query (over-fetch; post-filter) ─────────────────
    try:
        n_fetch = min(k * 6, 100)
        trace_step("vector_query", "start", fetch_limit=n_fetch)
        query_options = {
            "query_texts": [query],
            "n_results": n_fetch,
            "include": ["documents", "metadatas", "distances"],
        }
        if rbac_filter:
            query_options["where"] = {"doc_id": {"$in": sorted(accessible_set)}}
        results = collection.query(**query_options)
    except Exception as exc:
        logger.error("ChromaDB query failed: %s", exc)
        trace_step("vector_query", "error", error_type=type(exc).__name__)
        trace_step("vector_retrieval", "complete", user_id=user.id, retrieved_chunks=0,
                   duration_ms=round((time.perf_counter() - started) * 1000, 1))
        return []

    # ── Step 3: Post-filter + re-verify via SQL ───────────────────────────
    ids = results.get("ids", [[]])[0]
    docs_text = results.get("documents", [[]])[0]
    metas = results.get("metadatas", [[]])[0]
    distances = results.get("distances", [[]])[0]
    trace_step("vector_query", "complete", candidates=len(ids))

    verified: List[RetrievedChunk] = []
    permission_denials = 0
    held_count = 0
    for chroma_id, text, meta, dist in zip(ids, docs_text, metas, distances):
        doc_id = int(meta.get("doc_id", -1))

        if rbac_filter:
            # Python-level RBAC filter
            if doc_id not in accessible_set:
                permission_denials += 1
                continue

            # SQL permission re-check
            sql_doc = db.query(Document).filter(Document.id == doc_id).first()
            if not sql_doc or not can_read(user, sql_doc, now=now, db=db):
                logger.info(
                    "Retrieval excluded chroma_id=%s document_id=%d status=%s reason=access_denied",
                    chroma_id,
                    doc_id,
                    "missing_document" if not sql_doc else ("quarantined" if sql_doc.is_quarantined else "active"),
                )
                logger.warning(
                    "SQL re-check denied chunk %s (doc %d) for user id=%d",
                    chroma_id, doc_id, user.id,
                )
                permission_denials += 1
                continue

        # Check if chunk is quarantined or pending_judge in SQL
        sql_chunk = (
            db.query(Chunk)
            .filter(Chunk.chroma_id == chroma_id)
            .first()
        )
        sql_doc = db.query(Document).filter(Document.id == doc_id).first()
        is_held = bool(
            sql_chunk
            and (
                sql_chunk.is_quarantined
                or sql_chunk.status == "pending_judge"
                or sql_chunk.flagged_for_review
            )
        )
        if rbac_filter and sql_doc and not can_read(user, sql_doc, now=now, db=db, chunk=sql_chunk):
            excluded_status = (
                "quarantined" if sql_chunk and sql_chunk.is_quarantined
                else "pending_review" if sql_chunk and sql_chunk.flagged_for_review
                else sql_chunk.status if sql_chunk and sql_chunk.status
                else "unknown"
            )
            logger.info(
                "Retrieval excluded chroma_id=%s document_id=%d status=%s reason=held_or_unapproved",
                chroma_id,
                doc_id,
                excluded_status,
            )
            permission_denials += 1
            continue
        if is_held:
            held_count += 1
            logger.info("Excluding quarantined/pending_judge chunk %s at retrieval", chroma_id)
            verified.append(
                RetrievedChunk(
                    chroma_id=chroma_id,
                    text=text,
                    doc_id=doc_id,
                    chunk_index=int(meta.get("chunk_index", 0)),
                    distance=float(dist),
                    sql_chunk_id=sql_chunk.id,
                    is_quarantined=True,
                )
            )
            continue

        verified.append(
            RetrievedChunk(
                chroma_id=chroma_id,
                text=text,
                doc_id=doc_id,
                chunk_index=int(meta.get("chunk_index", 0)),
                distance=float(dist),
                sql_chunk_id=sql_chunk.id if sql_chunk else None,
                is_quarantined=False,
            )
        )

        if len(verified) >= k:
            break

    trace_step("vector_postfilter", "complete", allowed_chunks=len(verified),
               denied_candidates=permission_denials, held_candidates=held_count)
    trace_step("vector_retrieval", "complete", user_id=user.id, retrieved_chunks=len(verified),
               duration_ms=round((time.perf_counter() - started) * 1000, 1))
    return verified


_TITLE_STOP_WORDS = {"a", "about", "an", "and", "asking", "document", "for", "of", "the"}


def explain_empty_retrieval(query: str, user: User, db: Session) -> str:
    """Explain why a title-matched document did not provide answer context."""
    query_terms = {
        term for term in re.findall(r"[a-z0-9]+", query.lower())
        if term not in _TITLE_STOP_WORDS
    }
    matching_documents: list[tuple[int, Document]] = []
    for document in db.query(Document).all():
        title_terms = {
            term for term in re.findall(r"[a-z0-9]+", Path(document.filename).stem.lower())
            if term not in _TITLE_STOP_WORDS
        }
        overlap = len(query_terms & title_terms)
        minimum_overlap = min(2, len(title_terms))
        if title_terms and overlap >= minimum_overlap:
            matching_documents.append((overlap, document))

    if not matching_documents:
        return "I couldn't find a document matching that request in the indexed library."

    matching_documents.sort(key=lambda item: item[0], reverse=True)
    for _, document in matching_documents:
        if not can_read(user, document, db=db):
            return (
                f"I found a matching document ({document.filename}), but your role "
                "doesn't have access to it."
            )

        chunks = db.query(Chunk).filter(Chunk.document_id == document.id).all()
        pending = any(
            chunk.status == "pending_judge"
            or (chunk.flagged_for_review and not chunk.is_quarantined)
            for chunk in chunks
        )
        if pending and settings.pending_document_notice_enabled:
            return (
                f"The matching document ({document.filename}) is pending security "
                "review and approval, so I can't use it yet."
            )
        if document.is_quarantined or (chunks and all(
            chunk.is_quarantined or chunk.status == "quarantined" for chunk in chunks
        )):
            return (
                f"The matching document ({document.filename}) is quarantined for "
                "security review and isn't available to chat."
            )

    return (
        "I found a matching accessible document, but couldn't retrieve relevant "
        "content from its indexed chunks."
    )
