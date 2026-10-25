"""Re-chunk, rescan, and rebuild the Chroma index without losing access state."""
from __future__ import annotations

import logging
import statistics
import uuid
from collections import defaultdict
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import func

from app.config import settings
from app.db import Chunk, Department, Document, Permission, Role, ScanLog, SessionLocal
from app.embeddings import encode_texts, get_embedding_model
from app.ingest import _log_scan, chunk_text
from app.vector_store import get_chroma_client

logger = logging.getLogger("reindex")


def _run_local_document_scan(text: str):
    from unittest.mock import patch

    from app import ensemble

    ensemble._promptguard._client = None
    with patch("app.detectors.promptguard._get_groq_client", return_value=None):
        result = ensemble.run_ensemble(text, source="document")
    if (
        result.promptguard.failed
        and not result.deberta.failed
        and result.deberta.label == "INJECTION"
    ):
        result.final_label = "UNKNOWN"
        result.final_reason = "local_detector_flagged_pending_judge"
    return result


def _normalized(text: str) -> str:
    return " ".join(text.split())


def _retryable_fail_closed(chunk: Chunk) -> bool:
    return (
        chunk.status == "quarantined"
        and chunk.quarantine_reason
        in {"both_detectors_failed_fail_closed", "gemini_failed_fail_closed"}
    )


def _latest_local_only_scan(db, chunk: Chunk) -> ScanLog | None:
    latest_scan = (
        db.query(ScanLog)
        .filter(
            ScanLog.chunk_id == chunk.id,
            ScanLog.source == "document",
            ScanLog.source_type == "live",
        )
        .order_by(ScanLog.id.desc())
        .first()
    )
    if (
        latest_scan
        and latest_scan.final_reason in {"both_agree_injection", "both_agree_benign"}
        and latest_scan.promptguard_label == "UNKNOWN"
        and not latest_scan.gemini_used
    ):
        return latest_scan
    return None


def _retryable_local_quarantine(db, chunk: Chunk) -> bool:
    if chunk.status != "quarantined":
        return False
    return _latest_local_only_scan(db, chunk) is not None


def _retryable_quarantine(db, chunk: Chunk) -> bool:
    return _retryable_fail_closed(chunk) or _retryable_local_quarantine(db, chunk)


def _merge_chunks(texts: list[str], tokenizer, overlap_tokens: int) -> str:
    merged: list[int] = []
    for text in texts:
        backend_tokenizer = getattr(tokenizer, "backend_tokenizer", None)
        tokens = (
            backend_tokenizer.encode(text, add_special_tokens=False).ids
            if backend_tokenizer is not None
            else tokenizer.encode(text, add_special_tokens=False)
        )
        overlap = min(overlap_tokens, len(merged), len(tokens))
        while overlap and merged[-overlap:] != tokens[:overlap]:
            overlap -= 1
        merged.extend(tokens[overlap:])
    return tokenizer.decode(merged, skip_special_tokens=True).strip()


def _collection_records(collection) -> dict[str, tuple[str, dict]]:
    records = collection.get(include=["documents", "metadatas"])
    documents = records.get("documents") or []
    metadatas = records.get("metadatas") or []
    return {
        chroma_id: (text or "", metadata or {})
        for chroma_id, text, metadata in zip(records["ids"], documents, metadatas)
    }


def reindex() -> dict[str, object]:
    db = SessionLocal()
    client = get_chroma_client()
    stage_name = f"rag_reindex_{uuid.uuid4().hex[:12]}"
    backup_name = f"rag_backup_{uuid.uuid4().hex[:12]}"
    active_collection = None
    staged_collection = None
    renamed_active = False

    try:
        active_collection = client.get_collection(
            name=settings.chroma_collection,
            embedding_function=None,
        )
        old_records = _collection_records(active_collection)
        documents = db.query(Document).order_by(Document.id).all()
        chunks_by_document: dict[int, list[Chunk]] = defaultdict(list)
        for chunk in (
            db.query(Chunk)
            .filter(Chunk.status != "superseded")
            .order_by(Chunk.document_id, Chunk.chunk_index)
            .all()
        ):
            chunks_by_document[chunk.document_id].append(chunk)

        permission_rows = (
            db.query(Permission.document_id, Role.name)
            .join(Role, Permission.role_id == Role.id)
            .all()
        )
        roles_by_document: dict[int, set[str]] = defaultdict(set)
        for document_id, name in permission_rows:
            roles_by_document[document_id].add(name)

        old_text_by_chunk: dict[int, str] = {}
        for chunks in chunks_by_document.values():
            for chunk in chunks:
                vector_record = old_records.get(chunk.chroma_id)
                old_text_by_chunk[chunk.id] = (
                    chunk.text_content
                    or (vector_record[0] if vector_record else "")
                )

        model = get_embedding_model()
        max_seq_length = int(model.max_seq_length)
        prepared: list[dict[str, object]] = []
        reused_scans = 0
        new_scans = 0

        status_counts = {
            (status or "active", bool(quarantined)): count
            for status, quarantined, count in db.query(
                Chunk.status, Chunk.is_quarantined, func.count(Chunk.id)
            ).group_by(Chunk.status, Chunk.is_quarantined)
        }
        department_counts = {
            (department or "unassigned", confidentiality, bool(quarantined)): count
            for department, confidentiality, quarantined, count in db.query(
                Department.name,
                Document.confidentiality,
                Document.is_quarantined,
                func.count(Document.id),
            ).outerjoin(
                Department, Document.department_id == Department.id
            ).group_by(
                Department.name, Document.confidentiality, Document.is_quarantined
            )
        }
        logger.info("Existing chunk status groups: %s", dict(status_counts))
        logger.info("Existing document department/status groups: %s", dict(department_counts))

        for document in documents:
            old_chunks = chunks_by_document.get(document.id, [])
            recoverable_document_hold = (
                document.is_quarantined
                and bool(old_chunks)
                and (
                    (
                        not document.quarantine_reason
                        and all(_retryable_fail_closed(chunk) for chunk in old_chunks)
                    )
                    or (
                        document.quarantine_reason
                        == "Reindex detector quarantined one or more chunks."
                        and all(
                            not chunk.is_quarantined
                            or _retryable_local_quarantine(db, chunk)
                            for chunk in old_chunks
                        )
                    )
                )
            )
            if recoverable_document_hold:
                document.is_quarantined = False
            prior_texts = [
                (chunk, old_text_by_chunk[chunk.id])
                for chunk in old_chunks
                if old_text_by_chunk[chunk.id]
            ]
            source_chunks = [
                (chunk, text) for chunk, text in prior_texts if text.strip()
            ]
            full_text = _merge_chunks(
                [text for _, text in source_chunks],
                model.tokenizer,
                settings.chunk_overlap_tokens,
            )
            if not full_text:
                if old_chunks:
                    raise RuntimeError(
                        f"Document {document.id} ({document.filename}) has no recoverable chunk text."
                    )
                logger.warning(
                    "Document id=%d filename=%s has no indexed chunks; skipping",
                    document.id,
                    document.filename,
                )
                continue

            new_texts = chunk_text(full_text)
            old_by_text: dict[str, list[Chunk]] = defaultdict(list)
            for old_chunk, old_text in prior_texts:
                old_by_text[_normalized(old_text)].append(old_chunk)
            held_sources = [
                (chunk, _normalized(old_text))
                for chunk, old_text in prior_texts
                if chunk.is_quarantined
                or chunk.status == "quarantined"
                or chunk.status == "pending_judge"
                or chunk.flagged_for_review
                if not _retryable_quarantine(db, chunk)
            ]

            for index, text in enumerate(new_texts):
                normalized = _normalized(text)
                exact_matches = old_by_text.get(normalized, [])
                old_chunk = exact_matches.pop(0) if exact_matches else None
                held_match = next(
                    (
                        (source_chunk, source_status)
                        for source_chunk, source_status in held_sources
                        if normalized and normalized in source_status
                    ),
                    None,
                )

                if document.is_quarantined or (held_match and held_match[0].is_quarantined):
                    status = "quarantined"
                    is_quarantined = True
                    flagged_for_review = False
                    quarantine_reason = (
                        document.quarantine_reason
                        or (held_match[0].quarantine_reason if held_match else None)
                    )
                    scan_result = None
                elif held_match and (
                    held_match[0].status == "pending_judge"
                    or held_match[0].flagged_for_review
                ):
                    status = "pending_judge"
                    is_quarantined = False
                    flagged_for_review = True
                    quarantine_reason = None
                    scan_result = None
                elif old_chunk is not None and (
                    old_chunk.status == "pending_judge" or old_chunk.flagged_for_review
                ):
                    status = "pending_judge"
                    is_quarantined = False
                    flagged_for_review = True
                    quarantine_reason = None
                    scan_result = None
                elif old_chunk is not None and (
                    old_chunk.is_quarantined or old_chunk.status == "quarantined"
                ) and not _retryable_quarantine(db, old_chunk):
                    status = "quarantined"
                    is_quarantined = True
                    flagged_for_review = False
                    quarantine_reason = old_chunk.quarantine_reason
                    scan_result = None
                elif old_chunk is not None and _retryable_local_quarantine(db, old_chunk):
                    cached_scan = _latest_local_only_scan(db, old_chunk)
                    if cached_scan and cached_scan.final_label == "BENIGN":
                        scan_result = None
                        reused_scans += 1
                    else:
                        scan_result = _run_local_document_scan(text)
                        new_scans += 1
                else:
                    scan_result = None
                    if old_chunk is not None and not _retryable_quarantine(db, old_chunk) and db.query(ScanLog).filter(
                        ScanLog.chunk_id == old_chunk.id,
                        ScanLog.source == "document",
                        ScanLog.source_type == "live",
                    ).first():
                        reused_scans += 1
                    else:
                        scan_result = _run_local_document_scan(text)
                        new_scans += 1
                    pending_judge = bool(
                        scan_result
                        and scan_result.final_reason == "local_detector_flagged_pending_judge"
                    )
                    is_quarantined = bool(
                        scan_result
                        and scan_result.is_injection
                        and not pending_judge
                    )
                    status = (
                        "pending_judge"
                        if pending_judge
                        else "quarantined" if is_quarantined else "active"
                    )
                    flagged_for_review = pending_judge
                    quarantine_reason = (
                        scan_result.final_reason if is_quarantined and scan_result else None
                    )

                chunk = old_chunk
                if chunk is None:
                    chunk = Chunk(
                        document_id=document.id,
                        chunk_index=index,
                        chroma_id=f"doc{document.id}_reindex_{uuid.uuid4().hex[:12]}",
                    )
                    db.add(chunk)
                chunk.chunk_index = index
                chunk.text_content = text
                chunk.text_preview = text[:500]
                chunk.status = status
                chunk.is_quarantined = is_quarantined
                chunk.quarantine_reason = quarantine_reason
                chunk.flagged_for_review = flagged_for_review
                chunk.flag_reason = (
                    (
                        "Local detector flagged this chunk; hosted detectors were "
                        "not called during offline reindex."
                    )
                    if flagged_for_review
                    else None
                )
                prepared.append(
                    {
                        "chunk": chunk,
                        "text": text,
                        "metadata": {
                            "doc_id": document.id,
                            "chunk_index": index,
                            "allowed_roles": ",".join(sorted(roles_by_document[document.id])),
                            "filename": document.filename,
                            "department_id": document.department_id or 0,
                            "confidentiality": document.confidentiality,
                            "status": status,
                            "is_quarantined": is_quarantined,
                        },
                        "scan_result": scan_result,
                    }
                )

            if recoverable_document_hold:
                rebuilt_chunks = [
                    entry["chunk"]
                    for entry in prepared
                    if entry["chunk"].document_id == document.id
                ]
                newly_quarantined = [
                    chunk for chunk in rebuilt_chunks if chunk.is_quarantined
                ]
                document.is_quarantined = bool(newly_quarantined)
                document.quarantine_reason = (
                    "Reindex detector quarantined one or more chunks."
                    if newly_quarantined
                    else None
                )

            used_ids = {
                id(entry["chunk"])
                for entry in prepared
                if entry["chunk"].document_id == document.id
            }
            for old_chunk in old_chunks:
                if id(old_chunk) not in used_ids:
                    old_chunk.status = "superseded"
                    old_chunk.is_quarantined = False
                    old_chunk.flagged_for_review = False

        db.flush()
        stage_collection = client.create_collection(
            name=stage_name,
            metadata={"hnsw:space": "cosine"},
            embedding_function=None,
        )
        staged_collection = stage_collection
        texts = [str(entry["text"]) for entry in prepared]
        ids = [entry["chunk"].chroma_id for entry in prepared]
        metadatas = [entry["metadata"] for entry in prepared]
        if texts:
            embeddings = encode_texts(texts)
            stage_collection.upsert(
                ids=ids,
                documents=texts,
                metadatas=metadatas,
                embeddings=embeddings,
            )

        for entry in prepared:
            if entry["scan_result"] is not None:
                _log_scan(
                    db,
                    str(entry["text"]),
                    entry["scan_result"],
                    source="document",
                    chunk_id=entry["chunk"].id,
                )

        final_chunk_statuses = {
            (status or "active", bool(quarantined)): count
            for status, quarantined, count in db.query(
                Chunk.status, Chunk.is_quarantined, func.count(Chunk.id)
            ).group_by(Chunk.status, Chunk.is_quarantined)
        }
        final_document_groups = {
            (department or "unassigned", confidentiality, bool(quarantined)): count
            for department, confidentiality, quarantined, count in db.query(
                Department.name,
                Document.confidentiality,
                Document.is_quarantined,
                func.count(Document.id),
            ).outerjoin(
                Department, Document.department_id == Department.id
            ).group_by(
                Department.name, Document.confidentiality, Document.is_quarantined
            )
        }
        logger.info("Final chunk status groups: %s", final_chunk_statuses)
        logger.info("Final document department/status groups: %s", final_document_groups)

        lengths = [
            len(model.tokenizer.encode(str(entry["text"]), add_special_tokens=True))
            for entry in prepared
        ]
        if lengths and max(lengths) > max_seq_length:
            raise RuntimeError(
                f"Reindex produced a {max(lengths)}-token chunk, over model limit {max_seq_length}."
            )
        logger.info(
            "Chunk distribution tokens: count=%d min=%d median=%.1f max=%d max_seq_length=%d",
            len(lengths),
            min(lengths) if lengths else 0,
            statistics.median(lengths) if lengths else 0,
            max(lengths) if lengths else 0,
            max_seq_length,
        )

        if stage_collection.count() != len(prepared):
            raise RuntimeError(
                f"Staged vector count {stage_collection.count()} does not match "
                f"prepared chunk count {len(prepared)}."
            )

        active_collection.modify(name=backup_name)
        renamed_active = True
        stage_collection.modify(name=settings.chroma_collection)
        db.commit()
        try:
            client.delete_collection(name=backup_name)
        except Exception:
            logger.warning("Reindex succeeded; old collection backup remains as %s", backup_name)
        logger.info(
            "Reindex complete: documents=%d chunks=%d reused_scans=%d new_scans=%d",
            len(documents),
            len(prepared),
            reused_scans,
            new_scans,
        )
        return {
            "documents": len(documents),
            "chunks": len(prepared),
            "max_seq_length": max_seq_length,
            "chunk_token_min": min(lengths) if lengths else 0,
            "chunk_token_median": statistics.median(lengths) if lengths else 0,
            "chunk_token_max": max(lengths) if lengths else 0,
            "reused_scans": reused_scans,
            "new_scans": new_scans,
        }
    except Exception:
        db.rollback()
        if renamed_active:
            try:
                collections = client.list_collections()
                names = {
                    collection.name if hasattr(collection, "name") else str(collection)
                    for collection in collections
                }
                if settings.chroma_collection in names:
                    client.get_collection(
                        name=settings.chroma_collection,
                        embedding_function=None,
                    ).modify(name=stage_name)
                if backup_name in names:
                    client.get_collection(
                        name=backup_name,
                        embedding_function=None,
                    ).modify(name=settings.chroma_collection)
                if stage_name in {
                    collection.name if hasattr(collection, "name") else str(collection)
                    for collection in client.list_collections()
                }:
                    client.delete_collection(name=stage_name)
            except Exception:
                logger.exception("Reindex rollback could not restore the original collection.")
        elif staged_collection is not None:
            client.delete_collection(name=stage_name)
        raise
    finally:
        db.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
    print(reindex())
