"""Calibrate retrieval on dev queries and evaluate the held-out test split."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import chromadb

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import settings
from app.db import Document, SessionLocal, User
from app.embeddings import encode_texts
from app.rbac import get_accessible_document_ids, role_name
from app.retrieval import retrieve_chunks

ROOT = Path(__file__).resolve().parent.parent
DATA_PATH = ROOT / "eval" / "retrieval_eval.json"
BASELINE_PATH = ROOT / "reports" / "retrieval_baseline.json"
RESULT_PATH = ROOT / "reports" / "retrieval_eval_results.json"
TOP_K = 5
THRESHOLDS = (0.15, 0.2, 0.25, 0.3, 0.35, 0.4, 0.45, 0.5)
RELATIVE_CUTOFFS = (0.65, 0.75, 0.82, 0.9, 0.95)


def _load_cases() -> list[dict[str, Any]]:
    return json.loads(DATA_PATH.read_text(encoding="utf-8"))


def _role_user(db, role: str) -> User:
    users = db.query(User).join(User.role).all()
    for user in users:
        if role_name(user.role) == role:
            return user
    raise RuntimeError(f"No user exists for evaluation role {role!r}.")


def _metrics(cases: list[dict[str, Any]], hits_by_case: list[list[int]]) -> dict[str, float | int]:
    expected_total = sum(len(case["expected_document_ids"]) for case in cases)
    expected_hits = sum(
        len(set(case["expected_document_ids"]) & set(hit_ids))
        for case, hit_ids in zip(cases, hits_by_case)
    )
    returned_total = sum(len(hit_ids) for hit_ids in hits_by_case)
    irrelevant_total = sum(
        sum(doc_id not in set(case["expected_document_ids"]) for doc_id in hit_ids)
        for case, hit_ids in zip(cases, hits_by_case)
    )
    negative_indices = [
        index for index, case in enumerate(cases)
        if not case["expected_document_ids"]
    ]
    negative_correct = sum(not hits_by_case[index] for index in negative_indices)
    return {
        "recall_expected_documents": expected_hits / expected_total if expected_total else 0.0,
        "irrelevant_returned_chunks_share": (
            irrelevant_total / returned_total if returned_total else 0.0
        ),
        "negative_queries_correctly_empty_share": (
            negative_correct / len(negative_indices) if negative_indices else 0.0
        ),
        "expected_documents": expected_total,
        "expected_documents_found": expected_hits,
        "returned_chunks": returned_total,
        "irrelevant_chunks": irrelevant_total,
        "negative_queries": len(negative_indices),
        "negative_queries_empty": negative_correct,
    }


def _validate_expected_access(db, cases: list[dict[str, Any]]) -> None:
    documents = {doc.id for doc in db.query(Document.id).all()}
    for case in cases:
        missing_ids = set(case["expected_document_ids"]) - documents
        if missing_ids:
            raise RuntimeError(
                f"Evaluation expected document IDs are missing: {sorted(missing_ids)}."
            )
        user = _role_user(db, case["role"])
        inaccessible = set(case["expected_document_ids"]) - set(
            get_accessible_document_ids(user, db)
        )
        if inaccessible:
            raise RuntimeError(
                f"Expected documents {sorted(inaccessible)} are inaccessible to "
                f"role {case['role']!r}; fix the evaluation labels or access policy."
            )


def _baseline(db, cases: list[dict[str, Any]]) -> list[list[int]]:
    collection = chromadb.PersistentClient(
        path=settings.chroma_persist_dir
    ).get_collection(
        name=settings.chroma_collection,
        embedding_function=None,
    )
    collection_count = collection.count()
    results: list[list[int]] = []
    for case in cases:
        user = _role_user(db, case["role"])
        accessible = sorted(get_accessible_document_ids(user, db))
        if not accessible or not collection_count:
            results.append([])
            continue
        query_result = collection.query(
            query_embeddings=encode_texts([case["query"]]),
            n_results=min(TOP_K, collection_count),
            where={"doc_id": {"$in": accessible}},
            include=["metadatas"],
        )
        results.append([
            int(metadata["doc_id"])
            for metadata in query_result.get("metadatas", [[]])[0]
        ])
    return results


def _cutoff(db, cases: list[dict[str, Any]]) -> list[list[int]]:
    results: list[list[int]] = []
    for case in cases:
        user = _role_user(db, case["role"])
        hits = retrieve_chunks(case["query"], user, db, top_k=TOP_K)
        results.append([hit.doc_id for hit in hits])
    return results


def run_baseline() -> None:
    db = SessionLocal()
    try:
        cases = _load_cases()
        _validate_expected_access(db, cases)
        baseline_results: dict[str, Any] = {}
        for split in ("dev", "test"):
            split_cases = [case for case in cases if case["split"] == split]
            returned = _baseline(db, split_cases)
            baseline_results[split] = {
                "metrics": _metrics(split_cases, returned),
                "document_ids_by_query": returned,
            }
        BASELINE_PATH.parent.mkdir(parents=True, exist_ok=True)
        BASELINE_PATH.write_text(
            json.dumps(baseline_results, indent=2), encoding="utf-8"
        )
        print(json.dumps(baseline_results, indent=2))
    finally:
        db.close()


def run_calibrated_evaluation() -> None:
    db = SessionLocal()
    try:
        cases = _load_cases()
        _validate_expected_access(db, cases)
        dev_cases = [case for case in cases if case["split"] == "dev"]
        test_cases = [case for case in cases if case["split"] == "test"]

        best: tuple[float, float, float, dict[str, float | int]] | None = None
        for min_similarity in THRESHOLDS:
            for relative_cutoff in RELATIVE_CUTOFFS:
                settings.min_similarity = min_similarity
                settings.relative_cutoff = relative_cutoff
                metrics = _metrics(dev_cases, _cutoff(db, dev_cases))
                recall = float(metrics["recall_expected_documents"])
                irrelevant = float(metrics["irrelevant_returned_chunks_share"])
                negatives = float(metrics["negative_queries_correctly_empty_share"])
                score = 0.5 * recall + 0.25 * (1.0 - irrelevant) + 0.25 * negatives
                candidate = (score, min_similarity, relative_cutoff, metrics)
                if best is None or candidate[:3] > best[:3]:
                    best = candidate

        assert best is not None
        _, chosen_min, chosen_relative, dev_metrics = best
        settings.min_similarity = chosen_min
        settings.relative_cutoff = chosen_relative
        test_metrics = _metrics(test_cases, _cutoff(db, test_cases))

        baseline = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
        output = {
            "thresholds_chosen_on_dev": {
                "min_similarity": chosen_min,
                "relative_cutoff": chosen_relative,
            },
            "dev_metrics": dev_metrics,
            "test_metrics": test_metrics,
            "old_top5_no_cutoff_test_metrics": baseline["test"]["metrics"],
        }
        RESULT_PATH.parent.mkdir(parents=True, exist_ok=True)
        RESULT_PATH.write_text(json.dumps(output, indent=2), encoding="utf-8")
        print(json.dumps(output, indent=2))
    finally:
        db.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--baseline-only", action="store_true")
    mode.add_argument("--calibrate-and-test", action="store_true")
    arguments = parser.parse_args()
    if arguments.baseline_only:
        run_baseline()
    else:
        run_calibrated_evaluation()
