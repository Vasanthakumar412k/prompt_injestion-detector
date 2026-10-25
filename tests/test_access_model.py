"""Coverage for the data-driven document access policy and temporary grants."""
from __future__ import annotations

import datetime as dt
import json
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from unittest.mock import MagicMock, patch

from app.access_config import ROLE_POLICY
from app.db import Base, AccessAuditLog, AccessGrant, Chunk, Department, Document, Role, User
from app.ingest import sync_department_role_metadata
from app.pipeline import DefenseConfig, retry_judge_for_chunk, run_chat_pipeline
from app.rbac import (
    authorize_delegation, can_read, create_access_grant,
    get_accessible_document_ids, revoke_access_grant,
)
from app.retrieval import retrieve_chunks


class FakeCollection:
    def __init__(self, rows, distances=None):
        self.rows = rows
        self.distances = distances
        self.last_query = None

    def query(self, **kwargs):
        self.last_query = kwargs
        rows = self.rows
        where = kwargs.get("where", {}).get("doc_id", {}).get("$in")
        if where is not None:
            rows = [r for r in rows if r["metadata"]["doc_id"] in where]
        rows = rows[:kwargs["n_results"]]
        return {"ids": [[r["id"] for r in rows]], "documents": [[r["text"] for r in rows]],
                "metadatas": [[r["metadata"] for r in rows]],
                "distances": [[self.distances.get(r["id"], 0.1) if self.distances else 0.1
                               for r in rows]]}


@pytest.fixture
def access_db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(bind=engine)()
    departments = {name: Department(name=name) for name in ("HR", "Engineering")}
    session.add_all(departments.values())
    session.flush()
    roles = {name: Role(name=name, capabilities_json=json.dumps(caps)) for name, caps in ROLE_POLICY.items()}
    session.add_all(roles.values())
    session.flush()
    specs = [
        ("super_admin", "HR"), ("department_admin", "Engineering"),
        ("hr_manager", "HR"), ("security_admin", "Engineering"),
        ("auditor", "HR"), ("employee", "Engineering"),
    ]
    users = {}
    for role_name, dept in specs:
        user = User(username=f"{role_name}_user", hashed_password="x", role_id=roles[role_name].id,
                    department_id=departments[dept].id, team="team")
        session.add(user)
        users[role_name] = user
    session.flush()
    docs = {}
    for name, dept, level, quarantined in [
        ("public", "HR", "public", False), ("internal", "Engineering", "internal", False),
        ("department", "Engineering", "department", False), ("salary", "HR", "confidential", False),
        ("engineering_secret", "Engineering", "confidential", False), ("poisoned", "Engineering", "internal", True),
    ]:
        doc = Document(filename=f"{name}.txt", uploader_id=users["super_admin"].id,
                       owner_id=users["super_admin"].id, department_id=departments[dept].id,
                       confidentiality=level, is_quarantined=quarantined)
        session.add(doc)
        docs[name] = doc
    session.flush()
    rows = []
    for name, doc in docs.items():
        content = f"DOC_{name.upper()}_SECRET"
        chunk = Chunk(document_id=doc.id, chunk_index=0, chroma_id=f"chunk_{name}",
                      text_content=content, text_preview=content, is_quarantined=doc.is_quarantined,
                      status="quarantined" if doc.is_quarantined else "active")
        session.add(chunk)
        rows.append({"id": chunk.chroma_id, "text": content,
                     "metadata": {"doc_id": doc.id, "chunk_index": 0}})
    session.commit()
    yield session, users, docs, rows
    session.close()
    engine.dispose()


def test_role_document_matrix_filters_lists_retrieval_and_chat(access_db):
    db, users, docs, rows = access_db
    collection = FakeCollection(rows)
    expected = {
        "super_admin": {"public", "internal", "salary", "engineering_secret"},
        "department_admin": {"public", "internal", "department", "engineering_secret"},
        "hr_manager": {"public", "internal", "department", "salary"},
        "security_admin": {"public", "internal", "department"},
        "auditor": {"public", "internal"},
        "employee": {"public", "internal", "department"},
    }
    for role, user in users.items():
        permitted = expected[role]
        assert {name for name, doc in docs.items() if can_read(user, doc, db=db)} == permitted
        assert set(get_accessible_document_ids(user, db)) == {docs[name].id for name in permitted}
        with patch("app.retrieval._get_collection", return_value=collection):
            hits = retrieve_chunks("find relevant records", user, db)
        assert {hit.doc_id for hit in hits} == {docs[name].id for name in permitted}
        assert all(hit.text != "DOC_POISONED_SECRET" for hit in hits)
        assert collection.last_query["where"]["doc_id"]["$in"] == sorted(get_accessible_document_ids(user, db))
        with patch("app.retrieval._get_collection", return_value=collection), \
             patch("app.pipeline.generate_answer", side_effect=lambda system_prompt, **_: system_prompt):
            chat = run_chat_pipeline("summarize allowed records", "test", user, db,
                                     defense_config=DefenseConfig.rbac_only())
        for name, doc in docs.items():
            assert (f"DOC_{name.upper()}_SECRET" in chat.answer) == (name in permitted)


def test_temporary_grant_expiry_revocation_and_delegation_audit(access_db):
    db, users, docs, _ = access_db
    hr = users["hr_manager"]
    employee = users["employee"]
    now = dt.datetime(2030, 1, 1, 12)
    grant = create_access_grant(hr, employee, docs["salary"], "Quarterly payroll review", 2, db, now=now)
    assert can_read(employee, docs["salary"], now=now + dt.timedelta(hours=1), db=db)
    assert not can_read(employee, docs["salary"], now=grant.expires_at, db=db)
    revoke_access_grant(hr, grant, "Review completed", db, now=grant.expires_at - dt.timedelta(minutes=1))
    assert not can_read(employee, docs["salary"], now=now + dt.timedelta(minutes=30), db=db)
    assert db.query(AccessAuditLog).filter(AccessAuditLog.result == "allowed").count() >= 2

    attempts = [
        (users["department_admin"], employee, docs["salary"], "cross department", "grant_access"),
        (hr, employee, docs["engineering_secret"], "non HR document", "grant_access"),
        (hr, hr, docs["salary"], "self grant", "grant_access"),
        (employee, employee, docs["salary"], "no grant capability", "grant_access"),
    ]
    for actor, target, doc, reason, action in attempts:
        with pytest.raises(HTTPException):
            create_access_grant(actor, target, doc, reason, 1, db, now=now)
    assert db.query(AccessAuditLog).filter(AccessAuditLog.result == "denied").count() >= 4


def test_expired_grant_does_not_restore_document_access_in_existing_chat(access_db):
    db, users, docs, rows = access_db
    employee = users["employee"]
    now = dt.datetime(2030, 1, 1, 12)
    db.add(
        AccessGrant(
            grantee_id=employee.id,
            document_id=docs["salary"].id,
            granted_by=users["hr_manager"].id,
            reason="Temporary payroll review",
            starts_at=now - dt.timedelta(days=2),
            expires_at=now - dt.timedelta(days=1),
        )
    )
    db.commit()

    class MockDateTime:
        @staticmethod
        def utcnow():
            return now

    collection = FakeCollection(rows)
    history = [
        {"role": "user", "content": "Review the payroll document"},
        {"role": "assistant", "content": "I reviewed the document during the grant"},
    ]
    with patch("app.rbac.datetime", SimpleNamespace(datetime=MockDateTime)), \
         patch("app.retrieval._get_collection", return_value=collection):
        result = run_chat_pipeline(
            "Can you follow up on that document?",
            "test",
            employee,
            db,
            defense_config=DefenseConfig.rbac_only(),
            conversation_history=history,
        )

    accessible_ids = collection.last_query["where"]["doc_id"]["$in"]
    assert docs["salary"].id not in accessible_ids
    assert "DOC_SALARY_SECRET" not in result.answer


def test_hr_manager_can_retrieve_engineering_department_guide(access_db):
    db, users, docs, rows = access_db
    guide = docs["department"]
    guide.filename = "engineering_department_guide.txt"
    rows[:] = [row for row in rows if row["metadata"]["doc_id"] == guide.id]
    collection = FakeCollection(rows)
    with patch("app.retrieval._get_collection", return_value=collection), \
         patch("app.pipeline.generate_answer", side_effect=lambda system_prompt, **_: system_prompt):
        result = run_chat_pipeline(
            "What does the engineering department guide say?",
            "test",
            users["hr_manager"],
            db,
            defense_config=DefenseConfig.rbac_only(),
        )
    assert "DOC_DEPARTMENT_SECRET" in result.answer
    assert guide.id in collection.last_query["where"]["doc_id"]["$in"]


def test_department_vector_metadata_includes_hr_manager(access_db):
    db, _, docs, _ = access_db
    chunk = db.query(Chunk).filter(Chunk.document_id == docs["department"].id).one()
    db.add(
        Chunk(
            document_id=docs["department"].id,
            chunk_index=99,
            chroma_id="superseded_department_chunk",
            status="superseded",
        )
    )
    db.flush()
    collection = MagicMock()
    collection.get.return_value = {
        "ids": [chunk.chroma_id],
        "metadatas": [{"allowed_roles": "department_admin,employee"}],
    }
    client = MagicMock()
    client.get_collection.return_value = collection
    with patch("app.ingest._get_chroma", return_value=client):
        sync_department_role_metadata(db)
    collection.get.assert_called_once_with(
        ids=[chunk.chroma_id],
        include=["metadatas"],
    )
    collection.update.assert_called_once_with(
        ids=[chunk.chroma_id],
        metadatas=[{
            "allowed_roles": "department_admin,employee,hr_manager",
        }],
    )


def test_chat_explains_access_denial_for_matching_document(access_db):
    db, users, docs, rows = access_db
    salary = docs["salary"]
    salary.filename = "hr_salary_bands.txt"
    collection = FakeCollection([row for row in rows if row["metadata"]["doc_id"] == salary.id])
    with patch("app.retrieval._get_collection", return_value=collection), \
         patch("app.pipeline.generate_answer") as generate_answer:
        result = run_chat_pipeline(
            "What are the HR salary bands?",
            "test",
            users["employee"],
            db,
            defense_config=DefenseConfig.rbac_only(),
        )
    assert "doesn't have access" in result.answer
    assert salary.filename in result.answer
    generate_answer.assert_not_called()


def test_chat_explains_pending_approval_for_matching_document(access_db):
    db, users, docs, rows = access_db
    pending_doc = Document(
        filename="engineering_pending_guide.txt",
        uploader_id=users["super_admin"].id,
        owner_id=users["super_admin"].id,
        department_id=docs["department"].department_id,
        confidentiality="department",
    )
    db.add(pending_doc)
    db.flush()
    pending_chunk = Chunk(
        document_id=pending_doc.id,
        chunk_index=0,
        chroma_id="engineering_pending_guide_chunk",
        text_content="Pending engineering guide content",
        text_preview="Pending engineering guide content",
        status="pending_judge",
        flagged_for_review=True,
    )
    db.add(pending_chunk)
    db.commit()
    collection = FakeCollection([{
        "id": pending_chunk.chroma_id,
        "text": pending_chunk.text_content,
        "metadata": {"doc_id": pending_doc.id, "chunk_index": 0},
    }])
    with patch("app.retrieval._get_collection", return_value=collection), \
         patch("app.pipeline.generate_answer") as generate_answer:
        result = run_chat_pipeline(
            "What does the engineering pending guide say?",
            "test",
            users["employee"],
            db,
            defense_config=DefenseConfig.rbac_only(),
        )
    assert "pending security review and approval" in result.answer
    assert pending_doc.filename in result.answer
    assert pending_chunk.text_content not in result.answer
    generate_answer.assert_not_called()
    with patch(
        "app.detectors.gemini_judge.gemini_judge",
        return_value=SimpleNamespace(label="BENIGN"),
    ):
        promotion = retry_judge_for_chunk(db, pending_chunk)
    assert promotion["status"] == "cleared"
    assert pending_chunk.status == "active"


def test_expired_and_quarantined_chunks_are_never_retrieved(access_db):
    db, users, docs, rows = access_db
    grant = create_access_grant(users["hr_manager"], users["employee"], docs["salary"], "Coverage", 1, db)
    rows.append({"id": "held", "text": "DOC_POISONED_SECRET", "metadata": {"doc_id": docs["poisoned"].id, "chunk_index": 0}})
    collection = FakeCollection(rows)
    with patch("app.retrieval._get_collection", return_value=collection):
        result = retrieve_chunks("salary or poisoned", users["employee"], db)
    assert not any(hit.doc_id == docs["poisoned"].id for hit in result)
    grant.expires_at = dt.datetime.utcnow() - dt.timedelta(seconds=1)
    db.commit()
    with patch("app.retrieval._get_collection", return_value=collection):
        result = retrieve_chunks("salary", users["employee"], db)
    assert not any(hit.doc_id == docs["salary"].id for hit in result)


def test_retrieval_cutoff_keeps_strongest_and_drops_weak_matches(access_db, monkeypatch):
    db, users, docs, rows = access_db
    distances = {
        "chunk_public": 0.1,
        "chunk_internal": 0.45,
        "chunk_department": 0.55,
        "chunk_salary": 0.75,
    }
    collection = FakeCollection(rows, distances)
    monkeypatch.setattr("app.retrieval.settings.min_similarity", 0.3)
    monkeypatch.setattr("app.retrieval.settings.relative_cutoff", 0.8)

    with patch("app.retrieval._get_collection", return_value=collection):
        hits = retrieve_chunks("company policy details", users["hr_manager"], db)

    assert [hit.chroma_id for hit in hits] == ["chunk_public"]
    assert hits[0].similarity == pytest.approx(0.9)


def test_retrieval_below_threshold_returns_explicit_empty_status(access_db, monkeypatch):
    db, users, _, rows = access_db
    collection = FakeCollection(rows, {row["id"]: 0.8 for row in rows})
    stats = {}
    monkeypatch.setattr("app.retrieval.settings.min_similarity", 0.35)
    monkeypatch.setattr("app.retrieval.settings.relative_cutoff", 0.82)

    with patch("app.retrieval._get_collection", return_value=collection):
        hits = retrieve_chunks(
            "unrelated synthetic request", users["hr_manager"], db, stats=stats
        )

    assert hits == []
    assert stats["status"] == "no_relevant_chunks_above_threshold"
    assert stats["candidates_after_cutoff"] == 0


def test_empty_retrieval_uses_no_relevant_document_prompt(access_db, monkeypatch):
    db, users, docs, rows = access_db
    docs["public"].filename = "company_policy.txt"
    collection = FakeCollection(rows, {row["id"]: 0.8 for row in rows})
    monkeypatch.setattr("app.retrieval.settings.min_similarity", 0.35)
    monkeypatch.setattr("app.retrieval.settings.relative_cutoff", 0.82)
    with patch("app.retrieval._get_collection", return_value=collection), \
         patch("app.pipeline.generate_answer", side_effect=lambda system_prompt, **_: system_prompt):
        result = run_chat_pipeline(
            "What is the lunar company policy?",
            "test",
            users["hr_manager"],
            db,
            defense_config=DefenseConfig.rbac_only(),
        )

    assert "No relevant document passed the retrieval relevance threshold" in result.answer


def test_context_respects_maximum_character_budget(access_db, monkeypatch):
    db, users, _, rows = access_db
    collection = FakeCollection(rows)
    monkeypatch.setattr("app.pipeline.settings.max_context_chars", 8)
    with patch("app.retrieval._get_collection", return_value=collection), \
         patch("app.pipeline.generate_answer", side_effect=lambda system_prompt, **_: system_prompt):
        result = run_chat_pipeline(
            "Summarize the company policy.",
            "test",
            users["hr_manager"],
            db,
            defense_config=DefenseConfig.rbac_only(),
        )

    assert "DOC_PUBL" in result.answer
    assert "DOC_PUBLIC_SECRET" not in result.answer


def test_grant_matrix_retrieval_list_and_chat_at_expiry_and_revocation(access_db):
    db, users, docs, rows = access_db
    now = dt.datetime(2031, 5, 1, 9)
    super_admin = users["super_admin"]
    collection = FakeCollection(rows)
    base_allowed = {"hr_manager"}
    for role, user in users.items():
        if role == "super_admin":
            continue
        grant = create_access_grant(super_admin, user, docs["salary"], f"Matrix check for {role}", 1, db, now=now)
        before_expiry = now + dt.timedelta(minutes=30)
        after_expiry = grant.expires_at
        assert can_read(user, docs["salary"], now=before_expiry, db=db)
        assert docs["salary"].id in get_accessible_document_ids(user, db, now=before_expiry)
        with patch("app.retrieval._get_collection", return_value=collection):
            hits = retrieve_chunks("salary", user, db, now=before_expiry)
        assert docs["salary"].id in {hit.doc_id for hit in hits}
        assert not can_read(user, docs["salary"], now=after_expiry, db=db) if role not in base_allowed else can_read(user, docs["salary"], now=after_expiry, db=db)
        with patch("app.retrieval._get_collection", return_value=collection), \
             patch("app.pipeline.generate_answer", side_effect=lambda system_prompt, **_: system_prompt):
            chat = run_chat_pipeline("salary", "test", user, db, defense_config=DefenseConfig.rbac_only(), now=after_expiry)
        assert ("DOC_SALARY_SECRET" in chat.answer) == (role in base_allowed)
        revoke_access_grant(super_admin, grant, "Matrix revocation", db, now=before_expiry)
        assert can_read(user, docs["salary"], now=before_expiry, db=db) == (role in base_allowed)


def test_grant_matrix_retrieval_list_and_chat_after_expiry(access_db):
    db, users, docs, rows = access_db
    now = dt.datetime(2031, 5, 1, 9)
    super_admin = users["super_admin"]
    collection = FakeCollection(rows)
    for role, user in users.items():
        grant = create_access_grant(super_admin, user, docs["salary"], f"Matrix check for {role}", 1, db, now=now)
        assert can_read(user, docs["salary"], now=now + dt.timedelta(minutes=30), db=db)
        assert docs["salary"].id in get_accessible_document_ids(user, db, now=now + dt.timedelta(minutes=30))
        with patch("app.retrieval._get_collection", return_value=collection), \
             patch("app.rbac.datetime.datetime") as clock:
            clock.utcnow.return_value = now + dt.timedelta(minutes=30)
            hits = retrieve_chunks("salary", user, db)
        assert docs["salary"].id in {hit.doc_id for hit in hits}
        grant.expires_at = now + dt.timedelta(hours=1)
        db.commit()
        assert not can_read(user, docs["salary"], now=now + dt.timedelta(hours=1), db=db)
        with patch("app.retrieval._get_collection", return_value=collection), \
             patch("app.pipeline.generate_answer", side_effect=lambda system_prompt, **_: system_prompt), \
             patch("app.rbac.datetime.datetime") as clock:
            clock.utcnow.return_value = now + dt.timedelta(hours=1)
            clock.now.return_value = now + dt.timedelta(hours=1)
            clock.strptime = dt.datetime.strptime
            chat = run_chat_pipeline("salary", "test", user, db, defense_config=DefenseConfig.rbac_only())
        assert "DOC_SALARY_SECRET" not in chat.answer
