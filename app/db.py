"""
db.py – SQLAlchemy models and database initialisation.
Tables: users, roles, documents, chunks, permissions, scan_logs, chat_logs,
        chunk_release_logs, output_leak_logs, lab_runs, lab_results.
"""
from __future__ import annotations

import datetime
from typing import Optional

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    create_engine,
)
from sqlalchemy.orm import DeclarativeBase, Session, relationship, sessionmaker

from app.config import settings

engine = create_engine(
    settings.database_url,
    connect_args={"check_same_thread": False},  # SQLite only
)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)


class Base(DeclarativeBase):
    pass


# ── Models ─────────────────────────────────────────────────────────────────


class Role(Base):
    """An access-control role (e.g. admin, HR, employee)."""

    __tablename__ = "roles"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(64), unique=True, nullable=False, index=True)
    description = Column(String(256), nullable=True)
    capabilities_json = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    users = relationship("User", back_populates="role")
    permissions = relationship("Permission", back_populates="role", cascade="all, delete-orphan")


class User(Base):
    """Platform user with a single role."""

    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    hashed_password = Column(String(256), nullable=False)
    role_id = Column(Integer, ForeignKey("roles.id"), nullable=False)
    department_id = Column(Integer, ForeignKey("departments.id"), nullable=True)
    team = Column(String(128), nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    role = relationship("Role", back_populates="users")
    department = relationship("Department")


class Department(Base):
    __tablename__ = "departments"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(128), unique=True, nullable=False)


class Document(Base):
    """An uploaded document (metadata only; content lives in chunks)."""

    __tablename__ = "documents"

    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String(256), nullable=False)
    content_type = Column(String(64), nullable=True)
    uploader_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    department_id = Column(Integer, ForeignKey("departments.id"), nullable=True)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    confidentiality = Column(String(32), nullable=False, default="internal")
    is_quarantined = Column(Boolean, default=False)
    quarantine_reason = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    chunks = relationship("Chunk", back_populates="document", cascade="all, delete-orphan")
    permissions = relationship("Permission", back_populates="document", cascade="all, delete-orphan")
    uploader = relationship("User", foreign_keys=[uploader_id])
    department = relationship("Department")


class Chunk(Base):
    """A text chunk derived from a document."""

    __tablename__ = "chunks"

    id = Column(Integer, primary_key=True, index=True)
    document_id = Column(Integer, ForeignKey("documents.id"), nullable=False)
    chunk_index = Column(Integer, nullable=False)
    chroma_id = Column(String(128), unique=True, nullable=False)
    text_content = Column(Text, nullable=True)
    text_preview = Column(String(512), nullable=True)  # first 500 chars
    is_quarantined = Column(Boolean, default=False)
    quarantine_reason = Column(Text, nullable=True)
    status = Column(String(32), default="active")  # "active" | "quarantined" | "pending_judge"
    # flagged_for_review: detectors disagree but Gemini unavailable – admin review needed
    flagged_for_review = Column(Boolean, default=False)
    flag_reason = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    document = relationship("Document", back_populates="chunks")


class Permission(Base):
    """Grants a role access to a document."""

    __tablename__ = "permissions"

    id = Column(Integer, primary_key=True, index=True)
    role_id = Column(Integer, ForeignKey("roles.id"), nullable=False)
    document_id = Column(Integer, ForeignKey("documents.id"), nullable=False)
    granted_at = Column(DateTime, default=datetime.datetime.utcnow)
    granted_by = Column(Integer, ForeignKey("users.id"), nullable=True)

    role = relationship("Role", back_populates="permissions")
    document = relationship("Document", back_populates="permissions")


class ScanLog(Base):
    """Audit log of every detector / ensemble decision."""

    __tablename__ = "scan_logs"

    id = Column(Integer, primary_key=True, index=True)
    source = Column(String(32), nullable=False)          # "prompt" | "document"
    text_preview = Column(String(512), nullable=True)    # first 500 chars
    deberta_label = Column(String(32), nullable=True)
    deberta_score = Column(Float, nullable=True)
    deberta_latency_ms = Column(Float, nullable=True)
    deberta_error = Column(Text, nullable=True)
    promptguard_label = Column(String(32), nullable=True)
    promptguard_score = Column(Float, nullable=True)
    promptguard_latency_ms = Column(Float, nullable=True)
    promptguard_error = Column(Text, nullable=True)
    gemini_used = Column(Boolean, default=False)
    gemini_label = Column(String(32), nullable=True)
    gemini_reason = Column(String(512), nullable=True)
    gemini_confidence = Column(Float, nullable=True)
    gemini_error = Column(Text, nullable=True)
    final_label = Column(String(32), nullable=False)
    final_reason = Column(String(256), nullable=True)
    chunk_id = Column(Integer, ForeignKey("chunks.id"), nullable=True)
    user_id = Column(Integer, nullable=True)
    source_type = Column(String(16), default="live")     # "live" | "lab"
    created_at = Column(DateTime, default=datetime.datetime.utcnow)


class ChatLog(Base):
    """Audit log of every chat request and response."""

    __tablename__ = "chat_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    question_preview = Column(String(512), nullable=True)
    model_used = Column(String(128), nullable=True)
    chunks_used = Column(Text, nullable=True)    # JSON list of chunk IDs
    chunks_dropped = Column(Text, nullable=True) # JSON list of {id, reason}
    answer_preview = Column(String(512), nullable=True)
    prompt_blocked = Column(Boolean, default=False)
    source_type = Column(String(16), default="live")     # "live" | "lab"
    created_at = Column(DateTime, default=datetime.datetime.utcnow)


class Conversation(Base):
    """A user's private, soft-deletable chat conversation."""

    __tablename__ = "conversations"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    title = Column(String(256), nullable=False, default="New chat")
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    deleted_at = Column(DateTime, nullable=True)

    user = relationship("User")
    messages = relationship(
        "Message",
        back_populates="conversation",
        cascade="all, delete-orphan",
        order_by="Message.id",
    )


class Message(Base):
    """Persisted user or assistant content; retrieved document text is never stored."""

    __tablename__ = "messages"

    id = Column(Integer, primary_key=True, index=True)
    conversation_id = Column(
        Integer, ForeignKey("conversations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    role = Column(String(16), nullable=False)
    content = Column(Text, nullable=False)
    model = Column(String(128), nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    security_trace = Column(Text, nullable=True)
    blocked = Column(Boolean, nullable=False, default=False)
    status = Column(String(16), nullable=False, default="complete")

    conversation = relationship("Conversation", back_populates="messages")


class ChunkReleaseLog(Base):
    """Audit log when an admin manually releases a quarantined chunk."""

    __tablename__ = "chunk_release_logs"

    id = Column(Integer, primary_key=True, index=True)
    chunk_id = Column(Integer, ForeignKey("chunks.id"), nullable=False)
    document_id = Column(Integer, nullable=False)
    released_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    original_reason = Column(Text, nullable=True)
    admin_note = Column(Text, nullable=True)
    released_at = Column(DateTime, default=datetime.datetime.utcnow)


class OutputLeakLog(Base):
    """Audit log of output-guard triggered events."""

    __tablename__ = "output_leak_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    trigger_type = Column(String(64), nullable=False)   # "ngram_overlap" | "canary" | "secret_redact"
    matched_value = Column(String(256), nullable=True)  # sanitized excerpt of match
    answer_preview = Column(String(512), nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)


class LabRun(Base):
    """A red-team lab run (batch of attacks)."""

    __tablename__ = "lab_runs"

    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(String(64), unique=True, nullable=False, index=True)  # UUID
    models = Column(Text, nullable=True)       # JSON list of model keys
    configs = Column(Text, nullable=True)      # JSON list of defense config names
    splits = Column(Text, nullable=True)       # JSON list e.g. ["dev", "test"]
    status = Column(String(32), default="pending")  # pending|running|done|error
    started_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    started_at = Column(DateTime, default=datetime.datetime.utcnow)
    finished_at = Column(DateTime, nullable=True)
    error = Column(Text, nullable=True)
    total_attacks = Column(Integer, default=0)
    completed_attacks = Column(Integer, default=0)


class LabResult(Base):
    """One row per (attack, model, config) outcome."""

    __tablename__ = "lab_results"

    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(String(64), ForeignKey("lab_runs.run_id"), nullable=False, index=True)
    attack_id = Column(String(64), nullable=False, index=True)
    split = Column(String(16), nullable=False)       # "dev" | "test"
    category = Column(String(64), nullable=True)
    delivery = Column(String(32), nullable=True)     # "user_prompt" | "document"
    model = Column(String(128), nullable=False)
    config = Column(String(32), nullable=False)      # "none"|"rbac_only"|"detectors_only"|"full"
    attack_success = Column(Boolean, nullable=True)  # None if benign
    is_benign = Column(Boolean, default=False)
    benign_answered = Column(Boolean, nullable=True)
    blocked = Column(Boolean, default=False)
    blocked_by = Column(String(64), nullable=True)   # which layer blocked
    deberta_label = Column(String(32), nullable=True)
    deberta_score = Column(Float, nullable=True)
    pg_label = Column(String(32), nullable=True)
    pg_score = Column(Float, nullable=True)
    gemini_used = Column(Boolean, default=False)
    gemini_label = Column(String(32), nullable=True)
    output_guard_triggered = Column(Boolean, default=False)
    latency_ms = Column(Float, nullable=True)
    answer_preview = Column(String(512), nullable=True)
    error = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)


class PermissionAuditLog(Base):
    """Audit log of permission grants and revocations."""

    __tablename__ = "permission_audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    role_name = Column(String(64), nullable=False)
    document_id = Column(Integer, nullable=False)
    action = Column(String(32), nullable=False)  # "grant" | "revoke"
    performed_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)


class AccessGrant(Base):
    __tablename__ = "access_grants"
    id = Column(Integer, primary_key=True, index=True)
    grantee_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    document_id = Column(Integer, ForeignKey("documents.id"), nullable=False, index=True)
    granted_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    reason = Column(Text, nullable=False)
    starts_at = Column(DateTime, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    revoked_at = Column(DateTime, nullable=True)
    revoked_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    grantee = relationship("User", foreign_keys=[grantee_id])
    document = relationship("Document")


class AccessAuditLog(Base):
    __tablename__ = "access_audit_logs"
    id = Column(Integer, primary_key=True, index=True)
    actor_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    target_id = Column(Integer, nullable=True)
    action = Column(String(64), nullable=False)
    reason = Column(Text, nullable=True)
    result = Column(String(16), nullable=False)
    details = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)


class AuditRun(Base):
    """An offline security auditor execution run."""

    __tablename__ = "audit_runs"

    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(String(64), unique=True, nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    status = Column(String(32), default="pending")  # pending|running|completed|error
    is_approved = Column(Boolean, default=False)
    approved_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    approved_at = Column(DateTime, nullable=True)
    total_logs_analyzed = Column(Integer, default=0)
    redactions_count = Column(Text, nullable=True)  # JSON dict of counts
    summary = Column(Text, nullable=True)           # JSON dict of findings stats, recommendations, etc.
    auditor_model = Column(String(128), default="openai/gpt-oss-120b")
    error = Column(Text, nullable=True)

    findings = relationship("AuditFinding", back_populates="audit_run", cascade="all, delete-orphan")


class AuditFinding(Base):
    """A single finding flagged during an audit run."""

    __tablename__ = "audit_findings"

    id = Column(Integer, primary_key=True, index=True)
    audit_run_id = Column(Integer, ForeignKey("audit_runs.id"), nullable=False, index=True)
    finding_uid = Column(String(64), nullable=False)
    severity = Column(String(16), nullable=False)  # low|medium|high
    category = Column(String(64), nullable=False)  # injection_attempt|possible_leak|over_blocking|suspicious_pattern|weak_refusal|other
    status = Column(String(32), default="suspected")  # suspected|confirmed|not_reproduced
    evidence_log_ids = Column(Text, nullable=True)  # JSON list of strings (e.g. ["chat:12"])
    explanation = Column(Text, nullable=True)
    suggested_action = Column(Text, nullable=True)
    confidence = Column(Float, default=0.5)
    lab_result_id = Column(Integer, nullable=True)  # Link to validation LabResult
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    audit_run = relationship("AuditRun", back_populates="findings")


class AuditState(Base):
    """Configuration and state cursor for the offline auditor."""

    __tablename__ = "audit_state"

    id = Column(Integer, primary_key=True)
    last_chat_log_id = Column(Integer, default=0)
    last_scan_log_id = Column(Integer, default=0)
    schedule_mode = Column(String(32), default="interval")  # "interval" | "event_count"
    interval_hours = Column(Float, default=24.0)
    event_threshold = Column(Integer, default=20)
    sampling_rate = Column(Float, default=0.1)
    auditor_model = Column(String(128), default="openai/gpt-oss-120b")
    webhook_url = Column(String(512), nullable=True, default="")
    last_run_at = Column(DateTime, nullable=True)


# ── Helpers ────────────────────────────────────────────────────────────────


def get_db():
    """FastAPI dependency that yields a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def purge_expired_conversations(
    db: Session,
    now: datetime.datetime | None = None,
) -> int:
    """Hard-delete conversations beyond retention without touching audit records."""
    now = now or datetime.datetime.utcnow()
    cutoff = now - datetime.timedelta(days=settings.conversation_retention_days)
    expired = db.query(Conversation).filter(Conversation.created_at < cutoff).all()
    count = len(expired)
    for conversation in expired:
        db.delete(conversation)
    db.commit()
    return count


def init_db() -> None:
    """Create all tables and run lightweight migrations for new columns."""
    from sqlalchemy import text
    Base.metadata.create_all(bind=engine)
    with engine.connect() as conn:
        for table, column, declaration in (
            ("users", "department_id", "INTEGER REFERENCES departments(id)"),
            ("users", "team", "VARCHAR(128)"),
            ("documents", "department_id", "INTEGER REFERENCES departments(id)"),
            ("documents", "owner_id", "INTEGER REFERENCES users(id)"),
            ("documents", "confidentiality", "VARCHAR(32) DEFAULT 'internal'"),
            ("roles", "capabilities_json", "TEXT"),
        ):
            columns = {row[1] for row in conn.execute(text(f"PRAGMA table_info({table})"))}
            if column not in columns:
                conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {declaration}"))
                conn.commit()
        try:
            conn.execute(text("ALTER TABLE chunks ADD COLUMN flagged_for_review BOOLEAN DEFAULT 0"))
            conn.commit()
        except Exception:
            pass
        try:
            conn.execute(text("ALTER TABLE chunks ADD COLUMN flag_reason TEXT"))
            conn.commit()
        except Exception:
            pass
        try:
            conn.execute(text("ALTER TABLE chunks ADD COLUMN status VARCHAR(32) DEFAULT 'active'"))
            conn.commit()
        except Exception:
            pass
        try:
            conn.execute(text("ALTER TABLE scan_logs ADD COLUMN source_type VARCHAR(16) DEFAULT 'live'"))
            conn.commit()
        except Exception:
            pass
        try:
            conn.execute(text("ALTER TABLE chat_logs ADD COLUMN source_type VARCHAR(16) DEFAULT 'live'"))
            conn.commit()
        except Exception:
            pass
        try:
            conn.execute(text("ALTER TABLE chunks ADD COLUMN text_content TEXT"))
            conn.commit()
        except Exception:
            pass
