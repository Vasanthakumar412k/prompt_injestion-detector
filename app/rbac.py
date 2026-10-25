"""
rbac.py – Role-based access control: check and manage role→document permissions.
Permission checks are independent of any AI model.
"""
from __future__ import annotations

import logging
from typing import List, Optional

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.db import AccessAuditLog, AccessGrant, Department, Document, Permission, PermissionAuditLog, Role, User
from app.config import settings
from app.access_config import (
    CONFIDENTIAL_DOCUMENT_ROLES,
    MAX_ACCESS_GRANT_HOURS,
    ORGANIZATION_DEPARTMENT_DOCUMENT_ROLES,
    ROLE_POLICY,
    ROLE_RANK,
    LEGACY_ROLE_MAP,
)
from app.diagnostics import trace_step
import datetime
import json


def role_name(role: Role | str) -> str:
    name = role.name if isinstance(role, Role) else role
    return LEGACY_ROLE_MAP.get(name, name)


def capabilities_for(role: Role | str) -> dict[str, str]:
    name = role_name(role)
    configured = ROLE_POLICY.get(name, {}).copy()
    if isinstance(role, Role) and role.capabilities_json:
        try:
            return json.loads(role.capabilities_json)
        except (ValueError, TypeError):
            pass
    return configured


def authorize_delegation(actor: User, target: User | None, action: str, scope_department_id: int | None, reason: str, db: Session, document: Document | None = None, granted_role: str | None = None, granted_capability: str | None = None, duration_hours: float | None = None, force_denied: bool = False, audit_target_id: int | None = None) -> bool:
    """Single auditable authorization gate for role/capability/document grants."""
    actor_caps = capabilities_for(actor.role)
    if action in ("grant_access", "revoke_access"):
        cap = "grant_access"
    elif action in ("manage_documents", "release_chunk"):
        cap = "manage_documents"
    elif action == "assign_role_capability":
        cap = "manage_roles"
    else:
        cap = "manage_users"
    allowed = cap in actor_caps and not force_denied
    if not isinstance(reason, str) or not reason.strip():
        allowed = False
    actor_scope = actor_caps.get(cap)
    target_department_id = document.department_id if document else (target.department_id if target else scope_department_id)
    if actor_scope == "own_department" and target_department_id != actor.department_id:
        allowed = False
    if actor_scope == "own_department" and target is not None and target.department_id != actor.department_id:
        allowed = False
    if target is not None and target.id == actor.id:
        allowed = False
    if target is not None and ROLE_RANK.get(role_name(target.role), 99) > ROLE_RANK.get(role_name(actor.role), 0):
        allowed = False
    if granted_role and ROLE_RANK.get(role_name(granted_role), 99) > ROLE_RANK.get(role_name(actor.role), 0):
        allowed = False
    if granted_capability and granted_capability not in actor_caps:
        allowed = False
    if duration_hours is not None and not 0 < duration_hours <= min(MAX_ACCESS_GRANT_HOURS, settings.max_access_grant_hours):
        allowed = False
    if document and role_name(actor.role) == "hr_manager" and not (document.department and document.department.name == "HR"):
        allowed = False
    result = "allowed" if allowed else "denied"
    db.add(AccessAuditLog(actor_id=actor.id, target_id=target.id if target else (document.id if document else audit_target_id or scope_department_id), action=action, reason=reason or "", result=result, details=json.dumps({"document_id": document.id if document else None, "role": granted_role, "capability": granted_capability})))
    db.commit()
    trace_step("delegation", result, actor_id=actor.id, target_id=target.id if target else (document.id if document else audit_target_id or 0), action=action)
    return allowed


def create_access_grant(actor: User, grantee: User, document: Document, reason: str, duration_hours: float, db: Session, now: datetime.datetime | None = None) -> AccessGrant:
    now = now or datetime.datetime.utcnow()
    reason = reason.strip()
    allowed = authorize_delegation(actor, grantee, "grant_access", document.department_id, reason, db, document=document, duration_hours=duration_hours)
    if not allowed:
        raise HTTPException(status_code=403, detail="Grant denied by capability, scope, role, reason, or duration policy")
    grant = AccessGrant(grantee_id=grantee.id, document_id=document.id, granted_by=actor.id, reason=reason, starts_at=now, expires_at=now + datetime.timedelta(hours=duration_hours))
    db.add(grant)
    db.commit()
    db.refresh(grant)
    trace_step("access_grant", "created", grant_id=grant.id, grantee_id=grantee.id, document_id=document.id)
    return grant


def revoke_access_grant(actor: User, grant: AccessGrant, reason: str, db: Session, now: datetime.datetime | None = None) -> None:
    if not authorize_delegation(actor, grant.grantee, "revoke_access", grant.document.department_id, reason, db, document=grant.document):
        raise HTTPException(status_code=403, detail="Grant revocation denied by capability or scope policy")
    grant.revoked_at = now or datetime.datetime.utcnow()
    grant.revoked_by = actor.id
    db.commit()
    trace_step("access_grant", "revoked", grant_id=grant.id, actor_id=actor.id)


def can_read(user: User, document: Document, now: datetime.datetime | None = None, db: Session | None = None, chunk: object | None = None) -> bool:
    """Authoritative document/chunk read policy; now is injectable for expiry tests."""
    now = now or datetime.datetime.utcnow()
    if document.is_quarantined or (
        chunk is not None
        and (
            getattr(chunk, "is_quarantined", False)
            or getattr(chunk, "status", None) == "pending_judge"
            or getattr(chunk, "flagged_for_review", False)
        )
    ):
        return False
    level = (document.confidentiality or "internal").lower()
    if level == "public":
        return True
    if level == "internal":
        return True
    same_department = user.department_id is not None and user.department_id == document.department_id
    user_role = role_name(user.role)
    if level == "department":
        return same_department or user_role in ORGANIZATION_DEPARTMENT_DOCUMENT_ROLES
    if level != "confidential":
        return False
    names = CONFIDENTIAL_DOCUMENT_ROLES.get(document.department.name if document.department else "", ())
    organization_roles = CONFIDENTIAL_DOCUMENT_ROLES.get("*", ())
    if (same_department and user_role in names) or user_role in organization_roles:
        return True
    if db is None:
        return False
    grant = db.query(AccessGrant).filter(
        AccessGrant.grantee_id == user.id,
        AccessGrant.document_id == document.id,
        AccessGrant.revoked_at.is_(None),
        AccessGrant.starts_at <= now,
        AccessGrant.expires_at > now,
    ).first()
    return grant is not None

logger = logging.getLogger(__name__)


def get_role_by_name(name: str, db: Session) -> Role:
    role = db.query(Role).filter(Role.name == name).first()
    if not role:
        raise HTTPException(status_code=404, detail=f"Role '{name}' not found")
    return role


def get_document_or_404(doc_id: int, db: Session) -> Document:
    doc = db.query(Document).filter(Document.id == doc_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail=f"Document {doc_id} not found")
    return doc


def user_can_access_document(user: User, doc_id: int, db: Session) -> bool:
    """
    Return True if the user's role has permission to access the document.
    Admin always has access.  This check is purely SQL – no LLM involved.
    """
    doc = db.query(Document).filter(Document.id == doc_id).first()
    return bool(doc and can_read(user, doc, db=db))


def get_allowed_role_names_for_document(doc_id: int, db: Session) -> List[str]:
    """Return list of role names that have permission on a document."""
    perms = db.query(Permission).filter(Permission.document_id == doc_id).all()
    names = []
    for p in perms:
        role = db.query(Role).filter(Role.id == p.role_id).first()
        if role:
            names.append(role.name)
    # admin always implicitly allowed
    if "admin" not in names:
        names.append("admin")
    return names


def grant_permission(role_name: str, doc_id: int, granted_by: User, db: Session) -> Permission:
    """Grant a role access to a document. Idempotent."""
    role = get_role_by_name(role_name, db)
    doc = get_document_or_404(doc_id, db)

    existing = (
        db.query(Permission)
        .filter(Permission.role_id == role.id, Permission.document_id == doc.id)
        .first()
    )
    if existing:
        logger.info("Permission already exists: role=%s doc=%d", role_name, doc_id)
        return existing

    perm = Permission(role_id=role.id, document_id=doc.id, granted_by=granted_by.id if granted_by else None)
    db.add(perm)
    audit = PermissionAuditLog(
        role_name=role_name,
        document_id=doc_id,
        action="grant",
        performed_by=granted_by.id if granted_by else None,
    )
    db.add(audit)
    db.commit()
    db.refresh(perm)
    logger.info("Granted: role=%s → doc=%d by user=%s", role_name, doc_id, granted_by.username if granted_by else "system")
    return perm


def revoke_permission(role_name: str, doc_id: int, db: Session, revoked_by: Optional[User] = None) -> bool:
    """Revoke a role's access to a document. Returns True if something was deleted."""
    role = get_role_by_name(role_name, db)
    deleted = (
        db.query(Permission)
        .filter(Permission.role_id == role.id, Permission.document_id == doc_id)
        .delete()
    )
    audit = PermissionAuditLog(
        role_name=role_name,
        document_id=doc_id,
        action="revoke",
        performed_by=revoked_by.id if revoked_by else None,
    )
    db.add(audit)
    db.commit()
    logger.info("Revoked: role=%s → doc=%d (deleted=%d)", role_name, doc_id, deleted)
    return deleted > 0


def create_role(name: str, description: str, db: Session) -> Role:
    """Create a new role. Raises 409 if it already exists."""
    existing = db.query(Role).filter(Role.name == name).first()
    if existing:
        raise HTTPException(status_code=409, detail=f"Role '{name}' already exists")
    role = Role(name=name, description=description)
    db.add(role)
    db.commit()
    db.refresh(role)
    logger.info("Created role: %s", name)
    return role


def get_accessible_document_ids(user: User, db: Session, now: datetime.datetime | None = None) -> List[int]:
    """
    Return all document IDs the user's role can access (non-quarantined only).
    Admin gets everything.
    """
    docs = db.query(Document).all()
    return [d.id for d in docs if can_read(user, d, now=now, db=db)]


def get_inaccessible_document_ids(user: User, db: Session, now: datetime.datetime | None = None) -> List[int]:
    """
    Return document IDs the user's role CANNOT access.
    Used by the output guard to know what texts are forbidden.
    """
    all_docs = db.query(Document).all()
    return [d.id for d in all_docs if not can_read(user, d, now=now, db=db)]
