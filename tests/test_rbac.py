"""
tests/test_rbac.py – RBAC filtering tests.
Verifies an employee can never retrieve HR-only chunks.
"""
from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import Base, Chunk, Document, Permission, Role, User
from app.rbac import (
    get_accessible_document_ids,
    user_can_access_document,
    grant_permission,
    revoke_permission,
    create_role,
)
from app.auth import hash_password


# ── In-memory SQLite fixtures ─────────────────────────────────────────────────


@pytest.fixture(scope="function")
def db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


@pytest.fixture()
def roles_and_users(db):
    """Create hr/employee roles and matching users."""
    hr_role = Role(name="hr", description="HR")
    emp_role = Role(name="employee", description="Employee")
    admin_role = Role(name="admin", description="Admin")
    db.add_all([hr_role, emp_role, admin_role])
    db.flush()

    hr_user = User(username="hr_user", hashed_password=hash_password("test"), role_id=hr_role.id)
    emp_user = User(username="emp_user", hashed_password=hash_password("test"), role_id=emp_role.id)
    admin_user = User(username="admin", hashed_password=hash_password("test"), role_id=admin_role.id)
    db.add_all([hr_user, emp_user, admin_user])
    db.flush()

    # Documents
    general_doc = Document(filename="general.txt", content_type="text/plain", uploader_id=admin_user.id)
    hr_doc = Document(filename="salaries.txt", content_type="text/plain", uploader_id=hr_user.id)
    db.add_all([general_doc, hr_doc])
    db.flush()

    # Permissions
    db.add(Permission(role_id=hr_role.id, document_id=general_doc.id))
    db.add(Permission(role_id=emp_role.id, document_id=general_doc.id))
    db.add(Permission(role_id=hr_role.id, document_id=hr_doc.id))
    # No permission for employee on hr_doc
    db.flush()
    db.commit()

    return {
        "hr_role": hr_role, "emp_role": emp_role, "admin_role": admin_role,
        "hr_user": hr_user, "emp_user": emp_user, "admin_user": admin_user,
        "general_doc": general_doc, "hr_doc": hr_doc,
    }


class TestRBACFiltering:
    def test_employee_cannot_access_hr_document(self, db, roles_and_users):
        """Core RBAC rule: employee must not access HR-only document."""
        emp_user = roles_and_users["emp_user"]
        hr_doc = roles_and_users["hr_doc"]
        assert user_can_access_document(emp_user, hr_doc.id, db) is False

    def test_hr_can_access_hr_document(self, db, roles_and_users):
        hr_user = roles_and_users["hr_user"]
        hr_doc = roles_and_users["hr_doc"]
        assert user_can_access_document(hr_user, hr_doc.id, db) is True

    def test_employee_can_access_general_document(self, db, roles_and_users):
        emp_user = roles_and_users["emp_user"]
        general_doc = roles_and_users["general_doc"]
        assert user_can_access_document(emp_user, general_doc.id, db) is True

    def test_admin_can_access_hr_document(self, db, roles_and_users):
        """Admin always has access regardless of explicit permissions."""
        admin_user = roles_and_users["admin_user"]
        hr_doc = roles_and_users["hr_doc"]
        assert user_can_access_document(admin_user, hr_doc.id, db) is True

    def test_get_accessible_doc_ids_employee(self, db, roles_and_users):
        """Employee should only see general_doc in their accessible list."""
        emp_user = roles_and_users["emp_user"]
        general_doc = roles_and_users["general_doc"]
        hr_doc = roles_and_users["hr_doc"]
        accessible = get_accessible_document_ids(emp_user, db)
        assert general_doc.id in accessible
        assert hr_doc.id not in accessible

    def test_get_accessible_doc_ids_hr(self, db, roles_and_users):
        """HR should see both documents."""
        hr_user = roles_and_users["hr_user"]
        general_doc = roles_and_users["general_doc"]
        hr_doc = roles_and_users["hr_doc"]
        accessible = get_accessible_document_ids(hr_user, db)
        assert general_doc.id in accessible
        assert hr_doc.id in accessible

    def test_revoke_permission_blocks_access(self, db, roles_and_users):
        """Revoking permission should immediately block access."""
        hr_user = roles_and_users["hr_user"]
        general_doc = roles_and_users["general_doc"]
        revoke_permission("hr", general_doc.id, db)
        assert user_can_access_document(hr_user, general_doc.id, db) is False

    def test_quarantined_doc_excluded_from_accessible(self, db, roles_and_users):
        """Quarantined documents should not appear in accessible list."""
        emp_user = roles_and_users["emp_user"]
        general_doc = roles_and_users["general_doc"]
        general_doc.is_quarantined = True
        db.commit()
        accessible = get_accessible_document_ids(emp_user, db)
        assert general_doc.id not in accessible
