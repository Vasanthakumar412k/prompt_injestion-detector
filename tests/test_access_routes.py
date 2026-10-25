"""Direct API checks for user access-management routes and delegation auditing."""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import main
from app.access_config import ROLE_POLICY
from app.auth import create_access_token
from app.db import AccessAuditLog, Base, Department, Document, Role, User, get_db


@pytest.fixture
def access_api():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    db = factory()
    hr = Department(name="HR")
    engineering = Department(name="Engineering")
    db.add_all([hr, engineering])
    db.flush()
    roles = {name: Role(name=name, capabilities_json=json.dumps(policy)) for name, policy in ROLE_POLICY.items()}
    db.add_all(roles.values())
    db.flush()
    actor = User(username="api_super", hashed_password="unused", role_id=roles["super_admin"].id, department_id=hr.id)
    target = User(username="api_employee", hashed_password="unused", role_id=roles["employee"].id, department_id=engineering.id)
    outsider = User(username="api_hr_admin", hashed_password="unused", role_id=roles["department_admin"].id, department_id=hr.id)
    db.add_all([actor, target, outsider])
    db.flush()
    document = Document(filename="engineering-confidential.txt", uploader_id=actor.id, owner_id=actor.id,
                        department_id=engineering.id, confidentiality="confidential")
    db.add(document)
    db.commit()

    def override_db():
        session = factory()
        try:
            yield session
        finally:
            session.close()

    main.app.dependency_overrides[get_db] = override_db
    client = TestClient(main.app)
    tokens = {
        "super": create_access_token({"sub": actor.username}),
        "employee": create_access_token({"sub": target.username}),
        "department_admin": create_access_token({"sub": outsider.username}),
    }
    yield client, db, actor, target, outsider, document, tokens
    main.app.dependency_overrides.pop(get_db, None)
    db.close()
    engine.dispose()


def test_access_routes_enforce_employee_bypass_and_log_delegation(access_api):
    client, db, actor, target, _, document, tokens = access_api
    employee_headers = {"Authorization": f"Bearer {tokens['employee']}"}
    denied = [
        client.get("/access/users", headers=employee_headers),
        client.get("/access-grants", headers=employee_headers),
        client.get("/access-grants/requests", headers=employee_headers),
        client.get("/access-audit", headers=employee_headers),
        client.get("/roles", headers=employee_headers),
        client.post("/access-grants", headers=employee_headers, json={"grantee_id": target.id, "document_id": document.id, "reason": "test", "duration_hours": 1}),
        client.request("DELETE", "/access-grants/999", headers=employee_headers, data={"reason": "test"}),
        client.post(f"/access-grants/request?document_id={document.id}", headers=employee_headers, data={"reason": "test"}),
        client.post("/access-grants/requests/999/approve", headers=employee_headers, data={"duration_hours": 1}),
        client.patch(f"/users/{target.id}/role", headers=employee_headers, json={"role_name": "auditor", "reason": "test"}),
        client.patch("/roles/employee/capabilities", headers=employee_headers, json={"capability": "manage_users", "enabled": True, "reason": "test"}),
        client.post("/permissions", headers=employee_headers, json={"role_name": "employee", "document_id": document.id, "action": "grant"}),
    ]
    assert [response.status_code for response in denied] == [403] * len(denied)
    assert db.query(AccessAuditLog).filter_by(result="denied").count() >= 5

    super_headers = {"Authorization": f"Bearer {tokens['super']}"}
    grant_response = client.post("/access-grants", headers=super_headers,
                                 json={"grantee_id": target.id, "document_id": document.id,
                                       "reason": "Approved engineering support", "duration_hours": 2})
    assert grant_response.status_code == 200
    assert client.get("/me", headers=super_headers).json()["capabilities"]["manage_roles"] == "organization"

    self_role = client.patch(f"/users/{actor.id}/role", headers=super_headers,
                             json={"role_name": "employee", "reason": "Self-change attempt"})
    assert self_role.status_code == 403
    self_grant = client.post("/access-grants", headers=super_headers,
                             json={"grantee_id": actor.id, "document_id": document.id,
                                   "reason": "Self-grant attempt", "duration_hours": 1})
    assert self_grant.status_code == 403
    unheld_capability = client.patch("/roles/employee/capabilities", headers=super_headers,
                                     json={"capability": "manage_documents", "enabled": True,
                                           "reason": "Capability escalation attempt"})
    assert unheld_capability.status_code == 403

    cross_scope = client.post("/access-grants", headers={"Authorization": f"Bearer {tokens['department_admin']}"},
                              json={"grantee_id": target.id, "document_id": document.id,
                                    "reason": "Cross-department attempt", "duration_hours": 1})
    assert cross_scope.status_code == 403
    assert db.query(AccessAuditLog).filter_by(action="grant_access", result="denied").count() >= 3
    assert db.query(AccessAuditLog).filter_by(action="assign_role", result="denied").count() >= 1
    assert db.query(AccessAuditLog).filter_by(action="assign_role_capability", result="denied").count() >= 2
