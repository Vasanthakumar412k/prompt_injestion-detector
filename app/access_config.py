"""Central role and capability policy for the access model."""
from __future__ import annotations

CAPABILITIES = (
    "manage_users", "manage_roles", "manage_documents", "grant_access",
    "manage_detectors", "run_lab", "view_audit_reports", "approve_reports",
    "view_incidents", "request_record_access", "approve_record_access",
)

# Each capability is explicitly scoped. Empty capability maps mean chat-only access.
ROLE_POLICY = {
    "super_admin": {name: "organization" for name in ("manage_users", "manage_roles", "grant_access")},
    "department_admin": {name: "own_department" for name in ("manage_users", "manage_documents", "grant_access")},
    "hr_manager": {name: "own_department" for name in ("manage_documents", "grant_access", "approve_record_access")},
    "security_admin": {name: "organization" for name in ("manage_detectors", "run_lab", "view_incidents", "approve_reports")},
    "auditor": {name: "organization" for name in ("view_audit_reports", "view_incidents", "request_record_access")},
    "employee": {},
}

# Presentation features are separate from authority; document text access still
# comes exclusively from can_read.
ROLE_FEATURES = {
    "super_admin": {"chat": True, "list_documents": True},
    "department_admin": {"chat": True, "list_documents": True},
    "hr_manager": {"chat": True, "list_documents": True},
    "security_admin": {"chat": True, "list_documents": True},
    "auditor": {"chat": False, "list_documents": False},
    "employee": {"chat": True, "list_documents": True},
}

ROLE_RANK = {"employee": 0, "auditor": 1, "hr_manager": 2, "department_admin": 3, "security_admin": 3, "super_admin": 4}
LEGACY_ROLE_MAP = {
    "admin": "super_admin", "security": "security_admin",
    "security_reviewer": "auditor", "hr": "hr_manager",
}
# Confidential text access is independent from management capabilities. The
# super administrator is explicitly included in this read policy; quarantined
# documents and held chunks remain denied by can_read before role evaluation.
CONFIDENTIAL_DOCUMENT_ROLES = {
    "HR": ("hr_manager",),
    "Engineering": ("department_admin",),
    "*": ("super_admin",),
}
# HR managers may read department-level guides across the organization. This
# does not grant access to confidential documents in other departments.
ORGANIZATION_DEPARTMENT_DOCUMENT_ROLES = ("hr_manager",)
MAX_ACCESS_GRANT_HOURS = 24
