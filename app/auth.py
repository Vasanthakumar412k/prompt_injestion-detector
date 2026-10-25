"""
auth.py – JWT authentication with seeded users: admin, hr_user, employee_user.
"""
from __future__ import annotations

import datetime
import logging
import json
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.config import settings
from app.db import Department, Permission, Role, User, get_db
from app.access_config import LEGACY_ROLE_MAP, ROLE_POLICY
from app.rbac import capabilities_for, role_name
from app.diagnostics import trace_step

logger = logging.getLogger(__name__)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


# ── Pydantic schemas ────────────────────────────────────────────────────────


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserInfo(BaseModel):
    id: int
    username: str
    role: str
    is_active: bool


# ── Password helpers ────────────────────────────────────────────────────────


def hash_password(plain: str) -> str:
    return pwd_context.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


# ── JWT helpers ─────────────────────────────────────────────────────────────


def create_access_token(data: dict) -> str:
    payload = data.copy()
    expire = datetime.datetime.utcnow() + datetime.timedelta(
        minutes=settings.jwt_expire_minutes
    )
    payload["exp"] = expire
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(
            token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm]
        )
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


# ── FastAPI dependency: current user ────────────────────────────────────────


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    try:
        payload = decode_token(token)
    except HTTPException:
        trace_step("auth.token", "denied", reason="invalid_or_expired")
        raise
    username: Optional[str] = payload.get("sub")
    if not username:
        raise HTTPException(status_code=401, detail="Invalid token payload")

    user = db.query(User).filter(User.username == username).first()
    if not user or not user.is_active:
        trace_step("auth.user_lookup", "denied", reason="missing_or_inactive")
        raise HTTPException(status_code=401, detail="User not found or inactive")
    trace_step("auth.user_lookup", "complete", user_id=user.id, role_id=user.role_id)
    return user


def require_role(*roles: str):
    """Compatibility dependency resolved centrally against configured roles."""

    def _check(current_user: User = Depends(get_current_user)) -> User:
        allowed = {LEGACY_ROLE_MAP.get(r, r) for r in roles} | set(roles)
        if role_name(current_user.role) not in allowed and current_user.role.name not in allowed:
            trace_step("role_authorization", "denied", user_id=current_user.id, role_id=current_user.role_id)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires one of roles: {roles}",
            )
        trace_step("role_authorization", "allowed", user_id=current_user.id, role_id=current_user.role_id)
        return current_user

    return _check


def require_capability(capability: str):
    def _check(current_user: User = Depends(get_current_user)) -> User:
        if capability not in capabilities_for(current_user.role):
            trace_step("capability_authorization", "denied", user_id=current_user.id,
                       capability=capability, role_id=current_user.role_id)
            raise HTTPException(status_code=403, detail=f"Missing capability: {capability}")
        trace_step("capability_authorization", "allowed", user_id=current_user.id,
                   capability=capability, role_id=current_user.role_id)
        return current_user
    return _check


def require_any_capability(*capabilities: str):
    def _check(current_user: User = Depends(get_current_user)) -> User:
        if not any(name in capabilities_for(current_user.role) for name in capabilities):
            trace_step("capability_authorization", "denied", user_id=current_user.id,
                       capability="any_required", role_id=current_user.role_id)
            raise HTTPException(status_code=403, detail=f"Missing capabilities: {capabilities}")
        trace_step("capability_authorization", "allowed", user_id=current_user.id,
                   capability="any_required", role_id=current_user.role_id)
        return current_user
    return _check


from pathlib import Path


def get_seed_users() -> list[dict[str, str]]:
    """Load default users from gitignored file or env vars."""
    import os
    import json
    seed_file = Path("seed_users.json")
    if seed_file.exists():
        try:
            return json.loads(seed_file.read_text(encoding="utf-8"))
        except Exception as e:
            logger.warning("Failed to load seed_users.json: %s", e)
    env_users = os.getenv("SEED_USERS_JSON")
    if env_users:
        try:
            return json.loads(env_users)
        except Exception:
            pass

    if env_users:
        raise RuntimeError("SEED_USERS_JSON must contain a valid JSON array")
    raise RuntimeError("Configure users in gitignored seed_users.json or SEED_USERS_JSON")


SEED_ROLES = list(ROLE_POLICY)


def seed_users(db: Session) -> None:
    """Insert default roles and users if they don't already exist."""
    departments = {}
    for name in ("HR", "Engineering"):
        department = db.query(Department).filter(Department.name == name).first()
        if not department:
            department = Department(name=name)
            db.add(department)
            db.flush()
        departments[name] = department

    # Migrate legacy role rows in place; users and permission foreign keys remain valid.
    for old, new in LEGACY_ROLE_MAP.items():
        legacy = db.query(Role).filter(Role.name == old).first()
        canonical = db.query(Role).filter(Role.name == new).first()
        if legacy and not canonical:
            legacy.name = new
            db.flush()
        elif legacy and canonical:
            for user in legacy.users:
                user.role_id = canonical.id
            for permission in list(legacy.permissions):
                duplicate = db.query(Permission).filter(Permission.role_id == canonical.id, Permission.document_id == permission.document_id).first()
                if duplicate:
                    db.delete(permission)
                else:
                    permission.role_id = canonical.id
            db.delete(legacy)
    db.flush()

    # Roles
    role_objs: dict[str, Role] = {}
    for rname in SEED_ROLES:
        role = db.query(Role).filter(Role.name == rname).first()
        if not role:
            role = Role(name=rname, description=f"Default {rname} role", capabilities_json=json.dumps(ROLE_POLICY[rname]))
            db.add(role)
            db.flush()
            logger.info("Created role: %s", rname)
        elif role.capabilities_json is None:
            role.capabilities_json = json.dumps(ROLE_POLICY[rname])
        role_objs[rname] = role

    # Users
    for udata in get_seed_users():
        urole = LEGACY_ROLE_MAP.get(udata["role"], udata["role"])
        dept_name = udata.get("department", "HR" if urole == "hr_manager" else "Engineering")
        if dept_name not in departments:
            raise ValueError(f"Unknown seed department: {dept_name}")
        existing = db.query(User).filter(User.username == udata["username"]).first()
        if not existing:
            user = User(
                username=udata["username"],
                hashed_password=hash_password(udata["password"]),
                role_id=role_objs[urole].id,
                department_id=departments[dept_name].id,
                team=udata.get("team", dept_name),
            )
            db.add(user)
            logger.info("Created user: %s (role=%s)", udata["username"], urole)
        elif existing.department_id is None:
            existing.department_id = departments[dept_name].id
            existing.team = udata.get("team", dept_name)

    db.commit()


def authenticate_user(username: str, password: str, db: Session) -> Optional[User]:
    """Return User if credentials are valid, else None."""
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.hashed_password):
        return None
    return user
