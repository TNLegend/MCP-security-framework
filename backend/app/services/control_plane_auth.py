from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from hashlib import sha256
import hmac
import secrets
import threading
from typing import Annotated

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import Cookie, Depends, Header, HTTPException, Request, Response, status
from sqlalchemy import event, func, select, text
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.database import get_db
from app.models.control_plane import ControlPlaneSession, ControlPlaneUser
from app.services.control_plane_audit import record_control_plane_audit


ROLE_ADMIN = "ADMIN"
ROLE_VIEWER = "VIEWER"
VALID_ROLES = {ROLE_ADMIN, ROLE_VIEWER}
MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

password_hasher = PasswordHasher()


class ControlPlaneAuthError(ValueError):
    pass


@dataclass(frozen=True)
class AuthenticatedControlPlaneUser:
    user: ControlPlaneUser
    session: ControlPlaneSession


def hash_password(password: str) -> str:
    return password_hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return password_hasher.verify(password_hash, password)
    except VerifyMismatchError:
        return False
    except Exception:
        return False


def hash_token(token: str) -> str:
    return sha256(token.encode("utf-8")).hexdigest()


def normalize_role(role: str) -> str:
    normalized = role.strip().upper()
    if normalized not in VALID_ROLES:
        raise ControlPlaneAuthError("invalid_control_plane_role")
    return normalized


def create_user(
    db: Session,
    *,
    username: str,
    password: str,
    role: str,
    enabled: bool = True,
    display_name: str | None = None,
    created_by: str | None = None,
) -> ControlPlaneUser:
    normalized_username = username.strip()
    normalized_role = normalize_role(role)
    if db.scalar(select(ControlPlaneUser).where(ControlPlaneUser.username == normalized_username)):
        raise ControlPlaneAuthError("control_plane_username_duplicate")
    user = ControlPlaneUser(
        username=normalized_username,
        password_hash=hash_password(password),
        role=normalized_role,
        enabled=enabled,
        display_name=display_name,
        created_by=created_by,
    )
    db.add(user)
    db.flush()
    return user


def authenticate_user(
    db: Session,
    *,
    username: str,
    password: str,
    source_ip: str | None = None,
) -> ControlPlaneUser:
    user = db.scalar(select(ControlPlaneUser).where(ControlPlaneUser.username == username.strip()))
    if user is None or not verify_password(password, user.password_hash):
        record_control_plane_audit(
            db,
            actor=None,
            action="LOGIN_FAILED",
            target_type="control_plane_user",
            target_id=username.strip(),
            source_ip=source_ip,
            result="FAILED",
            metadata={"username": username.strip()},
        )
        raise ControlPlaneAuthError("invalid_credentials")
    if not user.enabled:
        record_control_plane_audit(
            db,
            actor=user,
            action="LOGIN_FAILED",
            target_type="control_plane_user",
            target_id=user.id,
            source_ip=source_ip,
            result="FAILED",
            metadata={"reason": "disabled_user"},
        )
        raise ControlPlaneAuthError("user_disabled")
    return user


def create_session(db: Session, *, user: ControlPlaneUser) -> tuple[str, str, ControlPlaneSession]:
    raw_token = secrets.token_urlsafe(settings.control_plane_session_token_bytes)
    csrf_token = secrets.token_urlsafe(24)
    now = datetime.utcnow()
    session = ControlPlaneSession(
        user_id=user.id,
        token_hash=hash_token(raw_token),
        csrf_token_hash=hash_token(csrf_token),
        created_at=now,
        expires_at=now + timedelta(seconds=settings.control_plane_session_ttl_seconds),
        last_seen_at=now,
    )
    user.last_login_at = now
    db.add(session)
    db.flush()
    return raw_token, csrf_token, session


def set_session_cookies(response: Response, *, token: str, csrf_token: str) -> None:
    max_age = settings.control_plane_session_ttl_seconds
    response.set_cookie(
        settings.control_plane_session_cookie_name,
        token,
        httponly=True,
        secure=settings.control_plane_cookie_secure,
        samesite=settings.control_plane_cookie_samesite,
        path="/",
        max_age=max_age,
    )
    response.set_cookie(
        settings.control_plane_csrf_cookie_name,
        csrf_token,
        httponly=False,
        secure=settings.control_plane_cookie_secure,
        samesite=settings.control_plane_cookie_samesite,
        path="/",
        max_age=max_age,
    )


def clear_session_cookies(response: Response) -> None:
    response.delete_cookie(settings.control_plane_session_cookie_name, path="/")
    response.delete_cookie(settings.control_plane_csrf_cookie_name, path="/")


def revoke_session(db: Session, session: ControlPlaneSession) -> None:
    if session.revoked_at is None:
        session.revoked_at = datetime.utcnow()
        db.flush()


def revoke_user_sessions(db: Session, user_id: str) -> int:
    sessions = db.scalars(
        select(ControlPlaneSession).where(
            ControlPlaneSession.user_id == user_id,
            ControlPlaneSession.revoked_at.is_(None),
        )
    ).all()
    now = datetime.utcnow()
    for session in sessions:
        session.revoked_at = now
    db.flush()
    return len(sessions)


def count_active_admins(db: Session) -> int:
    return int(
        db.scalar(
            select(func.count()).select_from(ControlPlaneUser).where(
                ControlPlaneUser.role == ROLE_ADMIN,
                ControlPlaneUser.enabled.is_(True),
            )
        )
        or 0
    )


LAST_ADMIN_LOCK_KEY = 807018001
_LAST_ADMIN_PROCESS_LOCK = threading.RLock()


def _release_last_admin_process_lock(session: Session, transaction) -> None:
    if transaction.parent is not None:
        return
    if session.info.pop("last_admin_process_lock_held", False):
        _LAST_ADMIN_PROCESS_LOCK.release()


def _acquire_last_admin_process_lock(db: Session) -> None:
    if db.info.get("last_admin_process_lock_held"):
        return
    _LAST_ADMIN_PROCESS_LOCK.acquire()
    db.info["last_admin_process_lock_held"] = True
    event.listen(db, "after_transaction_end", _release_last_admin_process_lock)


def lock_active_admins_for_update(db: Session) -> list[ControlPlaneUser]:
    _acquire_last_admin_process_lock(db)
    bind = db.get_bind()
    if bind.dialect.name == "postgresql":
        db.execute(text("SELECT pg_advisory_xact_lock(:lock_key)"), {"lock_key": LAST_ADMIN_LOCK_KEY})
    return list(
        db.scalars(
            select(ControlPlaneUser)
            .where(
                ControlPlaneUser.role == ROLE_ADMIN,
                ControlPlaneUser.enabled.is_(True),
            )
            .order_by(ControlPlaneUser.id)
            .with_for_update()
        ).all()
    )


def ensure_not_last_active_admin(db: Session, user: ControlPlaneUser) -> None:
    active_admins = lock_active_admins_for_update(db)
    db.refresh(user)
    if user.role == ROLE_ADMIN and user.enabled and len(active_admins) <= 1:
        raise ControlPlaneAuthError("cannot_remove_last_active_admin")


def require_authenticated_user(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    session_token: Annotated[
        str | None,
        Cookie(alias=settings.control_plane_session_cookie_name),
    ] = None,
    csrf_header: Annotated[
        str | None,
        Header(alias=settings.control_plane_csrf_header_name),
    ] = None,
) -> AuthenticatedControlPlaneUser:
    if not session_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    session = db.scalar(
        select(ControlPlaneSession).where(
            ControlPlaneSession.token_hash == hash_token(session_token)
        )
    )
    now = datetime.utcnow()
    if session is None or session.revoked_at is not None or session.expires_at <= now:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid session")
    user = db.get(ControlPlaneUser, session.user_id)
    if user is None or not user.enabled:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid user")

    if request.method in MUTATING_METHODS:
        if not csrf_header or not hmac.compare_digest(hash_token(csrf_header), session.csrf_token_hash):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF validation failed")

    session.last_seen_at = now
    db.flush()
    return AuthenticatedControlPlaneUser(user=user, session=session)


def require_admin(
    current: Annotated[AuthenticatedControlPlaneUser, Depends(require_authenticated_user)],
) -> AuthenticatedControlPlaneUser:
    if current.user.role != ROLE_ADMIN:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin role required")
    return current
