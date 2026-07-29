from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hmac
from hashlib import sha256
import re
import secrets

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.trusted_agent_session import TrustedAgentSession


SESSION_TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_-]{32,512}$")


class TrustedSessionError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class CreatedTrustedSession:
    session_reference: str
    session_token: str
    agent_id: str
    identity_issuer: str
    identity_subject: str
    identity_binding_revision: str
    expires_at: datetime


@dataclass(frozen=True)
class VerifiedTrustedSession:
    session_reference: str
    agent_id: str
    identity_issuer: str
    identity_subject: str
    identity_binding_revision: str
    expires_at: datetime
    last_seen_at: datetime


def create_trusted_session(
    *,
    agent_id: str,
    identity_issuer: str,
    identity_subject: str,
    identity_binding_revision: str,
    external_token_id: str | None,
    db: Session,
) -> CreatedTrustedSession:
    if not settings.trusted_session_enabled:
        raise TrustedSessionError("trusted_session_disabled")

    now = _utcnow_naive()
    expires_at = now + timedelta(seconds=settings.trusted_session_ttl_seconds)
    cleanup_expired_trusted_sessions(db=db)
    _enforce_active_session_limit(agent_id=agent_id, db=db, now=now)

    session_token = secrets.token_urlsafe(settings.trusted_session_token_bytes)
    session_reference = f"sess_{secrets.token_urlsafe(24)}"
    token_hash = _hash_session_token(session_token)
    token_id_hash = (
        sha256(external_token_id.encode("utf-8")).hexdigest()
        if external_token_id
        else None
    )

    try:
        db.add(
            TrustedAgentSession(
                session_reference=session_reference,
                token_hash=token_hash,
                agent_id=agent_id,
                identity_issuer=identity_issuer,
                identity_subject=identity_subject,
                identity_binding_revision=identity_binding_revision,
                created_from_token_id_hash=token_id_hash,
                expires_at=expires_at,
                last_seen_at=now,
            )
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise TrustedSessionError("trusted_session_collision") from exc
    except SQLAlchemyError as exc:
        db.rollback()
        raise TrustedSessionError("trusted_session_store_unavailable") from exc

    return CreatedTrustedSession(
        session_reference=session_reference,
        session_token=session_token,
        agent_id=agent_id,
        identity_issuer=identity_issuer,
        identity_subject=identity_subject,
        identity_binding_revision=identity_binding_revision,
        expires_at=expires_at.replace(tzinfo=timezone.utc),
    )


def validate_trusted_session(
    *,
    session_token: str | None,
    db: Session,
) -> VerifiedTrustedSession:
    if not settings.trusted_session_enabled:
        raise TrustedSessionError("trusted_session_disabled")
    if not isinstance(session_token, str) or not session_token.strip():
        raise TrustedSessionError("trusted_session_token_missing")
    if not SESSION_TOKEN_PATTERN.fullmatch(session_token):
        raise TrustedSessionError("trusted_session_token_invalid")

    token_hash = _hash_session_token(session_token)
    now = _utcnow_naive()

    try:
        session = db.scalar(
            select(TrustedAgentSession).where(
                TrustedAgentSession.token_hash == token_hash
            )
        )
        if session is None:
            raise TrustedSessionError("trusted_session_not_found")
        if session.revoked_at is not None:
            raise TrustedSessionError("trusted_session_revoked")
        if session.expires_at <= now:
            raise TrustedSessionError("trusted_session_expired")
        if session.last_seen_at + timedelta(
            seconds=settings.trusted_session_idle_timeout_seconds
        ) <= now:
            raise TrustedSessionError("trusted_session_idle_timeout")

        session.last_seen_at = now
        db.commit()
    except TrustedSessionError:
        db.rollback()
        raise
    except SQLAlchemyError as exc:
        db.rollback()
        raise TrustedSessionError("trusted_session_store_unavailable") from exc

    return VerifiedTrustedSession(
        session_reference=session.session_reference,
        agent_id=session.agent_id,
        identity_issuer=session.identity_issuer,
        identity_subject=session.identity_subject,
        identity_binding_revision=session.identity_binding_revision,
        expires_at=session.expires_at.replace(tzinfo=timezone.utc),
        last_seen_at=session.last_seen_at.replace(tzinfo=timezone.utc),
    )


def revoke_trusted_session(
    *,
    session_reference: str,
    reason: str,
    db: Session,
) -> None:
    now = _utcnow_naive()
    try:
        session = db.scalar(
            select(TrustedAgentSession).where(
                TrustedAgentSession.session_reference == session_reference
            )
        )
        if session is None:
            raise TrustedSessionError("trusted_session_not_found")
        session.revoked_at = now
        session.revocation_reason = reason[:255]
        db.commit()
    except TrustedSessionError:
        db.rollback()
        raise
    except SQLAlchemyError as exc:
        db.rollback()
        raise TrustedSessionError("trusted_session_store_unavailable") from exc


def cleanup_expired_trusted_sessions(*, db: Session) -> int:
    now = _utcnow_naive()
    try:
        sessions = db.scalars(
            select(TrustedAgentSession)
            .where(
                TrustedAgentSession.expires_at < now,
                TrustedAgentSession.revoked_at.is_(None),
            )
            .limit(settings.trusted_session_cleanup_batch_size)
        ).all()
        for session in sessions:
            session.revoked_at = now
            session.revocation_reason = "expired_cleanup"
        db.commit()
        return len(sessions)
    except SQLAlchemyError as exc:
        db.rollback()
        raise TrustedSessionError("trusted_session_store_unavailable") from exc


def _enforce_active_session_limit(
    *,
    agent_id: str,
    db: Session,
    now: datetime,
) -> None:
    try:
        active_count = len(
            db.scalars(
                select(TrustedAgentSession.id).where(
                    TrustedAgentSession.agent_id == agent_id,
                    TrustedAgentSession.expires_at > now,
                    TrustedAgentSession.revoked_at.is_(None),
                )
            ).all()
        )
    except SQLAlchemyError as exc:
        raise TrustedSessionError("trusted_session_store_unavailable") from exc

    if active_count >= settings.trusted_session_max_active_per_agent:
        raise TrustedSessionError("trusted_session_limit_exceeded")


def _hash_session_token(session_token: str) -> str:
    pepper = settings.trusted_session_token_pepper
    if not isinstance(pepper, str) or not pepper or pepper == "<configure-secret-pepper>":
        raise TrustedSessionError("trusted_session_pepper_unavailable")
    return hmac.new(
        pepper.encode("utf-8"),
        session_token.encode("utf-8"),
        sha256,
    ).hexdigest()


def _utcnow_naive() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)
