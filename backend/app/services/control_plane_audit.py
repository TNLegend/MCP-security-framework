from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.models.control_plane import ControlPlaneAuditEvent, ControlPlaneUser


SENSITIVE_KEYS = {
    "password",
    "new_password",
    "current_password",
    "password_hash",
    "token",
    "session_token",
    "csrf_token",
    "cookie",
    "authorization",
    "private_key",
    "secret",
}


def sanitize_audit_json(value: Any) -> Any:
    if isinstance(value, dict):
        sanitized = {}
        for key, item in value.items():
            key_text = str(key)
            if any(sensitive in key_text.lower() for sensitive in SENSITIVE_KEYS):
                continue
            sanitized[key_text] = sanitize_audit_json(item)
        return sanitized
    if isinstance(value, list):
        return [sanitize_audit_json(item) for item in value]
    return value


def record_control_plane_audit(
    db: Session,
    *,
    actor: ControlPlaneUser | None,
    action: str,
    target_type: str | None = None,
    target_id: str | None = None,
    revision_id: str | None = None,
    before_json: dict[str, Any] | None = None,
    after_json: dict[str, Any] | None = None,
    reason: str | None = None,
    source_ip: str | None = None,
    result: str = "SUCCESS",
    metadata: dict[str, Any] | None = None,
) -> ControlPlaneAuditEvent:
    event = ControlPlaneAuditEvent(
        actor_user_id=actor.id if actor else None,
        actor_username_snapshot=actor.username if actor else None,
        actor_role_snapshot=actor.role if actor else None,
        action=action,
        target_type=target_type,
        target_id=target_id,
        revision_id=revision_id,
        before_json=sanitize_audit_json(before_json),
        after_json=sanitize_audit_json(after_json),
        reason=reason,
        source_ip=source_ip,
        result=result,
        event_metadata=sanitize_audit_json(metadata),
    )
    db.add(event)
    db.flush()
    return event
