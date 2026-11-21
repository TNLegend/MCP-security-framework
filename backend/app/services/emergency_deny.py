from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import and_, select
from sqlalchemy.orm import Session

from app.models.control_plane import EmergencyDeny


EMERGENCY_DENY_TARGETS = {
    "global",
    "agent_id",
    "framework_session_id",
    "server_ref",
    "server_tool",
}


DENY_STATE_ACTIVE = "ACTIVE"
DENY_STATE_EXPIRED = "EXPIRED"
DENY_STATE_REVOKED = "REVOKED"


def active_emergency_deny_clause(now: datetime | None = None):
    """EM-01: the ONLY definition of an enforceable deny. Every enforcement
    query must use it, so a revoked deny can never block or be forgotten."""
    now = now or datetime.utcnow()
    return and_(EmergencyDeny.expires_at > now, EmergencyDeny.revoked_at.is_(None))


def emergency_deny_state(deny: EmergencyDeny, now: datetime | None = None) -> str:
    now = now or datetime.utcnow()
    if deny.revoked_at is not None:
        return DENY_STATE_REVOKED
    if deny.expires_at <= now:
        return DENY_STATE_EXPIRED
    return DENY_STATE_ACTIVE


class EmergencyDenyError(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def check_emergency_deny(
    db: Session,
    *,
    agent_id: str,
    framework_session_id: str,
    server_ref: str,
    tool_name: str,
) -> str | None:
    now = datetime.utcnow()
    try:
        candidates = db.scalars(
            select(EmergencyDeny)
            .where(active_emergency_deny_clause(now))
            .order_by(EmergencyDeny.created_at.desc())
        ).all()
    except Exception as exc:
        raise EmergencyDenyError("emergency_deny_store_unavailable") from exc
    for deny in candidates:
        if _matches(
            deny,
            agent_id=agent_id,
            framework_session_id=framework_session_id,
            server_ref=server_ref,
            tool_name=tool_name,
        ):
            return deny.id
    return None


def _matches(
    deny: EmergencyDeny,
    *,
    agent_id: str,
    framework_session_id: str,
    server_ref: str,
    tool_name: str,
) -> bool:
    if deny.target_type == "global":
        return True
    if deny.target_type == "agent_id":
        return deny.target_value == agent_id
    if deny.target_type == "framework_session_id":
        return deny.target_value == framework_session_id
    if deny.target_type == "server_ref":
        return deny.target_value == server_ref
    if deny.target_type == "server_tool":
        return deny.target_value == server_ref and deny.target_secondary_value == tool_name
    return False


def emergency_check_payload(context: dict[str, Any]) -> dict[str, str]:
    required = {
        "agent_id": context.get("agent_id"),
        "framework_session_id": context.get("framework_session_id"),
        "server_ref": context.get("server_ref"),
        "tool_name": context.get("tool_name"),
    }
    if any(not isinstance(value, str) or not value for value in required.values()):
        raise EmergencyDenyError("emergency_deny_context_invalid")
    return required
