from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models.control_plane import ControlPlaneAuditEvent
from app.services.control_plane_auth import AuthenticatedControlPlaneUser, require_authenticated_user

router = APIRouter(prefix="/control-plane/audit", tags=["Control Plane Audit"])


@router.get("/events")
def list_audit_events(
    _: AuthenticatedControlPlaneUser = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
):
    events = db.scalars(
        select(ControlPlaneAuditEvent).order_by(ControlPlaneAuditEvent.timestamp.desc()).limit(200)
    ).all()
    return [
        {
            "id": event.id,
            "timestamp": event.timestamp,
            "actor_user_id": event.actor_user_id,
            "actor_username_snapshot": event.actor_username_snapshot,
            "actor_role_snapshot": event.actor_role_snapshot,
            "action": event.action,
            "target_type": event.target_type,
            "target_id": event.target_id,
            "revision_id": event.revision_id,
            "before_json": event.before_json,
            "after_json": event.after_json,
            "reason": event.reason,
            "source_ip": event.source_ip,
            "result": event.result,
            "metadata": event.event_metadata,
        }
        for event in events
    ]
