from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models.control_plane import ControlPlaneAuditEvent
from app.services.control_plane_auth import AuthenticatedControlPlaneUser, require_authenticated_user

router = APIRouter(prefix="/control-plane/audit", tags=["Control Plane Audit"])


def _event_public(event: ControlPlaneAuditEvent) -> dict:
    return {
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


@router.get("/events")
def list_audit_events(
    limit: int = Query(default=200, ge=1, le=500),
    offset: int = Query(default=0, ge=0, le=1_000_000),
    _: AuthenticatedControlPlaneUser = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
):
    events = db.scalars(
        select(ControlPlaneAuditEvent)
        .order_by(ControlPlaneAuditEvent.timestamp.desc())
        .offset(offset)
        .limit(limit)
    ).all()
    return [_event_public(event) for event in events]


@router.get("/events/page")
def page_audit_events(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0, le=1_000_000),
    search: str | None = Query(default=None, max_length=255),
    _: AuthenticatedControlPlaneUser = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
):
    normalized = (search or "").strip()
    filters = []
    if normalized:
        pattern = f"%{normalized}%"
        filters.append(
            or_(
                ControlPlaneAuditEvent.action.ilike(pattern),
                ControlPlaneAuditEvent.target_type.ilike(pattern),
                ControlPlaneAuditEvent.target_id.ilike(pattern),
                ControlPlaneAuditEvent.actor_username_snapshot.ilike(pattern),
                ControlPlaneAuditEvent.result.ilike(pattern),
                ControlPlaneAuditEvent.reason.ilike(pattern),
            )
        )

    count_statement = select(func.count()).select_from(ControlPlaneAuditEvent)
    events_statement = select(ControlPlaneAuditEvent)
    if filters:
        count_statement = count_statement.where(*filters)
        events_statement = events_statement.where(*filters)

    total = int(db.scalar(count_statement) or 0)
    events = db.scalars(
        events_statement
        .order_by(ControlPlaneAuditEvent.timestamp.desc())
        .offset(offset)
        .limit(limit)
    ).all()
    return {
        "items": [_event_public(event) for event in events],
        "total": total,
        "limit": limit,
        "offset": offset,
    }
