from __future__ import annotations

import re
from datetime import datetime
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Query, HTTPException, Path
from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models.control_plane import (
    ControlPlaneAuditEvent, ControlPlaneConfigRevision, ControlPlaneUser, EmergencyDeny,
)
from app.models.mcp_server import MCPServer
from app.models.runtime_call import RuntimeCall
from app.models.tool_analysis import ToolProtocolObservation
from app.models.cloud_security import (
    CloudScanEvent, CloudDeployGovernanceDecision, CloudDeployExceptionEvent,
)
from app.services.control_plane_auth import ROLE_ADMIN, AuthenticatedControlPlaneUser, require_authenticated_user
from app.services.emergency_deny import emergency_deny_state

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



@router.get("/resolve/{target_type}/{target_id}")
def resolve_audit_target(
    target_type: Literal[
        "mcp_server", "control_plane_config_revision", "emergency_deny",
        "control_plane_user", "tool_protocol_observation",
    ],
    target_id: str = Path(min_length=1, max_length=36),
    current: AuthenticatedControlPlaneUser = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
):
    """Resolve the exact primary key and return only investigation metadata."""
    model = {
        "mcp_server": MCPServer,
        "control_plane_config_revision": ControlPlaneConfigRevision,
        "emergency_deny": EmergencyDeny,
        "control_plane_user": ControlPlaneUser,
        "tool_protocol_observation": ToolProtocolObservation,
    }[target_type]
    if target_type == "control_plane_user" and current.user.role != ROLE_ADMIN:
        raise HTTPException(status_code=404, detail="audit_target_not_available")
    if target_type in {"mcp_server", "tool_protocol_observation"}:
        key = int(target_id) if re.fullmatch(r"[1-9][0-9]{0,9}", target_id) else 0
        if not 0 < key <= 2147483647:
            raise HTTPException(status_code=404, detail="audit_target_not_available")
    else:
        try:
            key = str(UUID(target_id))
        except ValueError:
            raise HTTPException(status_code=404, detail="audit_target_not_available") from None
    record = db.get(model, key)
    if record is None:
        raise HTTPException(status_code=404, detail="audit_target_not_available")

    if isinstance(record, ToolProtocolObservation):
        # Only expose observations referenced by the authenticated audit view.
        # Do not turn audit navigation into a second inventory endpoint.
        receipt = db.scalar(select(ControlPlaneAuditEvent.id).where(
            ControlPlaneAuditEvent.target_type == target_type,
            ControlPlaneAuditEvent.target_id == str(key),
        ).limit(1))
        if receipt is None:
            raise HTTPException(status_code=404, detail="audit_target_not_available")
        label, status = f"Observation #{record.id}", record.analysis_state
    elif isinstance(record, MCPServer):
        label, status = record.name, record.status
    elif isinstance(record, ControlPlaneConfigRevision):
        label, status = f"Revision #{record.revision_number}", record.status
    elif isinstance(record, EmergencyDeny):
        label, status = "Emergency restriction", emergency_deny_state(record, datetime.utcnow())
    else:
        label, status = record.username, "Enabled" if record.enabled else "Disabled"
    return {"type": target_type, "id": str(record.id), "label": label, "status": status}


@router.get("/events")
def list_audit_events(
    limit: int = Query(default=200, ge=1, le=500),
    offset: int = Query(default=0, ge=0, le=1_000_000),
    _: AuthenticatedControlPlaneUser = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
):
    events = db.scalars(
        select(ControlPlaneAuditEvent)
        .order_by(ControlPlaneAuditEvent.timestamp.desc(), ControlPlaneAuditEvent.id.desc())
        .offset(offset)
        .limit(limit)
    ).all()
    return [_event_public(event) for event in events]


@router.get("/events/page")
def page_audit_events(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0, le=1_000_000),
    search: str | None = Query(default=None, max_length=255),
    snapshot_at: datetime | None = Query(default=None),
    snapshot_id: str | None = Query(default=None, max_length=36, pattern=r"^[0-9a-f-]{36}$"),
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

    # Anchor pagination to a (timestamp, ID) boundary, so new writes do not
    # shift previously loaded pages in an operator's search session.
    if (snapshot_at is None) != (snapshot_id is None):
        raise HTTPException(status_code=422, detail="audit_snapshot_pair_required")
    if snapshot_at is not None and snapshot_at.tzinfo is not None:
        raise HTTPException(status_code=422, detail="audit_snapshot_utc_naive_required")
    if snapshot_at is None:
        newest=select(ControlPlaneAuditEvent.timestamp,
                      ControlPlaneAuditEvent.id).order_by(
            ControlPlaneAuditEvent.timestamp.desc(),
            ControlPlaneAuditEvent.id.desc(),
        ).limit(1)
        if filters:
            newest=newest.where(*filters)
        first=db.execute(newest).first()
        if first is not None:
            snapshot_at,snapshot_id=first

    count_statement = select(func.count()).select_from(ControlPlaneAuditEvent)
    events_statement = select(ControlPlaneAuditEvent)
    if filters:
        count_statement = count_statement.where(*filters)
        events_statement = events_statement.where(*filters)
    if snapshot_at is not None:
        anchor=or_(
            ControlPlaneAuditEvent.timestamp<snapshot_at,
            and_(ControlPlaneAuditEvent.timestamp==snapshot_at,
                 ControlPlaneAuditEvent.id<=snapshot_id),
        )
        count_statement=count_statement.where(anchor)
        events_statement=events_statement.where(anchor)

    total = int(db.scalar(count_statement) or 0)
    events = db.scalars(
        events_statement
        .order_by(ControlPlaneAuditEvent.timestamp.desc(), ControlPlaneAuditEvent.id.desc())
        .offset(offset)
        .limit(limit)
    ).all()
    return {
        "items": [_event_public(event) for event in events],
        "total": total,
        "limit": limit,
        "offset": offset,
        "snapshot_at": snapshot_at.isoformat() if snapshot_at else None,
        "snapshot_id": snapshot_id,
    }

@router.get("/related/{target_kind}/{target_id}")
def related_security_timeline(
    target_kind: Literal["runtime_operation", "cloud_scan"],
    target_id: str = Path(
        pattern=r"^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$",
    ),
    limit: int = Query(default=80, ge=1, le=200),
    _: AuthenticatedControlPlaneUser = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
):
    """Correlate recorded events ONLY by an exact immutable operation/scan ID.

    This never correlates by fuzzy tool names, actor, time proximity or
    resource labels. It returns no raw arguments, cloud policy documents,
    OAuth tokens, external outputs or private audit metadata. Missing records
    are not proof that the corresponding security action never took place.
    """
    rows = []
    truncated = False

    def add(source: str, identifier: str, when: datetime,
            event_code: str, result: str | None = None):
        rows.append({
            "id": identifier, "source": source, "timestamp": when,
            "event_code": event_code, "result": result,
        })

    # All source queries are bounded separately to prevent unlimited loads.
    audit = db.scalars(select(ControlPlaneAuditEvent).where(
        ControlPlaneAuditEvent.target_type == target_kind,
        ControlPlaneAuditEvent.target_id == target_id,
    ).order_by(
        ControlPlaneAuditEvent.timestamp.desc(), ControlPlaneAuditEvent.id.desc()
    ).limit(limit + 1)).all()
    truncated = truncated or len(audit) > limit
    for row in audit[:limit]:
        add("ADMIN_AUDIT", row.id, row.timestamp, row.action, row.result)

    if target_kind == "runtime_operation":
        events = db.scalars(select(RuntimeCall).where(
            RuntimeCall.operation_id == target_id,
        ).order_by(RuntimeCall.created_at.desc(), RuntimeCall.id.desc())
                           .limit(3)).all()
        for event in events:
            add("RUNTIME", str(event.id), event.created_at,
                event.event_phase or "LEGACY_PHASE",
                event.execution_status or event.decision)
    else:
        events = db.scalars(select(CloudScanEvent).where(
            CloudScanEvent.scan_id == target_id,
        ).order_by(CloudScanEvent.created_at.desc(), CloudScanEvent.id.desc())
                            .limit(limit + 1)).all()
        truncated = truncated or len(events) > limit
        for event in events[:limit]:
            add("CLOUD_SCAN", event.id, event.created_at,
                event.message_code, event.event_type)

        governance = db.scalars(select(CloudDeployGovernanceDecision).where(
            CloudDeployGovernanceDecision.scan_id == target_id,
        ).order_by(CloudDeployGovernanceDecision.created_at.desc(),
                   CloudDeployGovernanceDecision.id.desc())
                               .limit(limit + 1)).all()
        truncated = truncated or len(governance) > limit
        for event in governance[:limit]:
            add("CLOUD_GOVERNANCE", event.id, event.created_at,
                "DEPLOY_GOVERNANCE_REVIEW", event.classification)

        exception_events = db.scalars(select(CloudDeployExceptionEvent).where(
            CloudDeployExceptionEvent.scan_id == target_id,
        ).order_by(CloudDeployExceptionEvent.created_at.desc(),
                   CloudDeployExceptionEvent.id.desc())
                                     .limit(limit + 1)).all()
        truncated = truncated or len(exception_events) > limit
        for event in exception_events[:limit]:
            add("CLOUD_EXCEPTION", event.id, event.created_at,
                event.operation, "RECORDED")

    rows.sort(key=lambda item: (
        item["timestamp"], item["source"], item["id"]
    ), reverse=True)
    if len(rows) > limit:
        truncated = True
    return {
        "target_kind": target_kind, "target_id": target_id,
        "events": rows[:limit], "truncated": truncated,
        "scope": "EXACT_ID_PERSISTED_EVENTS_ONLY",
        "limitations": (
            "Only records stored under this exact identifier are linked. "
            "Omitted, legacy or externally stored events are not inferred. "
            "This timeline does not prove remote MCP execution or effective AWS access."
        ),
    }
