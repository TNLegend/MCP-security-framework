from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models.control_plane import EmergencyDeny
from app.models.runtime_call import RuntimeCall
from app.services.dispatch_admission import lock_emergency_dispatch_authority
from app.schemas.control_plane import (
    EmergencyDenyCreateRequest,
    EmergencyDenyPublic,
    EmergencyDenyRevokeRequest,
)
from app.schemas.runtime import RuntimeCallRead
from app.services.emergency_deny import (
    DENY_STATE_ACTIVE,
    DENY_STATE_REVOKED,
    emergency_deny_state,
)
from app.services.control_plane_audit import record_control_plane_audit
from app.services.control_plane_auth import (
    AuthenticatedControlPlaneUser,
    require_admin,
    require_authenticated_user,
)


router = APIRouter(prefix="/control-plane/emergency-denies", tags=["Emergency Deny"])


MAX_LINKED_RUNTIME_EVENTS = 50


def _public(deny: EmergencyDeny, counts: dict[str, int], now: datetime) -> EmergencyDenyPublic:
    return EmergencyDenyPublic(
        id=deny.id,
        target_type=deny.target_type,
        target_value=deny.target_value,
        target_secondary_value=deny.target_secondary_value,
        reason=deny.reason,
        created_by=deny.created_by,
        created_at=deny.created_at,
        expires_at=deny.expires_at,
        state=emergency_deny_state(deny, now),
        revoked_at=deny.revoked_at,
        revoked_by=deny.revoked_by,
        revocation_justification=deny.revocation_justification,
        runtime_event_count=counts.get(deny.id, 0),
    )


def _runtime_event_counts(db: Session, deny_ids: list[str]) -> dict[str, int]:
    if not deny_ids:
        return {}
    rows = db.execute(
        select(RuntimeCall.emergency_deny_id, func.count(RuntimeCall.id))
        .where(RuntimeCall.emergency_deny_id.in_(deny_ids))
        .group_by(RuntimeCall.emergency_deny_id)
    ).all()
    return {deny_id: count for deny_id, count in rows}


@router.get("", response_model=list[EmergencyDenyPublic])
def list_emergency_denies(
    _: AuthenticatedControlPlaneUser = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
):
    denies = db.scalars(
        select(EmergencyDeny).order_by(EmergencyDeny.created_at.desc())
    ).all()
    counts = _runtime_event_counts(db, [deny.id for deny in denies])
    now = datetime.utcnow()
    return [_public(deny, counts, now) for deny in denies]


@router.post("", response_model=EmergencyDenyPublic, status_code=201)
def create_emergency_deny(
    payload: EmergencyDenyCreateRequest,
    current: AuthenticatedControlPlaneUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    lock_emergency_dispatch_authority(db)
    deny = EmergencyDeny(
        **payload.model_dump(),
        created_by=current.user.id,
        created_at=datetime.utcnow(),
    )
    db.add(deny)
    db.flush()
    record_control_plane_audit(
        db,
        actor=current.user,
        action="EMERGENCY_DENY_CREATED",
        target_type="emergency_deny",
        target_id=deny.id,
        reason=deny.reason,
        after_json={
            "target_type": deny.target_type,
            "target_value": deny.target_value,
            "target_secondary_value": deny.target_secondary_value,
            "expires_at": deny.expires_at.isoformat(),
        },
    )
    db.commit()
    db.refresh(deny)
    return _public(deny, {}, datetime.utcnow())


@router.post("/{deny_id}/revoke", response_model=EmergencyDenyPublic)
def revoke_emergency_deny(
    deny_id: str,
    payload: EmergencyDenyRevokeRequest,
    current: AuthenticatedControlPlaneUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """EM-01: logical revocation. The row is kept so every runtime event that
    cites this deny stays resolvable; enforcement ignores it from now on."""
    lock_emergency_dispatch_authority(db)
    deny = db.get(EmergencyDeny, deny_id, with_for_update=True)
    if deny is None:
        raise HTTPException(status_code=404, detail="Emergency deny not found")
    now = datetime.utcnow()
    state = emergency_deny_state(deny, now)
    if state == DENY_STATE_REVOKED:
        raise HTTPException(status_code=409, detail="emergency_deny_already_revoked")
    if state != DENY_STATE_ACTIVE:
        raise HTTPException(status_code=409, detail="emergency_deny_already_expired")
    justification = payload.justification.strip()
    if len(justification) < 8:
        raise HTTPException(status_code=422, detail="revocation_justification_too_short")
    deny.revoked_at = now
    deny.revoked_by = current.user.id
    deny.revocation_justification = justification
    record_control_plane_audit(
        db,
        actor=current.user,
        action="EMERGENCY_DENY_REVOKED",
        target_type="emergency_deny",
        target_id=deny.id,
        reason=justification,
        before_json={"state": state, "expires_at": deny.expires_at.isoformat()},
        after_json={"state": DENY_STATE_REVOKED, "revoked_at": now.isoformat()},
    )
    db.commit()
    db.refresh(deny)
    return _public(deny, _runtime_event_counts(db, [deny.id]), datetime.utcnow())


@router.delete("/{deny_id}", status_code=405)
def delete_emergency_deny_refused(
    deny_id: str,
    _: AuthenticatedControlPlaneUser = Depends(require_admin),
):
    """Physical deletion would orphan runtime evidence: refused (EM-01)."""
    raise HTTPException(
        status_code=405,
        detail="emergency_deny_deletion_disabled_use_revoke",
    )


@router.get("/{deny_id}/runtime-events", response_model=list[RuntimeCallRead])
def emergency_deny_runtime_events(
    deny_id: str,
    _: AuthenticatedControlPlaneUser = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
):
    if db.get(EmergencyDeny, deny_id) is None:
        raise HTTPException(status_code=404, detail="Emergency deny not found")
    return db.scalars(
        select(RuntimeCall)
        .where(RuntimeCall.emergency_deny_id == deny_id)
        .order_by(RuntimeCall.id.desc())
        .limit(MAX_LINKED_RUNTIME_EVENTS)
    ).all()
