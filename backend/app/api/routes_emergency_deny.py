from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models.control_plane import EmergencyDeny
from app.services.dispatch_admission import lock_emergency_dispatch_authority
from app.schemas.control_plane import EmergencyDenyCreateRequest, EmergencyDenyPublic
from app.services.control_plane_audit import record_control_plane_audit
from app.services.control_plane_auth import (
    AuthenticatedControlPlaneUser,
    require_admin,
    require_authenticated_user,
)


router = APIRouter(prefix="/control-plane/emergency-denies", tags=["Emergency Deny"])


@router.get("", response_model=list[EmergencyDenyPublic])
def list_emergency_denies(
    _: AuthenticatedControlPlaneUser = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
):
    return db.scalars(
        select(EmergencyDeny).order_by(EmergencyDeny.created_at.desc())
    ).all()


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
    return deny


@router.delete("/{deny_id}", status_code=204)
def revoke_emergency_deny(
    deny_id: str,
    current: AuthenticatedControlPlaneUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    lock_emergency_dispatch_authority(db)
    deny = db.get(EmergencyDeny, deny_id)
    if deny is None:
        raise HTTPException(status_code=404, detail="Emergency deny not found")
    record_control_plane_audit(
        db,
        actor=current.user,
        action="EMERGENCY_DENY_REVOKED",
        target_type="emergency_deny",
        target_id=deny.id,
        reason="Emergency deny manually revoked.",
        before_json={"expires_at": deny.expires_at.isoformat()},
    )
    db.delete(deny)
    db.commit()
