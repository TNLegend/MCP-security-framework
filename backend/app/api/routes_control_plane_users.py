from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models.control_plane import ControlPlaneUser
from app.schemas.control_plane import (
    ControlPlaneUserPublic,
    CreateControlPlaneUserRequest,
    PatchControlPlaneUserRequest,
    ReasonRequest,
    ResetPasswordRequest,
)
from app.services.control_plane_audit import record_control_plane_audit
from app.services.control_plane_auth import (
    AuthenticatedControlPlaneUser,
    ControlPlaneAuthError,
    create_user,
    ensure_not_last_active_admin,
    hash_password,
    normalize_role,
    require_admin,
    revoke_user_sessions,
)

router = APIRouter(prefix="/control-plane/users", tags=["Control Plane Users"])


@router.get("", response_model=list[ControlPlaneUserPublic])
def list_users(
    _: AuthenticatedControlPlaneUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    return [
        ControlPlaneUserPublic.model_validate(user)
        for user in db.scalars(select(ControlPlaneUser).order_by(ControlPlaneUser.username)).all()
    ]


@router.get("/{user_id}", response_model=ControlPlaneUserPublic)
def get_user(
    user_id: str,
    _: AuthenticatedControlPlaneUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    return ControlPlaneUserPublic.model_validate(_user_or_404(db, user_id))


@router.post("", response_model=ControlPlaneUserPublic, status_code=201)
def create_control_plane_user(
    payload: CreateControlPlaneUserRequest,
    request: Request,
    current: AuthenticatedControlPlaneUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    try:
        user = create_user(
            db,
            username=payload.username,
            password=payload.password,
            role=payload.role,
            enabled=payload.enabled,
            display_name=payload.display_name,
            created_by=current.user.id,
        )
    except ControlPlaneAuthError as exc:
        raise HTTPException(status_code=400, detail=exc.args[0])
    record_control_plane_audit(
        db,
        actor=current.user,
        action="USER_CREATED",
        target_type="control_plane_user",
        target_id=user.id,
        after_json=ControlPlaneUserPublic.model_validate(user).model_dump(mode="json"),
        source_ip=request.client.host if request.client else None,
    )
    db.commit()
    return ControlPlaneUserPublic.model_validate(user)


@router.patch("/{user_id}", response_model=ControlPlaneUserPublic)
def patch_user(
    user_id: str,
    payload: PatchControlPlaneUserRequest,
    request: Request,
    current: AuthenticatedControlPlaneUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    user = _user_or_404(db, user_id)
    before = ControlPlaneUserPublic.model_validate(user).model_dump(mode="json")
    if payload.role is not None:
        new_role = normalize_role(payload.role)
        if user.role != new_role and user.role == "ADMIN" and new_role == "VIEWER":
            try:
                ensure_not_last_active_admin(db, user)
            except ControlPlaneAuthError as exc:
                raise HTTPException(status_code=400, detail=exc.args[0])
        user.role = new_role
        record_control_plane_audit(
            db,
            actor=current.user,
            action="USER_ROLE_CHANGED",
            target_type="control_plane_user",
            target_id=user.id,
            before_json=before,
            after_json={"role": new_role},
            reason="role change",
            source_ip=request.client.host if request.client else None,
        )
    if payload.display_name is not None:
        user.display_name = payload.display_name
    db.flush()
    db.commit()
    return ControlPlaneUserPublic.model_validate(user)


@router.post("/{user_id}/enable", response_model=ControlPlaneUserPublic)
def enable_user(
    user_id: str,
    request: Request,
    current: AuthenticatedControlPlaneUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    user = _user_or_404(db, user_id)
    user.enabled = True
    record_control_plane_audit(
        db,
        actor=current.user,
        action="USER_ENABLED",
        target_type="control_plane_user",
        target_id=user.id,
        source_ip=request.client.host if request.client else None,
    )
    db.commit()
    return ControlPlaneUserPublic.model_validate(user)


@router.post("/{user_id}/disable", response_model=ControlPlaneUserPublic)
def disable_user(
    user_id: str,
    payload: ReasonRequest,
    request: Request,
    current: AuthenticatedControlPlaneUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    user = _user_or_404(db, user_id)
    try:
        ensure_not_last_active_admin(db, user)
    except ControlPlaneAuthError as exc:
        raise HTTPException(status_code=400, detail=exc.args[0])
    user.enabled = False
    revoked = revoke_user_sessions(db, user.id)
    record_control_plane_audit(
        db,
        actor=current.user,
        action="USER_DISABLED",
        target_type="control_plane_user",
        target_id=user.id,
        reason=payload.reason,
        source_ip=request.client.host if request.client else None,
        metadata={"revoked_sessions": revoked},
    )
    db.commit()
    return ControlPlaneUserPublic.model_validate(user)


@router.post("/{user_id}/reset-password")
def reset_password(
    user_id: str,
    payload: ResetPasswordRequest,
    request: Request,
    current: AuthenticatedControlPlaneUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    user = _user_or_404(db, user_id)
    user.password_hash = hash_password(payload.new_password)
    revoked = revoke_user_sessions(db, user.id)
    record_control_plane_audit(
        db,
        actor=current.user,
        action="USER_PASSWORD_RESET",
        target_type="control_plane_user",
        target_id=user.id,
        reason=payload.reason,
        source_ip=request.client.host if request.client else None,
        metadata={"revoked_sessions": revoked},
    )
    db.commit()
    return {"ok": True, "revoked_sessions": revoked}


@router.post("/{user_id}/revoke-sessions")
def revoke_sessions(
    user_id: str,
    payload: ReasonRequest,
    request: Request,
    current: AuthenticatedControlPlaneUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    user = _user_or_404(db, user_id)
    revoked = revoke_user_sessions(db, user.id)
    record_control_plane_audit(
        db,
        actor=current.user,
        action="USER_SESSIONS_REVOKED",
        target_type="control_plane_user",
        target_id=user.id,
        reason=payload.reason,
        source_ip=request.client.host if request.client else None,
        metadata={"revoked_sessions": revoked},
    )
    db.commit()
    return {"ok": True, "revoked_sessions": revoked}


def _user_or_404(db: Session, user_id: str) -> ControlPlaneUser:
    user = db.get(ControlPlaneUser, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user
