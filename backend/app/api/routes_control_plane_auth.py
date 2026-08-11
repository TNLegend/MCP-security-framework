from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.schemas.control_plane import (
    ChangePasswordRequest,
    ControlPlaneUserPublic,
    LoginRequest,
    LoginResponse,
)
from app.services.control_plane_audit import record_control_plane_audit
from app.services.control_plane_auth import (
    AuthenticatedControlPlaneUser,
    authenticate_user,
    clear_session_cookies,
    create_session,
    hash_password,
    require_authenticated_user,
    revoke_session,
    revoke_user_sessions,
    set_session_cookies,
    verify_password,
)

router = APIRouter(prefix="/control-plane/auth", tags=["Control Plane Auth"])


@router.post("/login", response_model=LoginResponse)
def login(
    payload: LoginRequest,
    response: Response,
    request: Request,
    db: Session = Depends(get_db),
):
    try:
        user = authenticate_user(
            db,
            username=payload.username,
            password=payload.password,
            source_ip=request.client.host if request.client else None,
        )
    except Exception:
        db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    token, csrf_token, session = create_session(db, user=user)
    set_session_cookies(response, token=token, csrf_token=csrf_token)
    record_control_plane_audit(
        db,
        actor=user,
        action="LOGIN_SUCCESS",
        target_type="control_plane_user",
        target_id=user.id,
        source_ip=request.client.host if request.client else None,
    )
    db.commit()
    return LoginResponse(
        user=ControlPlaneUserPublic.model_validate(user),
        csrf_token=csrf_token,
        expires_at=session.expires_at,
    )


@router.post("/logout")
def logout(
    response: Response,
    request: Request,
    current: AuthenticatedControlPlaneUser = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
):
    revoke_session(db, current.session)
    record_control_plane_audit(
        db,
        actor=current.user,
        action="LOGOUT",
        target_type="control_plane_session",
        target_id=current.session.id,
        source_ip=request.client.host if request.client else None,
    )
    clear_session_cookies(response)
    db.commit()
    return {"ok": True}


@router.get("/me", response_model=ControlPlaneUserPublic)
def me(current: AuthenticatedControlPlaneUser = Depends(require_authenticated_user)):
    return ControlPlaneUserPublic.model_validate(current.user)


@router.post("/change-password")
def change_password(
    payload: ChangePasswordRequest,
    current: AuthenticatedControlPlaneUser = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
):
    if not verify_password(payload.current_password, current.user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid password")
    current.user.password_hash = hash_password(payload.new_password)
    revoke_user_sessions(db, current.user.id)
    record_control_plane_audit(
        db,
        actor=current.user,
        action="USER_PASSWORD_RESET",
        target_type="control_plane_user",
        target_id=current.user.id,
        reason="self-service password change",
    )
    db.commit()
    return {"ok": True}
