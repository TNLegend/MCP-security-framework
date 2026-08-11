from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models.control_plane import ControlPlaneConfigRevision
from app.schemas.control_plane import (
    ConfigRevisionActionRequest,
    ConfigRevisionPatchRequest,
    ConfigRevisionPublic,
)
from app.services.control_plane_auth import (
    AuthenticatedControlPlaneUser,
    require_admin,
    require_authenticated_user,
)
from app.services.control_plane_config import (
    ControlPlaneConfigError,
    active_revision,
    create_draft_from_revision,
    patch_draft_revision,
    publish_revision,
    rollback_to_revision,
    validate_revision,
)

router = APIRouter(prefix="/control-plane/config", tags=["Control Plane Config"])


@router.get("/revisions", response_model=list[ConfigRevisionPublic])
def list_revisions(
    _: AuthenticatedControlPlaneUser = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
):
    revisions = db.scalars(
        select(ControlPlaneConfigRevision).order_by(
            ControlPlaneConfigRevision.revision_number.desc()
        )
    ).all()
    return [ConfigRevisionPublic.model_validate(revision) for revision in revisions]


@router.get("/active", response_model=ConfigRevisionPublic | None)
def get_active_revision(
    _: AuthenticatedControlPlaneUser = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
):
    revision = active_revision(db)
    return ConfigRevisionPublic.model_validate(revision) if revision else None


@router.get("/revisions/{revision_id}", response_model=ConfigRevisionPublic)
def get_revision(
    revision_id: str,
    _: AuthenticatedControlPlaneUser = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
):
    revision = db.get(ControlPlaneConfigRevision, revision_id)
    if revision is None:
        raise HTTPException(status_code=404, detail="Revision not found")
    return ConfigRevisionPublic.model_validate(revision)


@router.post("/revisions/{published_id}/draft", response_model=ConfigRevisionPublic, status_code=201)
def create_draft(
    published_id: str,
    payload: ConfigRevisionActionRequest,
    current: AuthenticatedControlPlaneUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    try:
        revision = create_draft_from_revision(
            db,
            published_revision_id=published_id,
            actor=current.user,
            change_summary=payload.change_summary,
        )
        db.commit()
        return ConfigRevisionPublic.model_validate(revision)
    except ControlPlaneConfigError as exc:
        raise HTTPException(status_code=400, detail=exc.args[0])


@router.patch("/revisions/{draft_id}", response_model=ConfigRevisionPublic)
def patch_revision(
    draft_id: str,
    payload: ConfigRevisionPatchRequest,
    current: AuthenticatedControlPlaneUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    try:
        revision = patch_draft_revision(
            db,
            draft_id=draft_id,
            content=payload.content,
            actor=current.user,
            change_summary=payload.change_summary,
        )
        db.commit()
        return ConfigRevisionPublic.model_validate(revision)
    except ControlPlaneConfigError as exc:
        raise HTTPException(status_code=400, detail=exc.args[0])
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.post("/revisions/{draft_id}/validate")
def validate_config_revision(
    draft_id: str,
    payload: ConfigRevisionActionRequest,
    current: AuthenticatedControlPlaneUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    try:
        result = validate_revision(
            db,
            revision_id=draft_id,
            actor=current.user,
            change_summary=payload.change_summary,
        )
        db.commit()
        return result
    except ControlPlaneConfigError as exc:
        raise HTTPException(status_code=400, detail=exc.args[0])
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.post("/revisions/{draft_id}/publish", response_model=ConfigRevisionPublic)
def publish_config_revision(
    draft_id: str,
    payload: ConfigRevisionActionRequest,
    current: AuthenticatedControlPlaneUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    try:
        revision = publish_revision(
            db,
            draft_id=draft_id,
            actor=current.user,
            change_summary=payload.change_summary,
        )
        db.commit()
        return ConfigRevisionPublic.model_validate(revision)
    except ControlPlaneConfigError as exc:
        raise HTTPException(status_code=400, detail=exc.args[0])
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.post("/revisions/{revision_id}/rollback", response_model=ConfigRevisionPublic)
def rollback_config_revision(
    revision_id: str,
    payload: ConfigRevisionActionRequest,
    current: AuthenticatedControlPlaneUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    try:
        revision = rollback_to_revision(
            db,
            revision_id=revision_id,
            actor=current.user,
            change_summary=payload.change_summary,
        )
        db.commit()
        return ConfigRevisionPublic.model_validate(revision)
    except ControlPlaneConfigError as exc:
        raise HTTPException(status_code=400, detail=exc.args[0])
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
