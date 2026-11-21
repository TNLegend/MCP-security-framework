from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models.control_plane import ControlPlaneConfigRevision
from app.schemas.control_plane import (
    ConfigPublishRequest,
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
    create_latest_draft,
    create_draft_from_revision,
    delete_inactive_revision,
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


@router.post("/revisions/latest", response_model=ConfigRevisionPublic, status_code=201)
def create_latest_config_draft(
    payload: ConfigRevisionActionRequest,
    current: AuthenticatedControlPlaneUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    revision = create_latest_draft(
        db,
        actor=current.user,
        change_summary=payload.change_summary,
    )
    db.commit()
    return ConfigRevisionPublic.model_validate(revision)


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
            expected_content_hash=payload.expected_content_hash,
        )
        db.commit()
        return ConfigRevisionPublic.model_validate(revision)
    except ControlPlaneConfigError as exc:
        raise HTTPException(
            status_code=409 if str(exc) == "draft_content_changed_conflict" else 400,
            detail=exc.args[0],
        )
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


@router.get("/revisions/{draft_id}/publication-preview")
def config_publication_preview(
    draft_id: str,
    _: AuthenticatedControlPlaneUser = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
):
    """CF-01: read-only diff + impact computed with the publish rules."""
    from app.services.control_plane_publication_preview import preview_publication
    try:
        return preview_publication(db, draft_id)
    except ControlPlaneConfigError as exc:
        raise HTTPException(
            status_code=404 if exc.args[0] == "revision_not_found" else 400,
            detail=exc.args[0],
        )


@router.post("/revisions/{draft_id}/publish", response_model=ConfigRevisionPublic)
def publish_config_revision(
    draft_id: str,
    payload: ConfigPublishRequest,
    current: AuthenticatedControlPlaneUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    try:
        revision = publish_revision(
            db,
            draft_id=draft_id,
            actor=current.user,
            change_summary=payload.change_summary,
            expected_preview_fingerprint=payload.expected_preview_fingerprint,
        )
        db.commit()
        return ConfigRevisionPublic.model_validate(revision)
    except ControlPlaneConfigError as exc:
        error_code = exc.args[0]
        conflict_codes = {"stale_draft_publication_conflict", "draft_active_parent_changed",
                          "publication_preview_stale"}
        raise HTTPException(
            status_code=409 if error_code in conflict_codes else 400,
            detail=error_code,
        )
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


@router.delete("/revisions/{revision_id}", status_code=204)
def delete_config_revision(
    revision_id: str,
    payload: ConfigRevisionActionRequest,
    current: AuthenticatedControlPlaneUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    try:
        delete_inactive_revision(
            db,
            revision_id=revision_id,
            actor=current.user,
            change_summary=payload.change_summary,
        )
        db.commit()
    except ControlPlaneConfigError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=exc.args[0])


# Preparation/decisions are separate from active approvals. All mutation paths
# retain the existing authenticated ADMIN + CSRF dependency.
from typing import Literal
from pydantic import BaseModel, Field, ConfigDict

class AnalyzerMigrationDecisionInput(BaseModel):
    model_config=ConfigDict(extra='forbid')
    observation_id: int = Field(gt=0)
    action: Literal['APPROVE','EXCLUDE']
    reason: str = Field(min_length=12,max_length=2000)
    confirmed: Literal[True]

class AnalyzerMigrationDecisionsInput(BaseModel):
    model_config=ConfigDict(extra='forbid')
    packet_hash: str = Field(pattern=r'^[0-9a-f]{64}$')
    grouped: bool = False
    decisions: list[AnalyzerMigrationDecisionInput] = Field(min_length=1,max_length=10000)

class AnalyzerMigrationActivationInput(BaseModel):
    model_config=ConfigDict(extra='forbid')
    packet_hash: str = Field(pattern=r'^[0-9a-f]{64}$')

@router.post('/analyzer-migrations',status_code=201)
def prepare_analyzer_migration(current: AuthenticatedControlPlaneUser=Depends(require_admin),db: Session=Depends(get_db)):
    from app.services.tda_application.migration import prepare_migration
    try:
        run=prepare_migration(db,admin_id=current.user.id)
        db.commit()
        return {'migration_id':run.id,'state':run.state,'packet_hash':run.packet_hash,'payload':run.payload}
    except ValueError as exc:
        db.rollback();raise HTTPException(status_code=409,detail=str(exc)) from exc

@router.get('/analyzer-migrations/{migration_id}')
def get_analyzer_migration(migration_id: str,current: AuthenticatedControlPlaneUser=Depends(require_admin),db: Session=Depends(get_db)):
    from app.models.analyzer_migration import AnalyzerMigration,AnalyzerMigrationDecision
    from app.services.tda_application.migration import _assert_packet
    run=db.get(AnalyzerMigration,migration_id)
    if run is None:raise HTTPException(status_code=404,detail='migration_not_found')
    try:_assert_packet(run)
    except ValueError as exc:raise HTTPException(status_code=409,detail=str(exc)) from exc
    decisions=db.scalars(select(AnalyzerMigrationDecision).where(AnalyzerMigrationDecision.migration_id==run.id)).all()
    return {'migration_id':run.id,'state':run.state,'packet_hash':run.packet_hash,'payload':run.payload,
            'decisions':[{'decision_id':d.id,'act':d.act,'signature':d.signature,'signature_key_id':d.signature_key_id} for d in decisions]}

@router.post('/analyzer-migrations/{migration_id}/decisions')
def decide_analyzer_migration(migration_id: str,payload: AnalyzerMigrationDecisionsInput,current: AuthenticatedControlPlaneUser=Depends(require_admin),db: Session=Depends(get_db)):
    from app.services.tda_application.migration import decide_migration
    from sqlalchemy.exc import IntegrityError
    try:
        decide_migration(db,migration_id=migration_id,admin_id=current.user.id,packet_hash=payload.packet_hash,
            decisions=[d.model_dump() for d in payload.decisions],grouped=payload.grouped)
        db.commit();return {'migration_id':migration_id,'state':'DECISIONS_RECORDED_NON_ACTIVE'}
    except IntegrityError as exc:
        db.rollback();raise HTTPException(status_code=409,detail='migration_decision_already_recorded') from exc
    except ValueError as exc:
        db.rollback();raise HTTPException(status_code=409,detail=str(exc)) from exc

@router.post('/analyzer-migrations/{migration_id}/activate')
def activate_analyzer_migration(migration_id: str,payload: AnalyzerMigrationActivationInput,current: AuthenticatedControlPlaneUser=Depends(require_admin),db: Session=Depends(get_db)):
    from app.services.tda_application.migration import activate_migration
    try:
        result=activate_migration(db,migration_id=migration_id,admin_id=current.user.id,packet_hash=payload.packet_hash)
        db.commit();return result
    except ValueError as exc:
        db.rollback();raise HTTPException(status_code=409,detail=str(exc)) from exc
