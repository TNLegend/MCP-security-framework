from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models.control_plane import ControlPlaneConfigRevision
from app.models.mcp_tool import MCPTool
from app.schemas.control_plane import ConfigRevisionPublic
from app.schemas.security_pack import (
    AddDeclarativeSecurityPackRequest,
    AISecurityPackDraftPublic,
    AITemplateSuggestionPublic,
    CreateToolContractDraftRequest,
    CreateToolSecurityPackDraftRequest,
    SecurityPackCatalogPublic,
    TemplateSuggestionPublic,
    ToolContractDraftPublic,
    ToolReanalysisPublic,
)
from app.services.control_plane_auth import (
    AuthenticatedControlPlaneUser,
    require_admin,
    require_authenticated_user,
)
from app.services.control_plane_config import active_revision
from app.services.published_configuration import validate_config_content
from app.services.security_pack_onboarding import (
    SecurityPackOnboardingError,
    add_declarative_security_pack,
    create_tool_security_pack_draft,
    create_tool_contract_draft,
    reanalyze_tool_with_published_contract,
    security_pack_catalog,
    suggest_security_pack_with_ai,
    suggest_template_with_ai,
    suggest_templates_for_tool,
)


router = APIRouter(
    prefix="/control-plane/security-packs",
    tags=["Control Plane Security Packs"],
)


@router.get("", response_model=SecurityPackCatalogPublic)
def list_security_packs(
    draft_revision_id: str | None = None,
    _: AuthenticatedControlPlaneUser = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
):
    content = _configuration_content(db, draft_revision_id)
    return security_pack_catalog(content)


@router.get(
    "/tools/{tool_id}/suggestions",
    response_model=list[TemplateSuggestionPublic],
)
def tool_template_suggestions(
    tool_id: int,
    draft_revision_id: str | None = None,
    _: AuthenticatedControlPlaneUser = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
):
    tool = db.get(MCPTool, tool_id)
    if tool is None:
        raise HTTPException(status_code=404, detail="Tool not found")
    content = _configuration_content(db, draft_revision_id)
    try:
        return suggest_templates_for_tool(tool, content=content)
    except SecurityPackOnboardingError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post(
    "/tools/{tool_id}/ai-suggestion",
    response_model=AITemplateSuggestionPublic,
)
def tool_ai_template_suggestion(
    tool_id: int,
    draft_revision_id: str | None = None,
    _: AuthenticatedControlPlaneUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    tool = db.get(MCPTool, tool_id)
    if tool is None:
        raise HTTPException(status_code=404, detail="Tool not found")
    content = _configuration_content(db, draft_revision_id)
    try:
        return suggest_template_with_ai(tool, content=content)
    except SecurityPackOnboardingError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.post(
    "/tools/{tool_id}/ai-pack-draft",
    response_model=AISecurityPackDraftPublic,
)
def tool_ai_security_pack_draft(
    tool_id: int,
    draft_revision_id: str | None = None,
    _: AuthenticatedControlPlaneUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    tool = db.get(MCPTool, tool_id)
    if tool is None:
        raise HTTPException(status_code=404, detail="Tool not found")
    content = _configuration_content(db, draft_revision_id)
    try:
        return suggest_security_pack_with_ai(tool, content=content)
    except SecurityPackOnboardingError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.post(
    "/tools/{tool_id}/packs/draft",
    response_model=ConfigRevisionPublic,
    status_code=201,
)
def draft_tool_security_pack(
    tool_id: int,
    payload: CreateToolSecurityPackDraftRequest,
    current: AuthenticatedControlPlaneUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    tool = db.get(MCPTool, tool_id)
    if tool is None:
        raise HTTPException(status_code=404, detail="Tool not found")
    try:
        revision = create_tool_security_pack_draft(
            db,
            tool=tool,
            manifest=payload.manifest,
            draft_revision_id=payload.draft_revision_id,
            actor=current.user,
            change_summary=payload.change_summary,
        )
        db.commit()
        return ConfigRevisionPublic.model_validate(revision)
    except SecurityPackOnboardingError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post(
    "/tools/{tool_id}/contracts/draft",
    response_model=ToolContractDraftPublic,
    status_code=201,
)
def draft_tool_contract(
    tool_id: int,
    payload: CreateToolContractDraftRequest,
    current: AuthenticatedControlPlaneUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    tool = db.get(MCPTool, tool_id)
    if tool is None:
        raise HTTPException(status_code=404, detail="Tool not found")
    try:
        result = create_tool_contract_draft(
            db,
            tool=tool,
            payload=payload,
            actor=current.user,
        )
        db.commit()
        return result
    except SecurityPackOnboardingError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post(
    "/tools/{tool_id}/reanalyze",
    response_model=ToolReanalysisPublic,
)
def reanalyze_tool_contract(
    tool_id: int,
    current: AuthenticatedControlPlaneUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    tool = db.get(MCPTool, tool_id)
    if tool is None:
        raise HTTPException(status_code=404, detail="Tool not found")
    try:
        result = reanalyze_tool_with_published_contract(
            db,
            tool=tool,
            actor=current.user,
        )
        db.commit()
        return result
    except SecurityPackOnboardingError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post(
    "/declarative",
    response_model=ConfigRevisionPublic,
    status_code=201,
)
def add_declarative_pack(
    payload: AddDeclarativeSecurityPackRequest,
    current: AuthenticatedControlPlaneUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    try:
        revision = add_declarative_security_pack(
            db,
            draft_revision_id=payload.draft_revision_id,
            manifest=payload.manifest,
            actor=current.user,
            change_summary=payload.change_summary,
        )
        db.commit()
        return ConfigRevisionPublic.model_validate(revision)
    except SecurityPackOnboardingError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def _configuration_content(db: Session, draft_revision_id: str | None):
    if draft_revision_id:
        revision = db.get(ControlPlaneConfigRevision, draft_revision_id)
        if revision is None or revision.status != "DRAFT" or revision.schema_version != 2:
            raise HTTPException(status_code=400, detail="v2_draft_required")
    else:
        revision = active_revision(db)
    return validate_config_content(revision.content) if revision else None
