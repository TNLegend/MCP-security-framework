from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Response
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
    InstallSecurityPackPackageRequest,
    SecurityPackActivateVersionRequest,
    SecurityPackCatalogPublic,
    SecurityPackDeprecateVersionRequest,
    SecurityPackLifecycleActionRequest,
    SecurityPackLifecycleCatalogPublic,
    SecurityPackPackageValidationPublic,
    TemplateSuggestionPublic,
    ToolAdapterGuidancePublic,
    TrustedAdapterCatalogPublic,
    ValidateSecurityPackPackageRequest,
    ToolContractDraftPublic,
    ToolReanalysisPublic,
)
from proxy.resource_adapters_v2 import AdapterRegistry
from proxy.tool_security_v2 import SecurityModelError
from proxy.trusted_adapter_packages import build_adapter_starter_archive
from app.services.control_plane_auth import (
    AuthenticatedControlPlaneUser,
    require_admin,
    require_authenticated_user,
)
from app.services.control_plane_config import active_revision
from app.services.published_configuration import validate_config_content
from app.services.security_pack_lifecycle import (
    SecurityPackLifecycleError,
    activate_version,
    configuration_for_validation,
    install_package,
    lifecycle_catalog,
    remove_pack,
    set_enabled,
    set_version_deprecated,
    validate_package,
)
from app.services.security_pack_onboarding import (
    SecurityPackOnboardingError,
    adapter_guidance_for_tool,
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


@router.get("/lifecycle", response_model=SecurityPackLifecycleCatalogPublic)
def list_security_pack_lifecycle(
    draft_revision_id: str | None = None,
    _: AuthenticatedControlPlaneUser = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
):
    content = _configuration_content(db, draft_revision_id)
    if content is None:
        raise HTTPException(status_code=400, detail="published_configuration_required")
    return lifecycle_catalog(content)


@router.get("/adapters", response_model=TrustedAdapterCatalogPublic)
def list_trusted_adapters(
    _: AuthenticatedControlPlaneUser = Depends(require_authenticated_user),
):
    return {
        "sdk_api_version": "1",
        "adapters": AdapterRegistry().catalog(),
    }


@router.get("/adapters/starters/{starter_id}")
def download_trusted_adapter_starter(
    starter_id: str,
    adapter_id: str = Query(pattern=r"^[a-z0-9][a-z0-9._-]{0,127}$"),
    _: AuthenticatedControlPlaneUser = Depends(require_admin),
):
    try:
        archive = build_adapter_starter_archive(starter_id, adapter_id)
    except SecurityModelError as exc:
        raise HTTPException(status_code=400, detail=exc.code) from exc
    return Response(
        content=archive,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{adapter_id}-starter.zip"',
            "X-Content-Type-Options": "nosniff",
        },
    )


@router.post(
    "/lifecycle/validate",
    response_model=SecurityPackPackageValidationPublic,
)
def validate_security_pack_package(
    payload: ValidateSecurityPackPackageRequest,
    _: AuthenticatedControlPlaneUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    try:
        content = configuration_for_validation(db, payload.draft_revision_id)
        return validate_package(payload.package, content=content)
    except SecurityPackLifecycleError as exc:
        raise HTTPException(status_code=400, detail=exc.code) from exc


@router.post(
    "/lifecycle/install",
    response_model=ConfigRevisionPublic,
    status_code=201,
)
def install_security_pack_package(
    payload: InstallSecurityPackPackageRequest,
    current: AuthenticatedControlPlaneUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    try:
        revision = install_package(
            db,
            package=payload.package,
            draft_revision_id=payload.draft_revision_id,
            activate=payload.activate,
            enable=payload.enable,
            actor=current.user,
            change_summary=payload.change_summary,
        )
        db.commit()
        return ConfigRevisionPublic.model_validate(revision)
    except SecurityPackLifecycleError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=exc.code) from exc


@router.post(
    "/lifecycle/{pack_id}/enable",
    response_model=ConfigRevisionPublic,
)
def enable_security_pack(
    pack_id: str,
    payload: SecurityPackLifecycleActionRequest,
    current: AuthenticatedControlPlaneUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    return _set_pack_enabled_route(db, current, pack_id, payload, True)


@router.post(
    "/lifecycle/{pack_id}/disable",
    response_model=ConfigRevisionPublic,
)
def disable_security_pack(
    pack_id: str,
    payload: SecurityPackLifecycleActionRequest,
    current: AuthenticatedControlPlaneUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    return _set_pack_enabled_route(db, current, pack_id, payload, False)


@router.post(
    "/lifecycle/{pack_id}/activate-version",
    response_model=ConfigRevisionPublic,
)
def activate_security_pack_version(
    pack_id: str,
    payload: SecurityPackActivateVersionRequest,
    current: AuthenticatedControlPlaneUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    try:
        revision = activate_version(
            db,
            pack_id=pack_id,
            version=payload.version,
            allow_deprecated=payload.allow_deprecated,
            draft_revision_id=payload.draft_revision_id,
            actor=current.user,
            change_summary=payload.change_summary,
        )
        db.commit()
        return ConfigRevisionPublic.model_validate(revision)
    except SecurityPackLifecycleError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=exc.code) from exc


@router.post(
    "/lifecycle/{pack_id}/deprecate-version",
    response_model=ConfigRevisionPublic,
)
def deprecate_security_pack_version(
    pack_id: str,
    payload: SecurityPackDeprecateVersionRequest,
    current: AuthenticatedControlPlaneUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    try:
        revision = set_version_deprecated(
            db,
            pack_id=pack_id,
            version=payload.version,
            deprecated=payload.deprecated,
            draft_revision_id=payload.draft_revision_id,
            actor=current.user,
            change_summary=payload.change_summary,
        )
        db.commit()
        return ConfigRevisionPublic.model_validate(revision)
    except SecurityPackLifecycleError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=exc.code) from exc


@router.delete(
    "/lifecycle/{pack_id}",
    response_model=ConfigRevisionPublic,
)
def remove_security_pack_installation(
    pack_id: str,
    payload: SecurityPackLifecycleActionRequest,
    current: AuthenticatedControlPlaneUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    try:
        revision = remove_pack(
            db,
            pack_id=pack_id,
            draft_revision_id=payload.draft_revision_id,
            actor=current.user,
            change_summary=payload.change_summary,
        )
        db.commit()
        return ConfigRevisionPublic.model_validate(revision)
    except SecurityPackLifecycleError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=exc.code) from exc


def _set_pack_enabled_route(
    db: Session,
    current: AuthenticatedControlPlaneUser,
    pack_id: str,
    payload: SecurityPackLifecycleActionRequest,
    enabled: bool,
):
    try:
        revision = set_enabled(
            db,
            pack_id=pack_id,
            enabled=enabled,
            draft_revision_id=payload.draft_revision_id,
            actor=current.user,
            change_summary=payload.change_summary,
        )
        db.commit()
        return ConfigRevisionPublic.model_validate(revision)
    except SecurityPackLifecycleError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=exc.code) from exc


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


@router.get(
    "/tools/{tool_id}/adapter-guidance",
    response_model=ToolAdapterGuidancePublic,
)
def tool_adapter_guidance(
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
        return adapter_guidance_for_tool(tool, content=content)
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
