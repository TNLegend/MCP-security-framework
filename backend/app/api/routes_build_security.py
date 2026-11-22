from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models.build_security import (
    BuildAssessment,
    BuildFinding,
    BuildScannerRun,
    BuildScanRun,
    BuildSourceBinding,
)
from app.schemas.build_security import (
    BuildAssessmentPublic,
    BuildEvidenceDraftRequest,
    BuildFindingPublic,
    BuildGitScanRequest,
    BuildInventoryScanRequest,
    BuildLocalDirectorySelectionPublic,
    BuildLocalScanRequest,
    BuildScanDetailPublic,
    BuildScannerRunPublic,
    BuildScanSourcePublic,
    BuildScanSummaryPublic,
    BuildScannerAvailabilityPublic,
    BuildSourceBindingPublic,
    BuildSourceBindingRequest,
)
from app.schemas.control_plane import ConfigRevisionPublic
from app.services.build_runtime_evidence import (
    BuildEvidenceError,
    attach_scan_evidence_to_draft,
)
from app.services.build_scan_orchestrator import (
    default_build_scanners,
    run_build_security_scan,
)
from app.services.build_target_intake import (
    BuildInventoryLinkError,
    bind_target_to_inventory_server,
    configured_git_workspace,
    configured_inventory_workspace,
    configured_local_target_policy,
    configured_local_workspace,
    get_build_source_binding,
    upsert_build_source_binding,
)
from app.services.control_plane_audit import record_control_plane_audit
from app.services.native_directory_picker import (
    NativeDirectoryPickerError,
    pick_native_local_directory,
)
from app.services.control_plane_auth import (
    AuthenticatedControlPlaneUser,
    require_admin,
    require_authenticated_user,
)
from scanners.contracts import BuildTargetType, ValidatedWorkspace
from scanners.git_targets import validate_git_ref
from scanners.targets import (
    BuildTargetValidationError,
    list_local_subdirectories,
)


router = APIRouter(
    prefix="/control-plane/build-security",
    tags=["Control Plane Build Security"],
)

_MAX_DETAIL_FINDINGS = 500


def _source_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _build_error_status(code: str) -> int:
    if code in {
        "mcp_server_not_found",
        "build_source_binding_not_configured",
    }:
        return 404
    if code in {
        "archived_mcp_server_not_build_scannable",
    }:
        return 409
    return 400


def _raise_target_error(exc: Exception) -> None:
    code = getattr(exc, "code", None) or str(exc) or "build_target_invalid"
    raise HTTPException(status_code=_build_error_status(code), detail=code) from exc


def _summary(scan: BuildScanRun) -> BuildScanSummaryPublic:
    return BuildScanSummaryPublic.model_validate(scan)


def _run_workspace_scan(
    db: Session,
    *,
    workspace: ValidatedWorkspace,
    current: AuthenticatedControlPlaneUser,
    request: Request,
    reason: str,
) -> BuildScanSummaryPublic:
    scan = run_build_security_scan(
        db,
        workspace=workspace,
        requested_by=current.user.id,
    )
    assessment = db.scalar(
        select(BuildAssessment).where(BuildAssessment.build_scan_id == scan.id)
    )
    record_control_plane_audit(
        db,
        actor=current.user,
        action="BUILD_SECURITY_SCAN_COMPLETED",
        target_type="build_scan",
        target_id=scan.id,
        source_ip=_source_ip(request),
        reason=reason,
        after_json={
            "target_type": scan.target_type,
            "linked_server_id": scan.linked_server_id,
            "source_revision": scan.source_revision,
            "source_fingerprint": scan.source_fingerprint,
            "scan_status": scan.status,
            "assessment_status": assessment.status if assessment else None,
            "required_scanners_complete": (
                assessment.required_scanners_complete if assessment else False
            ),
        },
    )
    db.commit()
    db.refresh(scan)
    return _summary(scan)


def _with_optional_server_binding(
    db: Session,
    workspace: ValidatedWorkspace,
    server_id: int | None,
    *,
    requested_ref: str | None = None,
) -> ValidatedWorkspace:
    if server_id is None:
        return workspace

    binding = get_build_source_binding(db, server_id=server_id)
    target = workspace.target
    if binding.target_type != target.target_type.value:
        raise BuildInventoryLinkError("build_source_binding_mismatch")

    if target.target_type == BuildTargetType.LOCAL_DIRECTORY:
        try:
            target_locator = str(Path(target.source_locator).resolve(strict=True))
            binding_locator = str(Path(binding.source_locator).resolve(strict=True))
        except (OSError, RuntimeError) as exc:
            raise BuildInventoryLinkError("build_source_binding_mismatch") from exc
        if target_locator != binding_locator or binding.source_ref is not None:
            raise BuildInventoryLinkError("build_source_binding_mismatch")
    elif target.target_type == BuildTargetType.GIT_REPOSITORY:
        if target.source_locator != binding.source_locator:
            raise BuildInventoryLinkError("build_source_binding_mismatch")
        try:
            normalized_ref = validate_git_ref(requested_ref)
        except BuildTargetValidationError as exc:
            raise BuildInventoryLinkError("build_source_binding_mismatch") from exc
        if normalized_ref != binding.source_ref:
            raise BuildInventoryLinkError("build_source_binding_mismatch")
    else:
        raise BuildInventoryLinkError("unsupported_build_source_type")

    target = bind_target_to_inventory_server(
        db,
        target=target,
        server_id=server_id,
    )
    return replace(workspace, target=target)


@router.get(
    "/scanners",
    response_model=list[BuildScannerAvailabilityPublic],
)
def build_scanner_availability(
    _: AuthenticatedControlPlaneUser = Depends(require_authenticated_user),
):
    result: list[BuildScannerAvailabilityPublic] = []
    for registration in default_build_scanners():
        availability = registration.scanner.probe()
        result.append(
            BuildScannerAvailabilityPublic(
                scanner_id=availability.scanner_id,
                available=availability.available,
                version=availability.version,
                reason_code=availability.reason_code,
            )
        )
    return result


@router.post(
    "/targets/local/pick-directory",
    response_model=BuildLocalDirectorySelectionPublic,
)
def pick_local_scan_directory(
    _: AuthenticatedControlPlaneUser = Depends(require_admin),
):
    policy = configured_local_target_policy()
    initial_directory = policy.allowed_roots[0] if policy.allowed_roots else None
    try:
        selected = pick_native_local_directory(initial_directory=initial_directory)
    except NativeDirectoryPickerError as exc:
        _raise_target_error(exc)

    if selected is None:
        return BuildLocalDirectorySelectionPublic(selected=False)

    try:
        current, _ = list_local_subdirectories(selected, policy=policy)
    except BuildTargetValidationError as exc:
        _raise_target_error(exc)

    return BuildLocalDirectorySelectionPublic(
        selected=True,
        path=str(current),
        name=current.name or str(current),
    )


@router.get(
    "/inventory/sources",
    response_model=list[BuildSourceBindingPublic],
)
def list_inventory_build_sources(
    limit: int = Query(default=1000, ge=1, le=5000),
    offset: int = Query(default=0, ge=0, le=10_000),
    _: AuthenticatedControlPlaneUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    bindings = db.scalars(
        select(BuildSourceBinding)
        .order_by(BuildSourceBinding.server_id.asc())
        .offset(offset)
        .limit(limit)
    ).all()
    return [BuildSourceBindingPublic.model_validate(binding) for binding in bindings]


@router.get(
    "/scan-sources",
    response_model=list[BuildScanSourcePublic],
)
def list_build_scan_sources(
    limit: int = Query(default=500, ge=1, le=500),
    offset: int = Query(default=0, ge=0, le=10_000),
    _: AuthenticatedControlPlaneUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    scans = db.scalars(
        select(BuildScanRun)
        .order_by(BuildScanRun.created_at.desc(), BuildScanRun.id.desc())
        .offset(offset)
        .limit(limit)
    ).all()
    return [
        BuildScanSourcePublic(
            scan_id=scan.id,
            target_type=scan.target_type,
            source_locator=scan.source_locator,
            source_revision=scan.source_revision,
            linked_server_id=scan.linked_server_id,
        )
        for scan in scans
    ]


@router.get(
    "/inventory/{server_id}/source",
    response_model=BuildSourceBindingPublic,
)
def read_inventory_build_source(
    server_id: int,
    _: AuthenticatedControlPlaneUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    try:
        binding = get_build_source_binding(db, server_id=server_id)
    except BuildInventoryLinkError as exc:
        _raise_target_error(exc)
    return BuildSourceBindingPublic.model_validate(binding)


@router.put(
    "/inventory/{server_id}/source",
    response_model=BuildSourceBindingPublic,
)
def configure_inventory_build_source(
    server_id: int,
    payload: BuildSourceBindingRequest,
    request: Request,
    current: AuthenticatedControlPlaneUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    before = None
    try:
        existing = get_build_source_binding(db, server_id=server_id)
        before = {
            "target_type": existing.target_type,
            "source_ref": existing.source_ref,
        }
    except BuildInventoryLinkError as exc:
        if exc.code not in {"build_source_binding_not_configured"}:
            _raise_target_error(exc)

    try:
        binding = upsert_build_source_binding(
            db,
            server_id=server_id,
            target_type=BuildTargetType(payload.target_type),
            source_locator=payload.source_locator,
            source_ref=payload.source_ref,
            actor_user_id=current.user.id,
        )
        record_control_plane_audit(
            db,
            actor=current.user,
            action="BUILD_SOURCE_BINDING_UPSERTED",
            target_type="mcp_server",
            target_id=str(server_id),
            source_ip=_source_ip(request),
            reason=payload.reason,
            before_json=before,
            after_json={
                "target_type": binding.target_type,
                "source_ref": binding.source_ref,
            },
        )
        db.commit()
        db.refresh(binding)
        return BuildSourceBindingPublic.model_validate(binding)
    except (BuildInventoryLinkError, BuildTargetValidationError) as exc:
        db.rollback()
        _raise_target_error(exc)


@router.post(
    "/scans/local",
    response_model=BuildScanSummaryPublic,
    status_code=201,
)
def scan_local_source(
    payload: BuildLocalScanRequest,
    request: Request,
    current: AuthenticatedControlPlaneUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    try:
        with configured_local_workspace(
            payload.source_locator,
            display_name=payload.display_name,
        ) as workspace:
            bound = _with_optional_server_binding(
                db,
                workspace,
                payload.linked_server_id,
            )
            return _run_workspace_scan(
                db,
                workspace=bound,
                current=current,
                request=request,
                reason=payload.reason,
            )
    except (BuildInventoryLinkError, BuildTargetValidationError) as exc:
        db.rollback()
        record_control_plane_audit(
            db,
            actor=current.user,
            action="BUILD_SECURITY_SCAN_REJECTED",
            target_type="build_target",
            source_ip=_source_ip(request),
            reason=payload.reason,
            result="FAILED",
            metadata={
                "target_type": BuildTargetType.LOCAL_DIRECTORY.value,
                "linked_server_id": payload.linked_server_id,
                "error_code": getattr(exc, "code", str(exc)),
            },
        )
        db.commit()
        _raise_target_error(exc)


@router.post(
    "/scans/git",
    response_model=BuildScanSummaryPublic,
    status_code=201,
)
def scan_git_source(
    payload: BuildGitScanRequest,
    request: Request,
    current: AuthenticatedControlPlaneUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    try:
        with configured_git_workspace(
            payload.repository_url,
            requested_ref=payload.source_ref,
            display_name=payload.display_name,
        ) as workspace:
            bound = _with_optional_server_binding(
                db,
                workspace,
                payload.linked_server_id,
                requested_ref=payload.source_ref,
            )
            return _run_workspace_scan(
                db,
                workspace=bound,
                current=current,
                request=request,
                reason=payload.reason,
            )
    except (BuildInventoryLinkError, BuildTargetValidationError) as exc:
        db.rollback()
        record_control_plane_audit(
            db,
            actor=current.user,
            action="BUILD_SECURITY_SCAN_REJECTED",
            target_type="build_target",
            source_ip=_source_ip(request),
            reason=payload.reason,
            result="FAILED",
            metadata={
                "target_type": BuildTargetType.GIT_REPOSITORY.value,
                "linked_server_id": payload.linked_server_id,
                "error_code": getattr(exc, "code", str(exc)),
            },
        )
        db.commit()
        _raise_target_error(exc)


@router.post(
    "/scans/inventory/{server_id}",
    response_model=BuildScanSummaryPublic,
    status_code=201,
)
def scan_inventory_source(
    server_id: int,
    payload: BuildInventoryScanRequest,
    request: Request,
    current: AuthenticatedControlPlaneUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    try:
        with configured_inventory_workspace(db, server_id=server_id) as workspace:
            return _run_workspace_scan(
                db,
                workspace=workspace,
                current=current,
                request=request,
                reason=payload.reason,
            )
    except (BuildInventoryLinkError, BuildTargetValidationError) as exc:
        db.rollback()
        record_control_plane_audit(
            db,
            actor=current.user,
            action="BUILD_SECURITY_SCAN_REJECTED",
            target_type="mcp_server",
            target_id=str(server_id),
            source_ip=_source_ip(request),
            reason=payload.reason,
            result="FAILED",
            metadata={
                "error_code": getattr(exc, "code", str(exc)),
            },
        )
        db.commit()
        _raise_target_error(exc)


@router.post(
    "/scans/{scan_id}/attach-to-draft",
    response_model=ConfigRevisionPublic,
)
def attach_build_scan_to_draft(
    scan_id: str,
    payload: BuildEvidenceDraftRequest,
    request: Request,
    current: AuthenticatedControlPlaneUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    try:
        revision = attach_scan_evidence_to_draft(
            db,
            scan_id=scan_id,
            draft_revision_id=payload.draft_revision_id,
            mode=payload.mode,
            max_evidence_age_hours=payload.max_evidence_age_hours,
            actor=current.user,
            change_summary=payload.reason,
        )
        record_control_plane_audit(
            db,
            actor=current.user,
            action="BUILD_EVIDENCE_ATTACHED_TO_DRAFT",
            target_type="control_plane_config_revision",
            target_id=revision.id,
            revision_id=revision.id,
            source_ip=_source_ip(request),
            reason=payload.reason,
            after_json={
                "scan_id": scan_id,
                "build_security_mode": payload.mode,
                "max_evidence_age_hours": payload.max_evidence_age_hours,
            },
        )
        db.commit()
        db.refresh(revision)
        return ConfigRevisionPublic.model_validate(revision)
    except BuildEvidenceError as exc:
        db.rollback()
        code = exc.code
        if code in {"build_scan_not_found", "revision_not_found"}:
            status_code = 404
        elif code in {
            "build_scan_not_terminal",
            "build_scan_not_inventory_linked",
            "build_scan_terminal_state_inconsistent",
            "build_scan_server_archived",
            "build_evidence_requires_draft",
        }:
            status_code = 409
        else:
            status_code = 400
        raise HTTPException(status_code=status_code, detail=code) from exc


@router.get(
    "/scans",
    response_model=list[BuildScanSummaryPublic],
)
def list_build_scans(
    status: str | None = Query(default=None, max_length=32),
    server_id: int | None = Query(default=None, ge=1),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0, le=10_000),
    _: AuthenticatedControlPlaneUser = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
):
    query = select(BuildScanRun)
    if status is not None:
        normalized_status = status.strip().upper()
        if normalized_status not in {"PENDING", "RUNNING", "COMPLETED", "FAILED"}:
            raise HTTPException(status_code=400, detail="build_scan_status_invalid")
        query = query.where(BuildScanRun.status == normalized_status)
    if server_id is not None:
        query = query.where(BuildScanRun.linked_server_id == server_id)
    scans = db.scalars(
        query.order_by(BuildScanRun.created_at.desc(), BuildScanRun.id.desc())
        .offset(offset)
        .limit(limit)
    ).all()
    return [_summary(scan) for scan in scans]


_FINDING_SEVERITY_RANK = case(
    (BuildFinding.severity == "CRITICAL", 5),
    (BuildFinding.severity == "HIGH", 4),
    (BuildFinding.severity == "MEDIUM", 3),
    (BuildFinding.severity == "LOW", 2),
    (BuildFinding.severity == "INFO", 1),
    else_=0,
)
_FINDING_SEVERITIES = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
_FINDING_STATES = {"NEW", "UNCHANGED", "RESOLVED", "REGRESSED"}


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


@router.get("/scans/{scan_id}/findings")
def page_build_scan_findings(
    scan_id: str,
    offset: int = Query(default=0, ge=0, le=1_000_000),
    limit: int = Query(default=50, ge=1, le=200),
    finding_id: str | None = Query(default=None, max_length=36),
    severity: str | None = Query(default=None, max_length=16),
    finding_state: str | None = Query(default=None, max_length=16),
    scanner_id: str | None = Query(default=None, max_length=64),
    rule_id: str | None = Query(default=None, max_length=255),
    path: str | None = Query(default=None, max_length=512),
    _: AuthenticatedControlPlaneUser = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
):
    """UX-09: every stored finding is reachable, beyond the 500-row detail cap.

    Stable server ordering (severity, scanner, path, line, then id) and a
    total computed by the same WHERE clause as the page. Returns exactly the
    same public finding shape as the detail endpoint, so role disclosure is
    unchanged (the absolute source binding stays admin-only elsewhere).
    """
    scan = db.get(BuildScanRun, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="build_scan_not_found")
    filters = [BuildFinding.build_scan_id == scan.id]
    applied: dict[str, str] = {}
    if finding_id:
        filters.append(BuildFinding.id == finding_id.strip())
        applied["finding_id"] = finding_id.strip()
    if severity:
        normalized = severity.strip().upper()
        if normalized not in _FINDING_SEVERITIES:
            raise HTTPException(status_code=422, detail="build_finding_severity_invalid")
        filters.append(BuildFinding.severity == normalized)
        applied["severity"] = normalized
    if finding_state:
        normalized = finding_state.strip().upper()
        if normalized not in _FINDING_STATES:
            raise HTTPException(status_code=422, detail="build_finding_state_invalid")
        filters.append(BuildFinding.finding_state == normalized)
        applied["finding_state"] = normalized
    if scanner_id:
        filters.append(BuildFinding.scanner_id == scanner_id.strip())
        applied["scanner_id"] = scanner_id.strip()
    if rule_id:
        filters.append(BuildFinding.rule_id == rule_id.strip())
        applied["rule_id"] = rule_id.strip()
    if path:
        filters.append(BuildFinding.file_path.like("%" + _escape_like(path.strip()) + "%", escape="\\"))
        applied["path"] = path.strip()
    total = int(db.scalar(select(func.count(BuildFinding.id)).where(*filters)) or 0)
    unfiltered_total = int(db.scalar(
        select(func.count(BuildFinding.id)).where(BuildFinding.build_scan_id == scan.id)
    ) or 0)
    rows = db.scalars(
        select(BuildFinding).where(*filters)
        .order_by(_FINDING_SEVERITY_RANK.desc(), BuildFinding.scanner_id.asc(),
                  BuildFinding.file_path.asc(), BuildFinding.line_start.asc(), BuildFinding.id.asc())
        .offset(offset).limit(limit)
    ).all()
    return {
        "scope": "PERSISTED_SCAN_FINDINGS",
        "items": [BuildFindingPublic.model_validate(row).model_dump(mode="json") for row in rows],
        "total": total,
        "unfiltered_total": unfiltered_total,
        "offset": offset,
        "limit": limit,
        "returned": len(rows),
        "has_more": offset + len(rows) < total,
        "filters": applied,
    }


@router.get(
    "/scans/{scan_id}",
    response_model=BuildScanDetailPublic,
)
def get_build_scan(
    scan_id: str,
    _: AuthenticatedControlPlaneUser = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
):
    scan = db.get(BuildScanRun, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="build_scan_not_found")

    scanner_runs = db.scalars(
        select(BuildScannerRun)
        .where(BuildScannerRun.build_scan_id == scan.id)
        .order_by(BuildScannerRun.scanner_id.asc())
        .limit(50)
    ).all()

    finding_total = db.scalar(
        select(func.count(BuildFinding.id)).where(
            BuildFinding.build_scan_id == scan.id
        )
    ) or 0
    findings = db.scalars(
        select(BuildFinding)
        .where(BuildFinding.build_scan_id == scan.id)
        .order_by(
            case(
                (BuildFinding.severity == "CRITICAL", 5),
                (BuildFinding.severity == "HIGH", 4),
                (BuildFinding.severity == "MEDIUM", 3),
                (BuildFinding.severity == "LOW", 2),
                (BuildFinding.severity == "INFO", 1),
                else_=0,
            ).desc(),
            BuildFinding.scanner_id.asc(),
            BuildFinding.file_path.asc(),
            BuildFinding.line_start.asc(),
        )
        .limit(_MAX_DETAIL_FINDINGS)
    ).all()
    assessment = db.scalar(
        select(BuildAssessment).where(BuildAssessment.build_scan_id == scan.id)
    )

    return BuildScanDetailPublic(
        scan=_summary(scan),
        scanner_runs=[
            BuildScannerRunPublic.model_validate(item) for item in scanner_runs
        ],
        findings=[BuildFindingPublic.model_validate(item) for item in findings],
        finding_total=int(finding_total),
        findings_truncated=int(finding_total) > len(findings),
        assessment=(
            BuildAssessmentPublic.model_validate(assessment)
            if assessment is not None
            else None
        ),
    )
