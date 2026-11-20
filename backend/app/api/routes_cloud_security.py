"""Authenticated Cloud Security API. Only ADMIN can configure or run audits."""
from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models.cloud_security import (
    CloudEnvironment, CloudEvidence, CloudFinding, CloudResource, CloudScan,
    CloudScanEvent, CloudIAMComparison, CloudIAMMapping, new_id,
)
from app.schemas.cloud_security import (
    ConnectionTestPublic, EnvironmentCreate, EnvironmentPublic,
    EvidencePublic, FindingPublic, ResourcePublic, ScanDetailPublic,
    ScanEventPublic, ScanPublic, IAMComparisonRequest, IAMComparisonPublic,
    IAMMappingCreate, IAMMappingApprove, IAMMappingPublic,
)
from app.services.cloud_security import (
    CloudAuditError, _safe_error, check_connection, enqueue_scan,
)
from app.services.cloud_iac_security import (
    IaCIntakeError, IAC_VERSION, MAX_ZIP_BYTES, discard_source,
    enqueue_iac, scanner_availability, stage_archive,
)
from app.services.cloud_prowler_security import (
    PROWLER_SCAN_VERSION, availability as prowler_availability,
    enqueue_advanced, engine_version as prowler_engine_version,
    permission_preview,
)
from app.services.cloud_iam_mcp_security import VERSION as IAM_MCP_VERSION, enqueue_comparison
from app.services.cloud_iam_mapping import (
    MappingError, context_for_server, compile_expectations,
    mapping_digest, verify_approved_mapping,
)
from app.services.published_configuration import PublishedConfigurationProvider
from app.models.mcp_server import MCPServer
from app.services.cloud_deploy_governance import (
    DeployGovernanceError, build_deploy_iam_governance_input,
)
from app.services.cloud_deploy_scan_governance import (
    build_deploy_cloud_governance_input,
)
from app.services.cloud_deploy_history import (
    DeployHistoryError, _hash as governance_digest, list_deploy_decisions,
    list_exception_history, record_deploy_decision, record_exception_event,
)
from app.services.cloud_deploy_opa_client import (
    DeployAdvisoryDecision, DeployOPAClient, DeployOPAError,
)
from app.core.config import settings
from app.services.control_plane_audit import record_control_plane_audit
from app.services.control_plane_auth import (
    AuthenticatedControlPlaneUser, require_admin, require_authenticated_user,
)

router=APIRouter(prefix="/control-plane/cloud-security",tags=["Cloud Security"])


def _env(db: Session, env_id: str) -> CloudEnvironment:
    value=db.get(CloudEnvironment,env_id)
    if value is None:
        raise HTTPException(status_code=404,detail="cloud_environment_not_found")
    return value


def _scan(db: Session, scan_id: str) -> CloudScan:
    item=db.get(CloudScan,scan_id)
    if item is None:
        raise HTTPException(status_code=404,detail="cloud_scan_not_found")
    return item


def _audit(db,request,actor,action,target_type,target_id,after):
    record_control_plane_audit(
        db,actor=actor.user,action=action,target_type=target_type,target_id=target_id,
        source_ip=request.client.host if request.client else None,after_json=after,
    )


@router.get("/environments",response_model=list[EnvironmentPublic])
def list_environments(
    _: AuthenticatedControlPlaneUser=Depends(require_authenticated_user),
    db:Session=Depends(get_db),
):
    return db.scalars(select(CloudEnvironment)
                      .order_by(CloudEnvironment.created_at.desc()).limit(100)).all()


@router.post("/environments",response_model=EnvironmentPublic,status_code=201)
def create_environment(
    payload:EnvironmentCreate,request:Request,
    actor:AuthenticatedControlPlaneUser=Depends(require_admin),
    db:Session=Depends(get_db),
):
    env=CloudEnvironment(
        name=payload.name,provider="AWS",regions=payload.regions,services=payload.services,
        credential_mode=payload.credential_mode,profile_name=payload.profile_name,
        role_arn=payload.role_arn,created_by=actor.user.id,
    )
    db.add(env)
    try:
        db.flush()
        _audit(db,request,actor,"CLOUD_ENVIRONMENT_CREATED","cloud_environment",
               env.id,{"name":env.name,"regions":env.regions,"services":env.services,
                       "credential_mode":env.credential_mode})
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409,detail="cloud_environment_name_exists") from exc
    db.refresh(env)
    return env


@router.patch("/environments/{environment_id}",response_model=EnvironmentPublic)
def update_environment(
    environment_id: str,
    payload: EnvironmentCreate,
    request: Request,
    actor: AuthenticatedControlPlaneUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Change an AWS credential reference without losing the audit history.

    Updates are serialized against starting a scan for this environment.
    Any meaningful connection change must be reverified before the next scan.
    """
    env = db.scalar(
        select(CloudEnvironment).where(CloudEnvironment.id == environment_id)
        .with_for_update()
    )
    if env is None:
        raise HTTPException(status_code=404,detail="cloud_environment_not_found")
    active = db.scalar(select(CloudScan.id).where(
        CloudScan.environment_id == env.id,
        CloudScan.status.in_(("QUEUED", "RUNNING")),
    ).limit(1))
    if active is not None:
        raise HTTPException(status_code=409,detail="cloud_scan_already_active")
    new_values = {
        "name": payload.name,
        "regions": payload.regions,
        "services": payload.services,
        "credential_mode": payload.credential_mode,
        "profile_name": payload.profile_name,
        "role_arn": payload.role_arn,
    }
    changed_keys = sorted(k for k, v in new_values.items() if getattr(env,k) != v)
    changed = bool(changed_keys)
    connection_changed = any(
        getattr(env, k) != new_values[k] for k in
        ("regions", "credential_mode", "profile_name", "role_arn")
    )
    for k,v in new_values.items():
        setattr(env,k,v)
    if connection_changed:
        env.account_id = None
        env.status = "UNVERIFIED"
        env.last_error_code = None
        env.last_checked_at = None
    try:
        if changed:
            _audit(db,request,actor,"CLOUD_ENVIRONMENT_UPDATED","cloud_environment",
                   env.id,{"fields_changed":changed_keys,
                           "connection_reverification_required":connection_changed})
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409,detail="cloud_environment_name_exists") from exc
    db.refresh(env)
    return env


@router.post("/environments/{environment_id}/test",response_model=ConnectionTestPublic)
def test_environment(
    environment_id:str,request:Request,
    actor:AuthenticatedControlPlaneUser=Depends(require_admin),
    db:Session=Depends(get_db),
):
    env=_env(db,environment_id)
    try:
        _,account,caller_type=check_connection(env)
    except CloudAuditError as exc:
        code=str(exc)
    except Exception as exc:
        code=_safe_error(exc)
    else:
        env.account_id=account
        env.status="CONNECTED"
        env.last_error_code=None
        env.last_checked_at=datetime.utcnow()
        _audit(db,request,actor,"CLOUD_CONNECTION_TESTED","cloud_environment",
               env.id,{"result":"CONNECTED","account_id":account})
        db.commit()
        return ConnectionTestPublic(status="CONNECTED",account_id=account,
                                    caller_type=caller_type,regions=env.regions)
    env.status="FAILED"
    env.last_error_code=code[:80]
    env.last_checked_at=datetime.utcnow()
    _audit(db,request,actor,"CLOUD_CONNECTION_TEST_FAILED","cloud_environment",
           env.id,{"reason_code":code[:80]})
    db.commit()
    raise HTTPException(status_code=400,detail=code)


@router.post("/environments/{environment_id}/scans",response_model=ScanPublic,status_code=202)
def start_scan(
    environment_id:str,request:Request,
    actor:AuthenticatedControlPlaneUser=Depends(require_admin),
    db:Session=Depends(get_db),
):
    # Serialize concurrent requests for a specific environment using PostgreSQL.
    env=db.scalar(select(CloudEnvironment).where(CloudEnvironment.id==environment_id)
                  .with_for_update())
    if env is None:
        raise HTTPException(status_code=404,detail="cloud_environment_not_found")
    if env.status!="CONNECTED" or not env.account_id:
        raise HTTPException(status_code=409,detail="cloud_connection_not_verified")
    active=db.scalar(select(CloudScan.id).where(
        CloudScan.environment_id==env.id,
        CloudScan.status.in_(("QUEUED","RUNNING"))).limit(1))
    if active is not None:
        raise HTTPException(status_code=409,detail="cloud_scan_already_active")
    scan=CloudScan(environment_id=env.id,requested_by=actor.user.id,
                   status="QUEUED",kind="AWS_BASELINE")
    db.add(scan)
    db.flush()
    db.add(CloudScanEvent(scan_id=scan.id,event_type="STATE",message_code="QUEUED"))
    _audit(db,request,actor,"CLOUD_SCAN_REQUESTED","cloud_scan",
           scan.id,{"environment_id":env.id,"kind":"AWS_BASELINE"})
    db.commit()
    if not enqueue_scan(scan.id):
        scan.status="FAILED"
        scan.error_code="CLOUD_WORKER_BUSY"
        scan.completed_at=datetime.utcnow()
        db.add(CloudScanEvent(scan_id=scan.id,event_type="STATE",
                              message_code="WORKER_BUSY"))
        db.commit()
        raise HTTPException(status_code=503,detail="cloud_worker_busy")
    db.refresh(scan)
    return scan


@router.get("/environments/{environment_id}/advanced/permissions")
def advanced_permission_preview(
    environment_id: str,
    _: AuthenticatedControlPlaneUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    env = _env(db, environment_id)
    if env.status != "CONNECTED" or not env.account_id:
        raise HTTPException(status_code=409, detail="cloud_connection_not_verified")
    try:
        return permission_preview(env)
    except CloudAuditError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=400, detail=_safe_error(exc)) from exc


@router.get("/advanced/scanner")
def prowler_scanner_status(
    _: AuthenticatedControlPlaneUser = Depends(require_authenticated_user),
):
    return prowler_availability()


@router.post(
    "/environments/{environment_id}/advanced-scans",
    response_model=ScanPublic, status_code=202,
)
def start_advanced_scan(
    environment_id: str,
    request: Request,
    actor: AuthenticatedControlPlaneUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    env = db.scalar(select(CloudEnvironment)
                    .where(CloudEnvironment.id == environment_id)
                    .with_for_update())
    if env is None:
        raise HTTPException(status_code=404, detail="cloud_environment_not_found")
    if env.status != "CONNECTED" or not env.account_id:
        raise HTTPException(status_code=409, detail="cloud_connection_not_verified")
    if not env.role_arn:
        raise HTTPException(status_code=409, detail="prowler_audit_role_required")
    if prowler_engine_version() is None:
        raise HTTPException(status_code=503, detail="prowler_not_installed")
    active = db.scalar(select(CloudScan.id).where(
        CloudScan.environment_id == env.id,
        CloudScan.status.in_(("QUEUED", "RUNNING")),
    ).limit(1))
    if active is not None:
        raise HTTPException(status_code=409, detail="cloud_scan_already_active")
    scan = CloudScan(
        id=new_id(), environment_id=env.id, kind="AWS_ADVANCED",
        status="QUEUED", scanner_version=PROWLER_SCAN_VERSION,
        requested_by=actor.user.id,
    )
    db.add(scan)
    db.flush()
    db.add(CloudScanEvent(scan_id=scan.id, event_type="STATE", message_code="QUEUED"))
    _audit(db, request, actor, "CLOUD_ADVANCED_SCAN_REQUESTED",
           "cloud_scan", scan.id, {"environment_id": env.id,
                                   "kind": "AWS_ADVANCED"})
    db.commit()
    if not enqueue_advanced(scan.id):
        scan.status = "FAILED"
        scan.error_code = "CLOUD_WORKER_BUSY"
        scan.completed_at = datetime.utcnow()
        db.add(CloudScanEvent(scan_id=scan.id, event_type="STATE",
                              message_code="WORKER_BUSY"))
        db.commit()
        raise HTTPException(status_code=503, detail="cloud_worker_busy")
    db.refresh(scan)
    return scan


@router.get("/iac/scanners")
def iac_scanner_status(
    _: AuthenticatedControlPlaneUser = Depends(require_authenticated_user),
):
    """Version-checked status; a missing engine is never silently passed."""
    return scanner_availability()


@router.post("/iac/scans", response_model=ScanPublic, status_code=202)
async def upload_iac_scan(
    request: Request,
    actor: AuthenticatedControlPlaneUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    # Raw application/zip avoids multipart parsing and never accepts arbitrary
    # user-selected local server paths.
    if request.headers.get("content-type", "").split(";")[0].strip().lower() not in (
        "application/zip", "application/x-zip-compressed",
    ):
        raise HTTPException(status_code=415, detail="IAC_ZIP_REQUIRED")
    if request.headers.get("content-encoding", "identity").lower() != "identity":
        raise HTTPException(status_code=415, detail="IAC_ENCODING_UNSUPPORTED")
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > MAX_ZIP_BYTES:
            raise HTTPException(status_code=413, detail="IAC_ARCHIVE_SIZE_INVALID")
    scan = CloudScan(
        id=new_id(), environment_id=None, kind="IAC_CONFIG", status="QUEUED",
        requested_by=actor.user.id, scanner_version=IAC_VERSION,
    )
    try:
        fingerprint, count = stage_archive(bytes(body), scan.id)
    except IaCIntakeError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    finally:
        body.clear()
    try:
        scan.source_fingerprint = fingerprint
        scan.source_file_count = count
        db.add(scan)
        db.flush()
        db.add(CloudScanEvent(scan_id=scan.id, event_type="STATE", message_code="QUEUED"))
        _audit(db, request, actor, "IAC_SCAN_REQUESTED", "cloud_scan", scan.id, {
            "kind": "IAC_CONFIG", "source_fingerprint": fingerprint, "file_count": count,
        })
        db.commit()
    except Exception:
        db.rollback()
        discard_source(scan.id)
        raise
    if not enqueue_iac(scan.id):
        discard_source(scan.id)
        scan.status = "FAILED"
        scan.error_code = "CLOUD_WORKER_BUSY"
        scan.completed_at = datetime.utcnow()
        db.add(CloudScanEvent(scan_id=scan.id, event_type="STATE", message_code="WORKER_BUSY"))
        db.commit()
        raise HTTPException(status_code=503, detail="cloud_worker_busy")
    db.refresh(scan)
    return scan


@router.get("/environments/{environment_id}/iam-mapping-context")
def iam_mapping_context(
    environment_id:str,mcp_server_id:int,
    _:AuthenticatedControlPlaneUser=Depends(require_authenticated_user),
    db:Session=Depends(get_db),
):
    _env(db,environment_id)
    server=db.get(MCPServer,mcp_server_id)
    if server is None or server.status!="active":
        raise HTTPException(status_code=404,detail="mcp_server_not_found")
    try:
        snapshot=PublishedConfigurationProvider(db).load_active_snapshot()
        return context_for_server(snapshot,server.endpoint)
    except MappingError as exc:
        raise HTTPException(status_code=409,detail=str(exc)) from exc


@router.get("/environments/{environment_id}/iam-mappings",
            response_model=list[IAMMappingPublic])
def list_iam_mappings(
    environment_id:str,
    _:AuthenticatedControlPlaneUser=Depends(require_authenticated_user),
    db:Session=Depends(get_db),
):
    _env(db,environment_id)
    return db.scalars(select(CloudIAMMapping).where(
        CloudIAMMapping.environment_id==environment_id
    ).order_by(CloudIAMMapping.created_at.desc()).limit(100)).all()


@router.post("/environments/{environment_id}/iam-mappings",
             response_model=IAMMappingPublic,status_code=201)
def create_iam_mapping(
    environment_id:str,payload:IAMMappingCreate,request:Request,
    actor:AuthenticatedControlPlaneUser=Depends(require_admin),
    db:Session=Depends(get_db),
):
    env=_env(db,environment_id)
    if env.status!="CONNECTED" or not env.account_id:
        raise HTTPException(status_code=409,detail="cloud_connection_not_verified")
    if payload.identity.region and payload.identity.region not in env.regions:
        raise HTTPException(status_code=422,detail="iam_identity_region_not_connected")
    server=db.get(MCPServer,payload.mcp_server_id)
    if server is None or server.status!="active":
        raise HTTPException(status_code=404,detail="mcp_server_not_found")
    try:
        snapshot=PublishedConfigurationProvider(db).load_active_snapshot()
        configuration={"identity":payload.identity.model_dump(mode="json",exclude_none=True),
                       "role_usage":payload.role_usage,
                       "unmapped_effects_acknowledged":payload.acknowledge_unmapped_effects,
                       "entries":[e.model_dump(mode="json") for e in payload.entries],
                       "source_binding":{"account_id":env.account_id,
                                         "server_endpoint":server.endpoint}}
        expected_rows=compile_expectations(snapshot,server.endpoint,configuration["entries"])
        if (any(x["status"]!="READY" for x in expected_rows)
                and not payload.acknowledge_unmapped_effects):
            raise MappingError("IAM_MCP_UNMAPPED_EFFECTS_REQUIRE_ACKNOWLEDGEMENT")
    except MappingError as exc:
        raise HTTPException(status_code=422,detail=str(exc)) from exc
    row=CloudIAMMapping(
        environment_id=environment_id,mcp_server_id=server.id,
        name=payload.name.strip(),configuration=configuration,status="DRAFT",
        signed_revision=snapshot.revision_number,
        signed_content_hash=snapshot.content_hash,created_by=actor.user.id,
    )
    db.add(row)
    db.flush()
    _audit(db,request,actor,"CLOUD_IAM_MAPPING_DRAFT_CREATED",
           "cloud_iam_mapping",row.id,{
               "environment_id":environment_id,"server_id":server.id,
               "signed_revision":snapshot.revision_number,
               "config_digest":mapping_digest(row),
           })
    db.commit()
    db.refresh(row)
    return row


@router.post("/environments/{environment_id}/iam-mappings/{mapping_id}/approve",
             response_model=IAMMappingPublic)
def approve_iam_mapping(
    environment_id:str,mapping_id:str,payload:IAMMappingApprove,request:Request,
    actor:AuthenticatedControlPlaneUser=Depends(require_admin),
    db:Session=Depends(get_db),
):
    _env(db,environment_id)
    row=db.scalar(select(CloudIAMMapping).where(
        CloudIAMMapping.id==mapping_id,
        CloudIAMMapping.environment_id==environment_id).with_for_update())
    if row is None:
        raise HTTPException(status_code=404,detail="iam_mapping_not_found")
    if row.status!="DRAFT":
        raise HTTPException(status_code=409,detail="iam_mapping_already_approved")
    server=db.get(MCPServer,row.mcp_server_id)
    if server is None or server.status!="active":
        raise HTTPException(status_code=409,detail="mcp_server_not_active")
    try:
        snapshot=PublishedConfigurationProvider(db).load_active_snapshot()
        if row.signed_revision!=snapshot.revision_number or row.signed_content_hash!=snapshot.content_hash:
            raise MappingError("IAM_MCP_MAPPING_SIGNED_REVISION_CHANGED")
        if row.configuration.get("source_binding")!={"account_id":_env(db,environment_id).account_id,
                                                      "server_endpoint":server.endpoint}:
            raise MappingError("IAM_MCP_MAPPING_CLOUD_OR_SERVER_BINDING_CHANGED")
        approved_rows=compile_expectations(snapshot,server.endpoint,row.configuration["entries"])
        if (any(x["status"]!="READY" for x in approved_rows)
                and not row.configuration.get("unmapped_effects_acknowledged",False)):
            raise MappingError("IAM_MCP_UNMAPPED_EFFECTS_REQUIRE_ACKNOWLEDGEMENT")
    except MappingError as exc:
        raise HTTPException(status_code=409,detail=str(exc)) from exc
    row.status="APPROVED"
    row.approved_by=actor.user.id
    row.approved_at=datetime.utcnow()
    row.approval_digest=mapping_digest(row)
    _audit(db,request,actor,"CLOUD_IAM_MAPPING_APPROVED",
           "cloud_iam_mapping",row.id,{
               "environment_id":environment_id,
               "signed_revision":row.signed_revision,
               "approved_digest":row.approval_digest,
           })
    db.commit()
    db.refresh(row)
    return row


@router.post("/environments/{environment_id}/iam-comparisons",
             response_model=ScanPublic,status_code=202)
def request_iam_mcp_comparison(
    environment_id:str,payload:IAMComparisonRequest,request:Request,
    actor:AuthenticatedControlPlaneUser=Depends(require_admin),
    db:Session=Depends(get_db),
):
    env=db.scalar(select(CloudEnvironment).where(
        CloudEnvironment.id==environment_id).with_for_update())
    if env is None:
        raise HTTPException(status_code=404,detail="cloud_environment_not_found")
    if env.status!="CONNECTED" or not env.account_id or not env.role_arn:
        raise HTTPException(status_code=409,detail="cloud_connection_not_verified")
    row=db.get(CloudIAMMapping,payload.mapping_id)
    if row is None or row.environment_id!=environment_id:
        raise HTTPException(status_code=404,detail="iam_mapping_not_found")
    server=db.get(MCPServer,row.mcp_server_id)
    if server is None or server.status!="active":
        raise HTTPException(status_code=409,detail="mcp_server_not_active")
    try:
        snapshot=PublishedConfigurationProvider(db).load_active_snapshot()
        verify_approved_mapping(row,snapshot,server.endpoint,env.account_id)
    except MappingError as exc:
        raise HTTPException(status_code=409,detail=str(exc)) from exc
    active=db.scalar(select(CloudScan.id).where(
        CloudScan.environment_id==env.id,
        CloudScan.status.in_(("QUEUED","RUNNING"))).limit(1))
    if active is not None:
        raise HTTPException(status_code=409,detail="cloud_scan_already_active")
    scan=CloudScan(id=new_id(),environment_id=env.id,kind="IAM_MCP",
                   status="QUEUED",scanner_version=IAM_MCP_VERSION,
                   source_fingerprint=row.approval_digest,
                   requested_by=actor.user.id)
    db.add(scan)
    db.flush()
    db.add(CloudScanEvent(scan_id=scan.id,event_type="STATE",
                          message_code="QUEUED"))
    _audit(db,request,actor,"CLOUD_IAM_MCP_COMPARISON_REQUESTED",
           "cloud_scan",scan.id,{
               "environment_id":env.id,
               "mcp_server_id":row.mcp_server_id,
               "iam_mapping_id":row.id,
               "approved_digest":row.approval_digest,
               "kind":"IAM_MCP",
           })
    db.commit()
    if not enqueue_comparison(scan.id,env.id,row.id):
        scan.status="FAILED"
        scan.error_code="CLOUD_WORKER_BUSY"
        scan.completed_at=datetime.utcnow()
        db.add(CloudScanEvent(scan_id=scan.id,event_type="STATE",
                              message_code="WORKER_BUSY"))
        db.commit()
        raise HTTPException(status_code=503,detail="cloud_worker_busy")
    db.refresh(scan)
    return scan


@router.get("/scans/{scan_id}/iam-comparisons",response_model=list[IAMComparisonPublic])
def list_iam_mcp_results(
    scan_id: str,
    _: AuthenticatedControlPlaneUser=Depends(require_authenticated_user),
    db: Session=Depends(get_db),
):
    scan=_scan(db,scan_id)
    if scan.kind!="IAM_MCP":
        raise HTTPException(status_code=404,detail="iam_comparison_not_found")
    return db.scalars(select(CloudIAMComparison).where(
        CloudIAMComparison.scan_id==scan_id).limit(250)).all()


def _deploy_context(db: Session, scan_id: str, kind: str) -> dict:
    if kind=="IAM_MCP":
        return build_deploy_iam_governance_input(db,scan_id)
    return build_deploy_cloud_governance_input(db,scan_id)


class DeployExceptionCreate(BaseModel):
    finding_id: str = Field(min_length=36,max_length=36)
    reason: str = Field(min_length=20,max_length=1000)


class DeployExceptionDecision(BaseModel):
    operation: Literal["APPROVE","REJECT","REVOKE"]
    reason: str = Field(min_length=20,max_length=1000)
    expires_days: int | None = Field(default=None,ge=1,le=90)


@router.post("/scans/{scan_id}/deploy-governance/evaluations",
             response_model=DeployAdvisoryDecision)
def evaluate_and_record_deploy_governance(
    scan_id: str, request: Request,
    actor: AuthenticatedControlPlaneUser=Depends(require_admin),
    db: Session=Depends(get_db),
):
    scan=_scan(db,scan_id)
    if scan.kind not in ("IAM_MCP","IAC_CONFIG","AWS_ADVANCED"):
        raise HTTPException(status_code=404,detail="deploy_governance_scan_not_found")
    try:
        evidence=_deploy_context(db,scan_id,scan.kind)
        result=DeployOPAClient(
            base_url=settings.opa_base_url,
            timeout_seconds=settings.opa_timeout_seconds,
        ).evaluate(evidence)
        # Serialize evaluation persistence with other scan-level decisions
        # before rebuilding its signed evidence under the lock.
        db.scalar(select(CloudScan).where(CloudScan.id == scan_id).with_for_update())
        fresh=_deploy_context(db,scan_id,scan.kind)
        if governance_digest(evidence)!=governance_digest(fresh):
            raise DeployHistoryError("DEPLOY_EVIDENCE_CHANGED_DURING_EVALUATION")
        recorded=record_deploy_decision(
            db,scan_id,actor.user.id,fresh,result.model_dump(mode="json"))
        _audit(db,request,actor,"DEPLOY_GOVERNANCE_EVALUATED","cloud_scan",
               scan_id,{"decision_id":recorded.id,"classification":result.classification,
                        "policy_revision":result.policy_revision,
                        "entry_sha256":recorded.entry_sha256})
        db.commit()
        return result
    except DeployOPAError as exc:
        db.rollback()
        raise HTTPException(status_code=503,detail=str(exc)) from exc
    except (DeployHistoryError,DeployGovernanceError,ValueError) as exc:
        db.rollback()
        raise HTTPException(status_code=409,detail=str(exc)) from exc


@router.get("/scans/{scan_id}/deploy-governance/history")
def get_deploy_governance_history(
    scan_id: str, _: AuthenticatedControlPlaneUser=Depends(require_authenticated_user),
    db: Session=Depends(get_db),
):
    _scan(db,scan_id)
    try:
        return list_deploy_decisions(db,scan_id)
    except DeployHistoryError as exc:
        raise HTTPException(status_code=409,detail=str(exc)) from exc


@router.get("/scans/{scan_id}/deploy-exceptions")
def get_deploy_exceptions(
    scan_id: str, _: AuthenticatedControlPlaneUser=Depends(require_authenticated_user),
    db: Session=Depends(get_db),
):
    _scan(db,scan_id)
    try:
        return list_exception_history(db,scan_id)
    except DeployHistoryError as exc:
        raise HTTPException(status_code=409,detail=str(exc)) from exc


@router.post("/scans/{scan_id}/deploy-exceptions",status_code=201)
def request_deploy_exception(
    scan_id: str,payload: DeployExceptionCreate,request: Request,
    actor: AuthenticatedControlPlaneUser=Depends(require_admin),
    db: Session=Depends(get_db),
):
    _scan(db,scan_id)
    try:
        result=record_exception_event(
            db,scan_id,actor.user.id,"REQUEST",payload.reason,
            finding_id=payload.finding_id)
        _audit(db,request,actor,"DEPLOY_EXCEPTION_REQUESTED","cloud_scan",
               scan_id,{"exception_id":result["exception_id"],
                        "finding_id":result["finding_id"],
                        "entry_sha256":result["entry_sha256"]})
        db.commit()
        return result
    except DeployHistoryError as exc:
        db.rollback()
        raise HTTPException(status_code=409,detail=str(exc)) from exc


@router.post("/scans/{scan_id}/deploy-exceptions/{exception_id}/decide")
def decide_deploy_exception(
    scan_id: str,exception_id: str,payload: DeployExceptionDecision,
    request: Request,
    actor: AuthenticatedControlPlaneUser=Depends(require_admin),
    db: Session=Depends(get_db),
):
    _scan(db,scan_id)
    try:
        result=record_exception_event(
            db,scan_id,actor.user.id,payload.operation,payload.reason,
            exception_id=exception_id,expires_days=payload.expires_days)
        _audit(db,request,actor,"DEPLOY_EXCEPTION_"+payload.operation,
               "cloud_scan",scan_id,{"exception_id":exception_id,
                                     "entry_sha256":result["entry_sha256"]})
        db.commit()
        return result
    except DeployHistoryError as exc:
        db.rollback()
        raise HTTPException(status_code=409,detail=str(exc)) from exc


@router.get("/scans/{scan_id}/deploy-governance",
            response_model=DeployAdvisoryDecision)
def get_iam_deploy_governance(
    scan_id: str,
    _: AuthenticatedControlPlaneUser=Depends(require_authenticated_user),
    db: Session=Depends(get_db),
):
    """Advisory OPA review; never authorize/deny MCP tools or mutate AWS.

    The only OPA input is reconstructed from verified signed and hash-consistent
    PostgreSQL scan records, not submitted by a caller.
    """
    scan=_scan(db,scan_id)
    if scan.kind not in ("IAM_MCP", "IAC_CONFIG", "AWS_ADVANCED"):
        raise HTTPException(status_code=404,detail="deploy_governance_scan_not_found")
    try:
        evidence=_deploy_context(db,scan_id,scan.kind)
    except (DeployGovernanceError,ValueError) as exc:
        raise HTTPException(status_code=409,detail=str(exc)) from exc
    try:
        return DeployOPAClient(
            base_url=settings.opa_base_url,
            timeout_seconds=settings.opa_timeout_seconds,
        ).evaluate(evidence)
    except DeployOPAError as exc:
        raise HTTPException(status_code=503,detail=str(exc)) from exc


@router.get("/scans",response_model=list[ScanPublic])
def list_scans(
    environment_id:str|None=None,
    _:AuthenticatedControlPlaneUser=Depends(require_authenticated_user),
    db:Session=Depends(get_db),
):
    statement=select(CloudScan).order_by(CloudScan.created_at.desc()).limit(100)
    if environment_id:
        statement=statement.where(CloudScan.environment_id==environment_id)
    return db.scalars(statement).all()


@router.get("/scans/{scan_id}",response_model=ScanDetailPublic)
def scan_detail(
    scan_id:str,
    _:AuthenticatedControlPlaneUser=Depends(require_authenticated_user),
    db:Session=Depends(get_db),
):
    scan=_scan(db,scan_id)
    return ScanDetailPublic(
        scan=ScanPublic.model_validate(scan),
        resources=[ResourcePublic.model_validate(x) for x in
                   db.scalars(select(CloudResource).where(CloudResource.scan_id==scan_id)
                              .limit(250)).all()],
        findings=[FindingPublic.model_validate(x) for x in
                  db.scalars(select(CloudFinding).where(CloudFinding.scan_id==scan_id)
                             .limit(300)).all()],
        evidence=[EvidencePublic.model_validate(x) for x in
                  db.scalars(select(CloudEvidence).where(CloudEvidence.scan_id==scan_id)
                             .limit(500)).all()],
        events=[ScanEventPublic.model_validate(x) for x in
                db.scalars(select(CloudScanEvent).where(CloudScanEvent.scan_id==scan_id)
                           .order_by(CloudScanEvent.created_at.desc()).limit(100)).all()],
    )
