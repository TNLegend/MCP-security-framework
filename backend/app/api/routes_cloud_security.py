"""Authenticated Cloud Security API. Only ADMIN can configure or run audits."""
from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models.cloud_security import (
    CloudEnvironment, CloudEvidence, CloudFinding, CloudResource, CloudScan,
    CloudScanEvent,
)
from app.schemas.cloud_security import (
    ConnectionTestPublic, EnvironmentCreate, EnvironmentPublic,
    EvidencePublic, FindingPublic, ResourcePublic, ScanDetailPublic,
    ScanEventPublic, ScanPublic,
)
from app.services.cloud_security import (
    CloudAuditError, _safe_error, check_connection, enqueue_scan,
)
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
