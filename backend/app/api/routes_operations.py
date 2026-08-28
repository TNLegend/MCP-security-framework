from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.schemas.operations import (
    OperationsSummary,
    RuntimeCleanupRequest,
    RuntimeCleanupResult,
)
from app.services.control_plane_audit import record_control_plane_audit
from app.services.control_plane_auth import (
    AuthenticatedControlPlaneUser,
    require_admin,
    require_authenticated_user,
)
from app.services.runtime_operations import cleanup_runtime_logs, operations_summary


router = APIRouter(
    prefix="/control-plane/operations",
    tags=["Control Plane Operations"],
)


@router.get("/summary", response_model=OperationsSummary)
def get_operations_summary(
    _: AuthenticatedControlPlaneUser = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
) -> OperationsSummary:
    return operations_summary(db)


@router.post("/runtime-logs/cleanup", response_model=RuntimeCleanupResult)
def cleanup_runtime_log_storage(
    payload: RuntimeCleanupRequest,
    request: Request,
    current: AuthenticatedControlPlaneUser = Depends(require_admin),
    db: Session = Depends(get_db),
) -> RuntimeCleanupResult:
    result = cleanup_runtime_logs(db, dry_run=payload.dry_run)
    record_control_plane_audit(
        db,
        actor=current.user,
        action=(
            "RUNTIME_LOG_RETENTION_PREVIEW"
            if payload.dry_run
            else "RUNTIME_LOG_RETENTION_APPLIED"
        ),
        target_type="runtime_logs",
        target_id="retention",
        source_ip=request.client.host if request.client else None,
        result="SUCCESS",
        after_json=result.model_dump(mode="json"),
        reason=payload.reason,
    )
    db.commit()
    return result
