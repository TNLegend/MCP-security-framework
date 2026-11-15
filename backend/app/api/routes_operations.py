from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Path, Request
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.schemas.operations import (
    OperationsSummary,
    RuntimeCleanupRequest,
    RuntimeCleanupResult,
    RuntimeOperationReconciliation,
)
from app.services.control_plane_audit import record_control_plane_audit
from app.services.control_plane_auth import (
    AuthenticatedControlPlaneUser,
    require_admin,
    require_authenticated_user,
)
from app.services.runtime_operations import cleanup_runtime_logs, operations_summary
from app.services.runtime_reconciliation import runtime_operation_reconciliation


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


@router.get(
    "/runtime-operations/{operation_id}/reconciliation",
    response_model=RuntimeOperationReconciliation,
)
def read_runtime_operation_reconciliation(
    operation_id: str = Path(
        pattern=r"^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$",
    ),
    _: AuthenticatedControlPlaneUser = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
) -> RuntimeOperationReconciliation:
    result = runtime_operation_reconciliation(db, operation_id=operation_id)
    if result is None:
        raise HTTPException(status_code=404, detail="runtime_operation_not_found")
    return result


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
