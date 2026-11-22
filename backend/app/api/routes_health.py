from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.config import settings
from common.build_identity import get_build_identity
from app.db.database import engine, get_db
from app.services.control_plane_auth import AuthenticatedControlPlaneUser, require_authenticated_user
from app.services.local_runtime_manager import LocalRuntimeManager

router = APIRouter(tags=["Health"])


@router.get("/health")
def health_check():
    return {
        "status": "ok",
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "service": settings.app_name,
        "version": settings.app_version,
        "environment": settings.environment,
        # UX-01: what this process loaded at start; never today's disk HEAD.
        "build": get_build_identity("api"),
    }


@router.get("/control-plane/local-runtime/provenance")
def local_runtime_provenance(
    _: AuthenticatedControlPlaneUser = Depends(require_authenticated_user),
):
    """UX-01: independently probed build identities and their comparison.

    Reachability, a known-but-different revision and an unknown revision are
    reported as distinct states. Readiness stays a separate endpoint.
    """
    return LocalRuntimeManager().provenance(get_build_identity("api"))




@router.get("/readiness")
def readiness_check(db: Session = Depends(get_db)):
    manager = LocalRuntimeManager()
    runtime = manager.status(db=db, backend_current_process=True)
    identity = manager.identity_provider_status()
    mcp_lab = manager.mcp_lab_status()
    ready = (
        runtime.ready
        and identity.status == "healthy"
        and (
            not settings.readiness_require_mcp_lab
            or mcp_lab.status == "healthy"
        )
    )
    component_statuses = {
        "backend": runtime.backend.status,
        "database": runtime.database.status,
        "opa": runtime.opa.status,
        "gateway": runtime.gateway.status,
        "identity_provider": identity.status,
        "mcp_lab": mcp_lab.status,
    }
    return JSONResponse(
        status_code=200 if ready else 503,
        content={
            "status": "ready" if ready else "not_ready",
            "components": component_statuses,
            "required_components": [
                "backend", "database", "opa", "gateway", "identity_provider",
                *(["mcp_lab"] if settings.readiness_require_mcp_lab else []),
            ],
        },
    )


@router.get("/status")
def api_status():
    return {
        "status": "running",
        "message": "Backend operational",
        "phase": "Control Plane / Runtime Security",
        "task": "Task 8A.6 - Control Center and local runtime",
        "next_modules": [
            "MCP inventory",
            "OPA runtime authorization",
            "Runtime logs",
            "Audit events",
        ],
    }


@router.get("/db-check")
def db_check():
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return {
            "status": "ok",
            "database": "connected",
        }
    except Exception:
        return {
            "status": "error",
            "database": "not connected",
        }


@router.get("/control-plane/local-runtime/status")
def local_runtime_status(
    _: AuthenticatedControlPlaneUser = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
):
    manager = LocalRuntimeManager()
    payload = manager.status(
        db=db,
        backend_current_process=True,
    ).as_dict(include_ownership=False)
    payload["mcp_lab"] = manager.mcp_lab_status().as_dict()
    payload["mcp_lab"].pop("managed_by_framework", None)
    payload["ready"] = payload["ready"] and (
        not settings.readiness_require_mcp_lab
        or payload["mcp_lab"]["status"] == "healthy"
    )
    payload["required_components"] = [
        "backend", "database", "opa", "gateway", "identity_provider",
        *(["mcp_lab"] if settings.readiness_require_mcp_lab else []),
    ]
    return payload
