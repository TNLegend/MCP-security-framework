from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.database import engine, get_db
from app.services.control_plane_auth import AuthenticatedControlPlaneUser, require_authenticated_user
from app.services.local_runtime_manager import LocalRuntimeManager

router = APIRouter(tags=["Health"])


@router.get("/health")
def health_check():
    return {
        "status": "ok",
        "service": settings.app_name,
        "version": settings.app_version,
        "environment": settings.environment,
    }


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
    return LocalRuntimeManager().status(
        db=db,
        backend_current_process=True,
    ).as_dict(include_ownership=False)
