from fastapi import APIRouter

from app.core.config import settings

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
        "message": "Backend minimal opérationnel",
        "phase": "Phase 1 - Architecture & environnement minimal",
        "task": "Tâche 1.4 - Backend FastAPI minimal",
        "next_modules": [
            "MCP inventory",
            "Policy engine",
            "Runtime logs",
            "Audit events",
        ],
    }
