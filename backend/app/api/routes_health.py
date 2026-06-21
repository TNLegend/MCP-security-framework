from fastapi import APIRouter
from sqlalchemy import text

from app.core.config import settings
from app.db.database import engine

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
        "task": "Tâche 1.5 - Base PostgreSQL minimale",
        "next_modules": [
            "MCP inventory",
            "Policy engine",
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
    except Exception as exc:
        return {
            "status": "error",
            "database": "not connected",
            "detail": str(exc),
        }
