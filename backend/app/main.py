from fastapi import FastAPI

from app.api.routes_health import router as health_router
from app.core.config import settings

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description=(
        "Backend minimal du MCP Security Framework. "
        "Il servira à centraliser l’inventaire MCP, les politiques, "
        "les décisions runtime, les logs et les preuves d’audit."
    ),
)

app.include_router(health_router, prefix=settings.api_prefix)


@app.get("/")
def root():
    return {
        "message": "MCP Security Framework Backend",
        "version": settings.app_version,
        "environment": settings.environment,
        "docs": "/docs",
        "health": f"{settings.api_prefix}/health",
        "status": f"{settings.api_prefix}/status",
    }
