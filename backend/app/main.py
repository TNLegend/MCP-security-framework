from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes_health import router as health_router
from app.api.routes_policies import router as policies_router
from app.api.routes_runtime import router as runtime_router
from app.api.routes_servers import router as servers_router
from app.api.routes_tools import router as tools_router
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

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5173",
        "http://localhost:5173",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

app.include_router(health_router, prefix=settings.api_prefix)
app.include_router(servers_router, prefix=settings.api_prefix)
app.include_router(tools_router, prefix=settings.api_prefix)
app.include_router(policies_router, prefix=settings.api_prefix)
app.include_router(runtime_router, prefix=settings.api_prefix)


@app.get("/")
def root():
    return {
        "message": "MCP Security Framework Backend",
        "version": settings.app_version,
        "environment": settings.environment,
        "docs": "/docs",
        "health": f"{settings.api_prefix}/health",
        "status": f"{settings.api_prefix}/status",
        "db_check": f"{settings.api_prefix}/db-check",
    }
