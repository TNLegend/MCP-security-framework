from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes_control_plane_audit import router as control_plane_audit_router
from app.api.routes_control_plane_auth import router as control_plane_auth_router
from app.api.routes_control_plane_config import router as control_plane_config_router
from app.api.routes_controlled_ai import router as controlled_ai_router
from app.api.routes_control_plane_tool_analysis import (
    router as control_plane_tool_analysis_router,
)
from app.api.routes_control_plane_users import router as control_plane_users_router
from app.api.routes_emergency_deny import router as emergency_deny_router
from app.api.routes_health import router as health_router
from app.api.routes_internal import router as internal_router
from app.api.routes_inventory import router as inventory_router
from app.api.routes_policies import router as policies_router
from app.api.routes_runtime import router as runtime_router
from app.api.routes_servers import router as servers_router
from app.api.routes_tool_analysis import router as tool_analysis_router
from app.api.routes_tools import router as tools_router
from app.api.routes_upstream_oauth import router as upstream_oauth_router
from app.api.routes_security_packs import router as security_packs_router
from app.core.config import settings
from proxy.trusted_adapter_packages import load_trusted_adapters_from_environment

load_trusted_adapters_from_environment()

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
    allow_origins=settings.control_center_cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE"],
    allow_headers=["*"],
)

app.include_router(health_router, prefix=settings.api_prefix)
app.include_router(servers_router, prefix=settings.api_prefix)
app.include_router(tools_router, prefix=settings.api_prefix)
app.include_router(policies_router, prefix=settings.api_prefix)
app.include_router(runtime_router, prefix=settings.api_prefix)
app.include_router(internal_router, prefix=settings.api_prefix)
app.include_router(inventory_router, prefix=settings.api_prefix)
app.include_router(tool_analysis_router, prefix=settings.api_prefix)
app.include_router(control_plane_auth_router, prefix=settings.api_prefix)
app.include_router(upstream_oauth_router, prefix=settings.api_prefix)
app.include_router(security_packs_router, prefix=settings.api_prefix)
app.include_router(control_plane_users_router, prefix=settings.api_prefix)
app.include_router(control_plane_config_router, prefix=settings.api_prefix)
app.include_router(controlled_ai_router, prefix=settings.api_prefix)
app.include_router(control_plane_tool_analysis_router, prefix=settings.api_prefix)
app.include_router(control_plane_audit_router, prefix=settings.api_prefix)
app.include_router(emergency_deny_router, prefix=settings.api_prefix)


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
