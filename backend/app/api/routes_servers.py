from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from common.upstream_auth import AUTH_MODE_OAUTH, delete_upstream_secret
from app.db.database import get_db
from app.models.mcp_server import MCPServer
from app.schemas.control_plane import ReasonRequest
from app.schemas.server import MCPServerCreate, MCPServerRead
from app.services.control_plane_audit import record_control_plane_audit
from app.services.control_plane_auth import (
    AuthenticatedControlPlaneUser,
    require_admin,
    require_authenticated_user,
)

router = APIRouter(prefix="/servers", tags=["MCP Servers"])


@router.get("", response_model=list[MCPServerRead])
def list_servers(
    _: AuthenticatedControlPlaneUser = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
):
    return list_servers_from_db(db)


@router.post("", response_model=MCPServerRead)
def create_server(
    server: MCPServerCreate,
    _: AuthenticatedControlPlaneUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    db_server = MCPServer(**server.model_dump())
    db.add(db_server)
    db.commit()
    db.refresh(db_server)
    return db_server


@router.post("/{server_id}/trust", response_model=MCPServerRead)
def trust_server(
    server_id: int,
    payload: ReasonRequest,
    current: AuthenticatedControlPlaneUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    return _set_server_trust(
        db,
        server_id=server_id,
        trust_status="trusted",
        action="MCP_SERVER_TRUSTED",
        payload=payload,
        current=current,
    )


@router.post("/{server_id}/revoke-trust", response_model=MCPServerRead)
def revoke_server_trust(
    server_id: int,
    payload: ReasonRequest,
    current: AuthenticatedControlPlaneUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    return _set_server_trust(
        db,
        server_id=server_id,
        trust_status="unknown",
        action="MCP_SERVER_TRUST_REVOKED",
        payload=payload,
        current=current,
    )


@router.post("/{server_id}/archive", response_model=MCPServerRead)
def archive_server(
    server_id: int,
    payload: ReasonRequest,
    current: AuthenticatedControlPlaneUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    server = db.get(MCPServer, server_id)
    if server is None:
        raise HTTPException(status_code=404, detail="MCP server not found")
    reason = payload.reason.strip()
    if len(reason) < 3:
        raise HTTPException(status_code=422, detail="archive_reason_too_short")
    if server.status != "archived":
        oauth_config = dict(server.oauth_config or {})
        client_secret_ref = oauth_config.pop("client_secret_ref", None)
        credential_refs = {
            reference
            for reference in (server.credential_ref, client_secret_ref)
            if isinstance(reference, str) and reference
        }
        for reference in credential_refs:
            delete_upstream_secret(reference)
        before = {
            "status": server.status,
            "trust_status": server.trust_status,
            "security_status": server.security_status,
            "credential_present": bool(server.credential_ref or client_secret_ref),
        }
        server.status = "archived"
        server.trust_status = "archived"
        server.security_status = "archived"
        server.credential_ref = None
        if server.auth_mode == AUTH_MODE_OAUTH:
            server.oauth_config = oauth_config
            server.oauth_connected_at = None
            server.oauth_last_error = None
        record_control_plane_audit(
            db,
            actor=current.user,
            action="MCP_SERVER_ARCHIVED",
            target_type="mcp_server",
            target_id=str(server.id),
            reason=reason,
            before_json=before,
            after_json={
                "status": server.status,
                "trust_status": server.trust_status,
                "security_status": server.security_status,
                "credential_present": False,
            },
        )
        db.commit()
        db.refresh(server)
    return server


def _set_server_trust(
    db: Session,
    *,
    server_id: int,
    trust_status: str,
    action: str,
    payload: ReasonRequest,
    current: AuthenticatedControlPlaneUser,
) -> MCPServer:
    server = db.get(MCPServer, server_id)
    if server is None:
        raise HTTPException(status_code=404, detail="MCP server not found")
    if server.status == "archived":
        raise HTTPException(status_code=409, detail="archived_server_trust_immutable")
    reason = payload.reason.strip()
    if len(reason) < 3:
        raise HTTPException(status_code=422, detail="trust_reason_too_short")
    if server.trust_status != trust_status:
        before = {"trust_status": server.trust_status}
        server.trust_status = trust_status
        record_control_plane_audit(
            db,
            actor=current.user,
            action=action,
            target_type="mcp_server",
            target_id=str(server.id),
            reason=reason,
            before_json=before,
            after_json={"trust_status": server.trust_status},
        )
        db.commit()
        db.refresh(server)
    return server


def list_servers_from_db(db: Session) -> list[MCPServer]:
    return db.scalars(select(MCPServer).order_by(MCPServer.id)).all()
