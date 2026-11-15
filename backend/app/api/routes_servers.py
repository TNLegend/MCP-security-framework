from contextlib import ExitStack

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from common.upstream_auth import (
    AUTH_MODE_OAUTH, UpstreamAuthError, delete_upstream_secret, oauth_credential_lock,
)
from app.db.database import get_db
from app.models.mcp_server import MCPServer
from app.models.control_plane import ControlPlaneAuditEvent
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
    current: AuthenticatedControlPlaneUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    db_server = MCPServer(**server.model_dump())
    try:
        db.add(db_server)
        db.flush()
        record_control_plane_audit(
            db,
            actor=current.user,
            action="MCP_SERVER_CREATED",
            target_type="mcp_server",
            target_id=str(db_server.id),
            after_json={"endpoint": db_server.endpoint, "auth_mode": db_server.auth_mode,
                        "trust_status": db_server.trust_status},
        )
        # Creation and audit share one transaction. A failed audit aborts both.
        db.commit()
    except Exception:
        db.rollback()
        raise
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


def _credential_ref_used_elsewhere(db: Session, server_id: int, reference: str) -> bool:
    # References can legitimately be shared across different MCPs, including
    # OAuth client-secret refs. Never retire a credential still in use.
    other_servers = db.scalars(
        select(MCPServer).where(
            MCPServer.id != server_id,
            MCPServer.status != "archived",
        )
    )
    for other in other_servers:
        if other.credential_ref == reference:
            return True
        config = other.oauth_config if isinstance(other.oauth_config, dict) else {}
        if config.get("client_secret_ref") == reference:
            return True
    return False


def _retire_archived_server_refs(
    db: Session, server_id: int, references: set[str],
) -> None:
    # Called only AFTER the archived status+audit have committed. If the
    # filesystem fails, the reference list in the immutable archive event is
    # a durable retry journal: POST archive again to retry safely.
    for reference in sorted(references):
        with oauth_credential_lock(reference):
            if not _credential_ref_used_elsewhere(db, server_id, reference):
                delete_upstream_secret(reference)


def _archived_server_pending_refs(db: Session, server_id: int) -> set[str]:
    prior = db.scalar(
        select(ControlPlaneAuditEvent).where(
            ControlPlaneAuditEvent.action == "MCP_SERVER_ARCHIVED",
            ControlPlaneAuditEvent.target_type == "mcp_server",
            ControlPlaneAuditEvent.target_id == str(server_id),
        ).order_by(ControlPlaneAuditEvent.timestamp.desc())
    )
    if prior is None or not isinstance(prior.after_json, dict):
        return set()
    values = prior.after_json.get("credential_retirement_refs", [])
    return {
        value for value in values
        if isinstance(value, str) and value
    } if isinstance(values, list) else set()


@router.post("/{server_id}/archive", response_model=MCPServerRead)
def archive_server(
    server_id: int,
    payload: ReasonRequest,
    current: AuthenticatedControlPlaneUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    server = db.get(MCPServer, server_id, with_for_update=True)
    if server is None:
        raise HTTPException(status_code=404, detail="MCP server not found")
    reason = payload.reason.strip()
    if len(reason) < 3:
        raise HTTPException(status_code=422, detail="archive_reason_too_short")
    if server.status == "archived":
        # Idempotent recovery after a crash between DB commit and file unlink.
        refs = _archived_server_pending_refs(db, server_id)
        try:
            _retire_archived_server_refs(db, server_id, refs)
        except UpstreamAuthError as exc:
            raise HTTPException(status_code=503, detail="archived_credential_cleanup_pending") from exc
        return server

    oauth_config = dict(server.oauth_config or {})
    client_secret_ref = oauth_config.pop("client_secret_ref", None)
    credential_refs = {
        reference for reference in (server.credential_ref, client_secret_ref)
        if isinstance(reference, str) and reference
    }
    # Lock ordering: PostgreSQL row first, then sorted credential lock(s).
    # Hold through commit and deletion to prevent refresh resurrection.
    with ExitStack() as protected_secrets:
        for reference in sorted(credential_refs):
            protected_secrets.enter_context(oauth_credential_lock(reference))
        before = {
            "status": server.status,
            "trust_status": server.trust_status,
            "security_status": server.security_status,
            "credential_present": bool(credential_refs),
        }
        server.status = "archived"
        server.trust_status = "archived"
        server.security_status = "archived"
        server.credential_ref = None
        if server.auth_mode == AUTH_MODE_OAUTH:
            server.oauth_config = oauth_config
            server.oauth_connected_at = None
            server.oauth_last_error = None
        # This list is a reference, never the secret value. It survives a
        # crash and is not consumed as authorization for runtime calls.
        record_control_plane_audit(
            db,
            actor=current.user,
            action="MCP_SERVER_ARCHIVED",
            target_type="mcp_server",
            target_id=str(server.id),
            reason=reason,
            before_json=before,
            after_json={
                "status": "archived",
                "trust_status": "archived",
                "security_status": "archived",
                "credential_present": False,
                "credential_retirement_refs": sorted(credential_refs),
            },
        )
        try:
            db.commit()
        except Exception:
            db.rollback()
            raise
        db.refresh(server)
        # Never delete a secret before a successful database commit.
        # Shared credentials remain present for any other active server.
        try:
            for reference in sorted(credential_refs):
                if not _credential_ref_used_elsewhere(db, server_id, reference):
                    delete_upstream_secret(reference)
        except UpstreamAuthError as exc:
            raise HTTPException(status_code=503, detail="archived_credential_cleanup_pending") from exc
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
