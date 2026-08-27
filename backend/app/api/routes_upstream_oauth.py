from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from common.mcp_endpoint import is_exact_local_lab_endpoint
from common.upstream_auth import (
    AUTH_MODE_OAUTH,
    UPSTREAM_SECRET_DIR,
    UpstreamAuthError,
    delete_upstream_secret,
    write_upstream_secret,
)
from common.upstream_oauth import (
    UpstreamOAuthError,
    consume_oauth_attempt,
    create_oauth_attempt,
    discover_oauth_configuration,
    exchange_authorization_code,
    normalize_requested_scopes,
    register_dynamic_oauth_client,
)
from app.core.config import settings
from app.db.database import get_db
from app.models.control_plane import ControlPlaneUser
from app.models.mcp_server import MCPServer
from app.schemas.server import MCPServerRead
from app.schemas.upstream_oauth import (
    OAuthConnectionStartResponse,
    OAuthConnectionStatus,
    OAuthMCPRegistrationRequest,
)
from app.services.control_plane_audit import record_control_plane_audit
from app.services.control_plane_auth import AuthenticatedControlPlaneUser, require_admin


router = APIRouter(prefix="/control-plane/upstream-oauth", tags=["Upstream OAuth"])
OAUTH_ATTEMPT_DIR = UPSTREAM_SECRET_DIR / "oauth-attempts"


@router.get("/callback-uri")
def get_oauth_callback_uri(
    _: AuthenticatedControlPlaneUser = Depends(require_admin),
):
    _validate_callback_uri(settings.upstream_oauth_callback_uri)
    return {"callback_uri": settings.upstream_oauth_callback_uri}


@router.post("/servers", response_model=MCPServerRead, status_code=status.HTTP_201_CREATED)
def register_oauth_server(
    payload: OAuthMCPRegistrationRequest,
    current: AuthenticatedControlPlaneUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    existing = db.scalar(
        select(MCPServer).where(
            MCPServer.endpoint == payload.endpoint,
            MCPServer.transport == "streamable_http",
        )
    )
    retrying_configuration = (
        existing is not None
        and existing.auth_mode == AUTH_MODE_OAUTH
        and existing.oauth_status in {"OAUTH_CONFIGURED", "OAUTH_ERROR"}
        and existing.last_seen_at is None
    )
    if existing is not None and not retrying_configuration:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="mcp_server_already_registered")

    previous_client_secret_ref: str | None = None
    if retrying_configuration:
        server = existing
        assert server is not None
        previous_configuration = server.oauth_config or {}
        previous_client_id = previous_configuration.get("client_id")
        client_secret_ref = previous_configuration.get("client_secret_ref")
        if isinstance(client_secret_ref, str):
            previous_client_secret_ref = client_secret_ref
        if payload.client_id and payload.client_id != previous_client_id:
            client_secret_ref = None
        server.name = payload.endpoint
        server.protocol_version = payload.protocol_version
        server.oauth_config = {
            **({"client_id": payload.client_id} if payload.client_id else {
                "client_id": previous_client_id
            } if isinstance(previous_client_id, str) else {}),
            "requested_scopes": normalize_requested_scopes(payload.requested_scopes),
            **({"client_secret_ref": client_secret_ref} if isinstance(client_secret_ref, str) else {}),
        }
        server.oauth_status = "OAUTH_CONFIGURED"
        server.oauth_last_error = None
    else:
        server = MCPServer(
            name=payload.endpoint,
            server_type="mcp",
            endpoint=payload.endpoint,
            transport="streamable_http",
            protocol_version=payload.protocol_version,
            auth_mode=AUTH_MODE_OAUTH,
            credential_ref=f"oauth/tokens/{uuid4().hex}.json",
            oauth_config={
                **({"client_id": payload.client_id} if payload.client_id else {}),
                "requested_scopes": normalize_requested_scopes(payload.requested_scopes),
            },
            oauth_status="OAUTH_CONFIGURED",
            status="active",
            trust_status=("lab_trusted" if is_exact_local_lab_endpoint(payload.endpoint) else "unknown"),
            security_status="not_analyzed",
        )
        db.add(server)
    db.flush()
    client_secret_ref = (server.oauth_config or {}).get("client_secret_ref")
    new_client_secret_ref: str | None = None
    try:
        if payload.client_secret:
            client_secret_ref = f"oauth/clients/{server.id}-{uuid4().hex}.secret"
            write_upstream_secret(client_secret_ref, payload.client_secret)
            new_client_secret_ref = client_secret_ref
            server.oauth_config = {**server.oauth_config, "client_secret_ref": client_secret_ref}
        record_control_plane_audit(
            db,
            actor=current.user,
            action=(
                "UPSTREAM_OAUTH_SERVER_RECONFIGURED"
                if retrying_configuration
                else "UPSTREAM_OAUTH_SERVER_REGISTERED"
            ),
            target_type="mcp_server",
            target_id=str(server.id),
            reason="Admin registered an OAuth-protected MCP server.",
            after_json={
                "endpoint": server.endpoint,
                "auth_mode": server.auth_mode,
                "requested_scopes": server.oauth_config.get("requested_scopes", []),
                "has_client_secret": client_secret_ref is not None,
                "reconfigured": retrying_configuration,
            },
        )
        db.commit()
        if (
            isinstance(previous_client_secret_ref, str)
            and previous_client_secret_ref != client_secret_ref
        ):
            delete_upstream_secret(previous_client_secret_ref)
    except Exception:
        db.rollback()
        if new_client_secret_ref:
            delete_upstream_secret(new_client_secret_ref)
        raise
    db.refresh(server)
    return server


@router.post("/servers/{server_id}/connect", response_model=OAuthConnectionStartResponse)
def begin_oauth_connection(
    server_id: int,
    current: AuthenticatedControlPlaneUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    server = _oauth_server(db, server_id)
    bootstrap = server.oauth_config or {}
    dynamic_client_secret_ref: str | None = None
    try:
        _validate_callback_uri(settings.upstream_oauth_callback_uri)
        configuration = discover_oauth_configuration(
            mcp_endpoint=server.endpoint,
            client_id=bootstrap.get("client_id") if isinstance(bootstrap.get("client_id"), str) else None,
            requested_scopes=list(bootstrap.get("requested_scopes") or []),
        )
        client_secret_ref = bootstrap.get("client_secret_ref")
        if "client_id" not in configuration:
            registration_endpoint = configuration.get("registration_endpoint")
            if not isinstance(registration_endpoint, str):
                raise UpstreamOAuthError("upstream_oauth_dynamic_registration_unsupported")
            registered_client = register_dynamic_oauth_client(
                registration_endpoint=registration_endpoint,
                redirect_uri=settings.upstream_oauth_callback_uri,
                scopes=configuration["scopes"],
            )
            configuration["client_id"] = registered_client["client_id"]
            configuration["client_registration"] = "dynamic"
            if "client_secret" in registered_client:
                dynamic_client_secret_ref = f"oauth/clients/{server.id}-{uuid4().hex}.secret"
                write_upstream_secret(dynamic_client_secret_ref, registered_client["client_secret"])
                client_secret_ref = dynamic_client_secret_ref
        if isinstance(client_secret_ref, str) and client_secret_ref:
            configuration["client_secret_ref"] = client_secret_ref
        _state, authorization_url, expires_at = create_oauth_attempt(
            attempt_directory=OAUTH_ATTEMPT_DIR,
            server_id=server.id,
            actor_user_id=current.user.id,
            redirect_uri=settings.upstream_oauth_callback_uri,
            authorization_endpoint=configuration["authorization_endpoint"],
            token_endpoint=configuration["token_endpoint"],
            client_id=configuration["client_id"],
            client_secret_ref=configuration.get("client_secret_ref"),
            resource=configuration["resource"],
            scopes=configuration["scopes"],
        )
    except UpstreamOAuthError as exc:
        if dynamic_client_secret_ref:
            delete_upstream_secret(dynamic_client_secret_ref)
        server.oauth_status = "OAUTH_ERROR"
        server.oauth_last_error = str(exc)
        record_control_plane_audit(
            db,
            actor=current.user,
            action="UPSTREAM_OAUTH_CONNECT_FAILED",
            target_type="mcp_server",
            target_id=str(server.id),
            result="FAILED",
            after_json={"endpoint": server.endpoint, "error_code": str(exc)},
        )
        db.commit()
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    server.oauth_config = configuration
    server.oauth_status = "AUTHORIZATION_PENDING"
    server.oauth_last_error = None
    record_control_plane_audit(
        db,
        actor=current.user,
        action="UPSTREAM_OAUTH_CONNECT_STARTED",
        target_type="mcp_server",
        target_id=str(server.id),
        reason="Admin initiated OAuth authorization for this MCP server.",
        after_json={
            "endpoint": server.endpoint,
            "authorization_server": configuration["authorization_server"],
            "scopes": configuration["scopes"],
        },
    )
    db.commit()
    return OAuthConnectionStartResponse(
        authorization_url=authorization_url,
        expires_at=expires_at.isoformat(),
    )


@router.get("/callback")
def complete_oauth_connection(
    state: str | None = Query(default=None, max_length=256),
    code: str | None = Query(default=None, max_length=8192),
    error: str | None = Query(default=None, max_length=128),
    db: Session = Depends(get_db),
):
    try:
        attempt = consume_oauth_attempt(attempt_directory=OAUTH_ATTEMPT_DIR, state=state or "")
    except UpstreamOAuthError:
        return _callback_redirect("failed")

    server_id = int(attempt["server_id"])
    server = db.get(MCPServer, server_id)
    actor = db.get(ControlPlaneUser, attempt["actor_user_id"])
    if (
        server is None
        or server.status == "archived"
        or server.auth_mode != AUTH_MODE_OAUTH
        or not server.credential_ref
        or actor is None
        or not actor.enabled
        or actor.role != "ADMIN"
    ):
        return _callback_redirect("failed", server_id)

    if error or not code:
        server.oauth_status = "OAUTH_ERROR"
        server.oauth_last_error = "upstream_oauth_authorization_denied"
        record_control_plane_audit(
            db,
            actor=actor,
            action="UPSTREAM_OAUTH_CONNECT_FAILED",
            target_type="mcp_server",
            target_id=str(server.id),
            result="FAILED",
            after_json={"endpoint": server.endpoint, "error_code": server.oauth_last_error},
        )
        db.commit()
        return _callback_redirect("failed", server_id)

    try:
        exchange_authorization_code(
            code=code,
            attempt=attempt,
            credential_ref=server.credential_ref,
        )
    except UpstreamOAuthError as exc:
        server.oauth_status = "OAUTH_ERROR"
        server.oauth_last_error = str(exc)
        record_control_plane_audit(
            db,
            actor=actor,
            action="UPSTREAM_OAUTH_CONNECT_FAILED",
            target_type="mcp_server",
            target_id=str(server.id),
            result="FAILED",
            after_json={"endpoint": server.endpoint, "error_code": str(exc)},
        )
        db.commit()
        return _callback_redirect("failed", server_id)

    server.oauth_status = "CONNECTED"
    server.oauth_connected_at = datetime.now(UTC).replace(tzinfo=None)
    server.oauth_last_error = None
    record_control_plane_audit(
        db,
        actor=actor,
        action="UPSTREAM_OAUTH_CONNECTED",
        target_type="mcp_server",
        target_id=str(server.id),
        reason="The framework completed an OAuth connection for this MCP server.",
        after_json={"endpoint": server.endpoint, "auth_mode": server.auth_mode},
    )
    db.commit()
    return _callback_redirect("connected", server_id)


@router.post("/servers/{server_id}/disconnect", response_model=OAuthConnectionStatus)
def disconnect_oauth_server(
    server_id: int,
    current: AuthenticatedControlPlaneUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    server = _oauth_server(db, server_id)
    if server.credential_ref:
        delete_upstream_secret(server.credential_ref)
    server.oauth_status = "OAUTH_CONFIGURED"
    server.oauth_connected_at = None
    server.oauth_last_error = None
    record_control_plane_audit(
        db,
        actor=current.user,
        action="UPSTREAM_OAUTH_DISCONNECTED",
        target_type="mcp_server",
        target_id=str(server.id),
        reason="Admin disconnected the framework-held OAuth credential.",
        after_json={"endpoint": server.endpoint, "auth_mode": server.auth_mode},
    )
    db.commit()
    return OAuthConnectionStatus(server_id=server.id, oauth_status=server.oauth_status)


def _oauth_server(db: Session, server_id: int) -> MCPServer:
    server = db.get(MCPServer, server_id)
    if server is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="mcp_server_not_found")
    if server.auth_mode != AUTH_MODE_OAUTH:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="mcp_server_not_oauth")
    if server.status == "archived":
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="mcp_server_archived")
    return server


def _validate_callback_uri(value: str) -> None:
    try:
        parsed = urlsplit(value)
    except ValueError as exc:
        raise UpstreamOAuthError("upstream_oauth_callback_uri_invalid") from exc
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise UpstreamOAuthError("upstream_oauth_callback_uri_invalid")
    if parsed.scheme == "http" and parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise UpstreamOAuthError("upstream_oauth_callback_https_required")


def _callback_redirect(result: str, server_id: int | None = None) -> RedirectResponse:
    suffix = f"?oauth={result}"
    if server_id is not None:
        suffix += f"&server_id={server_id}"
    return RedirectResponse(f"{settings.control_center_url}/#{suffix}", status_code=status.HTTP_303_SEE_OTHER)
