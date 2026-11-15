from __future__ import annotations

from datetime import UTC, datetime
from hashlib import sha256
from hmac import compare_digest
from uuid import uuid4
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from common.mcp_endpoint import is_exact_local_lab_endpoint
from common.upstream_auth import (
    AUTH_MODE_OAUTH,
    UPSTREAM_SECRET_DIR,
    delete_upstream_secret,
    oauth_credential_lock,
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
    validate_authorization_response_issuer,
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
    restoring_archived = (
        existing is not None
        and existing.auth_mode == AUTH_MODE_OAUTH
        and existing.status == "archived"
    )
    retrying_configuration = (
        existing is not None
        and existing.auth_mode == AUTH_MODE_OAUTH
        and existing.oauth_status in {"OAUTH_CONFIGURED", "OAUTH_ERROR"}
        and (existing.last_seen_at is None or restoring_archived)
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
            **({"expected_authorization_server": payload.expected_authorization_server}
               if payload.expected_authorization_server
               else {"expected_authorization_server": previous_configuration["expected_authorization_server"]}
               if isinstance(previous_configuration.get("expected_authorization_server"), str)
               and (not payload.client_id or payload.client_id == previous_client_id)
               else {}),
            **({"authorization_server": previous_configuration["authorization_server"]}
               if isinstance(previous_configuration.get("authorization_server"), str)
               and (not payload.client_id or payload.client_id == previous_client_id)
               else {}),
        }
        server.oauth_status = "OAUTH_CONFIGURED"
        server.oauth_last_error = None
        if restoring_archived:
            server.status = "active"
            server.trust_status = (
                "lab_trusted"
                if is_exact_local_lab_endpoint(payload.endpoint)
                else "unknown"
            )
            server.security_status = "not_analyzed"
            server.credential_ref = f"oauth/tokens/{uuid4().hex}.json"
            server.oauth_connected_at = None
            server.last_seen_at = None
            server.last_scan_at = None
            server.server_info_name = None
            server.server_info_title = None
            server.server_info_version = None
            server.server_info_description = None
            server.server_info_icons = None
            server.server_info_website_url = None
            server.capabilities = None
            server.instructions = None
            server.raw_initialize_result = None
            server.detected_protocol_era = None
            server.supported_protocol_versions = None
            server.preferred_protocol_version = None
            server.negotiated_protocol_version = None
            server.protocol_transport_kind = None
            server.protocol_verdict_expires_at = None
            server.supported_protocol_profiles = None
            server.preferred_upstream_profile = None
            server.last_protocol_probe_at = None
            server.protocol_probe_status = None
            server.protocol_probe_error = None
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
                **({"expected_authorization_server": payload.expected_authorization_server}
                   if payload.expected_authorization_server else {}),
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
                "UPSTREAM_OAUTH_SERVER_RESTORED"
                if restoring_archived
                else "UPSTREAM_OAUTH_SERVER_RECONFIGURED"
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
                "reconfigured": retrying_configuration and not restoring_archived,
                "restored": restoring_archived,
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
    server = _oauth_server(db, server_id, lock=True)
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
        previous_issuer = bootstrap.get("authorization_server")
        current_issuer = configuration.get("authorization_server")
        expected_issuer = bootstrap.get("expected_authorization_server") or previous_issuer
        if client_secret_ref and not expected_issuer:
            # Remote MCP metadata alone may not select an issuer that
            # receives an independently pre-registered client secret.
            raise UpstreamOAuthError("upstream_oauth_expected_issuer_binding_missing")
        if expected_issuer and expected_issuer != current_issuer:
            raise UpstreamOAuthError("upstream_oauth_client_authority_changed")
        if (
            isinstance(previous_issuer, str)
            and previous_issuer
            and previous_issuer != current_issuer
        ):
            # An OAuth client registration/secret is scoped to its AS.
            # A new issuer requires an explicit new client registration.
            raise UpstreamOAuthError("upstream_oauth_client_authority_changed")
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
        # Every authorization flow starts a new credential generation.
        # A token issued for an older configuration can never be promoted.
        configuration["credential_generation"] = str(uuid4())
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
            authorization_server=configuration["authorization_server"],
            credential_generation=configuration["credential_generation"],
            authorization_response_iss_parameter_supported=configuration.get(
                "authorization_response_iss_parameter_supported", False
            ),
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

    # Bind the currently authorized flow to this exact server. Only a hash
    # of the random OAuth state is persisted; new connects supersede old.
    server.oauth_config = {
        **configuration,
        "active_attempt_state_sha256": sha256(_state.encode("ascii")).hexdigest(),
    }
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
    iss: str | None = Query(default=None, max_length=2048),
    db: Session = Depends(get_db),
    request: Request = None,
):
    # FastAPI normally chooses one value for repeated parameters. Reject
    # ambiguity before consuming state or issuing any token request.
    if request is not None:
        for parameter in ("state", "code", "error", "iss"):
            if len(request.query_params.getlist(parameter)) > 1:
                return _callback_redirect("failed")
    try:
        attempt = consume_oauth_attempt(attempt_directory=OAUTH_ATTEMPT_DIR, state=state or "")
    except UpstreamOAuthError:
        return _callback_redirect("failed")

    server_id = int(attempt["server_id"])
    # Hold PostgreSQL row lock through exchange and commit. A disconnect or
    # reconfiguration cannot interleave with token writes and revive a flow.
    server = db.get(MCPServer, server_id, with_for_update=True)
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

    active_state_hash = (server.oauth_config or {}).get("active_attempt_state_sha256")
    received_hash = sha256((state or "").encode("utf-8")).hexdigest()
    if (
        server.oauth_status != "AUTHORIZATION_PENDING"
        or not isinstance(active_state_hash, str)
        or len(active_state_hash) != 64
        or not compare_digest(active_state_hash, received_hash)
        or attempt.get("authorization_server") != (server.oauth_config or {}).get("authorization_server")
        or attempt.get("client_id") != (server.oauth_config or {}).get("client_id")
        or attempt.get("resource") != (server.oauth_config or {}).get("resource")
    ):
        return _callback_redirect("failed", server_id)

    try:
        validate_authorization_response_issuer(attempt=attempt, iss=iss)
    except UpstreamOAuthError as exc:
        server.oauth_config = {k: v for k, v in (server.oauth_config or {}).items() if k != "active_attempt_state_sha256"}
        server.oauth_status = "OAUTH_ERROR"
        server.oauth_last_error = str(exc)
        record_control_plane_audit(
            db, actor=actor, action="UPSTREAM_OAUTH_CONNECT_FAILED",
            target_type="mcp_server", target_id=str(server.id), result="FAILED",
            after_json={"endpoint": server.endpoint, "error_code": str(exc)},
        )
        db.commit()
        return _callback_redirect("failed", server_id)

    if error or not code:
        server.oauth_config = {k: v for k, v in (server.oauth_config or {}).items() if k != "active_attempt_state_sha256"}
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
        with oauth_credential_lock(server.credential_ref):
            exchange_authorization_code(
                code=code,
                attempt=attempt,
                credential_ref=server.credential_ref,
            )
    except UpstreamOAuthError as exc:
        server.oauth_config = {k: v for k, v in (server.oauth_config or {}).items() if k != "active_attempt_state_sha256"}
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

    server.oauth_config = {k: v for k, v in (server.oauth_config or {}).items() if k != "active_attempt_state_sha256"}
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
    server = _oauth_server(db, server_id, lock=True)
    if server.credential_ref:
        with oauth_credential_lock(server.credential_ref):
            delete_upstream_secret(server.credential_ref)
    # Revoking the active generation is persistent and fail-closed even if
    # the OAuth state file is later delivered by the authorization server.
    server.oauth_config = {
        k: v for k, v in (server.oauth_config or {}).items()
        if k != "active_attempt_state_sha256"
    }
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


def _oauth_server(db: Session, server_id: int, *, lock: bool = False) -> MCPServer:
    server = (
        db.get(MCPServer, server_id, with_for_update=True)
        if lock else db.get(MCPServer, server_id)
    )
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
