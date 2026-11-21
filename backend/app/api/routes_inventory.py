from datetime import datetime
from typing import Callable

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from common.mcp_endpoint import is_exact_local_lab_endpoint
from app.db.database import get_db
from app.models.mcp_server import MCPServer
from app.models.discovery_generation import MCPDiscoveryGeneration
from app.models.mcp_tool import MCPTool
from app.models.tool_analysis import ToolProtocolObservation
from app.schemas.inventory import (
    DiscoveryImportPayload, DiscoveryRequest, DiscoveryReservationRequest,
)
from app.services.control_plane_audit import record_control_plane_audit
from app.services.control_plane_auth import AuthenticatedControlPlaneUser, require_admin
from app.services.discovery_generation import (
    DiscoveryGenerationError, discovery_scope_key,
    trusted_discovery_context_digest,
    get_discovery_generation_status,
    fail_discovery_generation, publish_discovery_generation,
    reserve_discovery_generation,
)
from app.services.mcp_discovery import (
    MCPDiscoveryError, discover_http_mcp_server, is_valid_discovery_tool_name,
)
from app.services.published_configuration import PublishedConfigurationProvider
from app.services.signed_service_request import (
    PERMISSION_INVENTORY_IMPORT_DISCOVERY,
    VerifiedServiceRequest,
    require_internal_service_permission,
)
from app.services.server_security_metadata import refresh_server_security_status
from app.services.tda.configuration import STATUS_STALE
from app.services.tda_application.analysis_service import ToolAnalysisService
from proxy.protocol_profiles import LEGACY_PROFILE_ID
from proxy.protocol_revisions import ProtocolRevisionRegistry, ProtocolRevisionError

try:
    from common.mcp_endpoint import server_ref_for_server
except Exception:  # pragma: no cover - import fallback for unusual launch paths
    server_ref_for_server = None

router = APIRouter(prefix="/inventory", tags=["Inventory"])


@router.get("/admin/discovery-generations/latest")
def read_latest_discovery_generation(
    endpoint: str = Query(min_length=7, max_length=2048),
    _: AuthenticatedControlPlaneUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Admin-only read-only reconciliation; never replays tools/list.

    This endpoint reveals no auth context digest, bearer token, OAuth state,
    imported tool descriptions or credential material.
    """
    if db.get_bind().dialect.name != "postgresql":
        raise HTTPException(status_code=503, detail="discovery_postgresql_required")
    try:
        scope=discovery_scope_key(transport="streamable_http", endpoint=endpoint)
    except DiscoveryGenerationError as exc:
        raise HTTPException(status_code=422, detail=exc.code) from exc
    item=db.scalar(select(MCPDiscoveryGeneration).where(
        MCPDiscoveryGeneration.scope_key==scope,
    ).order_by(MCPDiscoveryGeneration.generation.desc()).limit(1))
    if item is None:
        raise HTTPException(status_code=404, detail="discovery_generation_not_recorded")
    return {
        "generation_id":item.id,
        "generation":item.generation,
        "status":item.status,
        "error_code":item.error_code,
        "started_at":item.started_at,
        "completed_at":item.completed_at,
        "terminal":item.status in {"PUBLISHED", "FAILED", "SUPERSEDED"},
        "may_retry_import":False,
        "interpretation":"Only the newest durable discovery generation for this endpoint.",
    }


@router.get("/discovery-generations/{generation_id}")
def read_signed_discovery_generation(
    generation_id: str,
    _: VerifiedServiceRequest = Depends(
        require_internal_service_permission(PERMISSION_INVENTORY_IMPORT_DISCOVERY)
    ),
    db: Session = Depends(get_db),
):
    """Read-only reconciliation for signed Discovery clients.

    A lost import response MUST NOT trigger automatic re-import or replay
    of tools/list. Never disclose the stored auth/credential context.
    """
    try:
        return get_discovery_generation_status(db, generation_id=generation_id)
    except DiscoveryGenerationError as exc:
        db.rollback()
        code = exc.code
        if code == "discovery_generation_unknown":
            http_status = status.HTTP_404_NOT_FOUND
        elif code == "discovery_generation_id_invalid":
            http_status = status.HTTP_422_UNPROCESSABLE_ENTITY
        else:
            http_status = status.HTTP_503_SERVICE_UNAVAILABLE
        raise HTTPException(status_code=http_status, detail=code) from exc


@router.post("/reserve-discovery")
def reserve_signed_discovery(
    payload: DiscoveryReservationRequest,
    _: VerifiedServiceRequest = Depends(
        require_internal_service_permission(PERMISSION_INVENTORY_IMPORT_DISCOVERY)
    ),
    db: Session = Depends(get_db),
):
    try:
        context_hash = trusted_discovery_context_digest(
            auth_mode=payload.auth_mode, credential_ref=payload.credential_ref,
            protocol_version=payload.protocol_version, profile_id=payload.profile_id,
        )
        generation = reserve_discovery_generation(
            db, endpoint=payload.endpoint, transport=payload.transport,
            context_hash=context_hash,
        )
        result = {
            "generation_id": generation.id,
            "generation": generation.generation,
            "context_hash": context_hash,
        }
        db.commit()
        return result
    except Exception as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="discovery_generation_reservation_unavailable",
        ) from exc


def _import_signed_discovery_if_current(
    payload: DiscoveryImportPayload, db: Session,
) -> dict:
    """A signed worker cannot overwrite a newer server security context.

    Lock the existing server row until the fenced import transaction commits.
    Rotated credentials or profiles require a new privileged discovery.
    """
    server = db.scalar(
        select(MCPServer).where(
            MCPServer.endpoint == payload.server.endpoint,
            MCPServer.transport == payload.server.transport,
        ).with_for_update().execution_options(populate_existing=True)
    )
    if server is not None and (
        server.auth_mode != payload.server.auth_mode
        or server.credential_ref != payload.server.credential_ref
        or (server.protocol_version is not None and
            server.protocol_version != payload.server.protocol_version)
        # An unpinned profile returned by tools/list is a fresh
        # observation requiring analysis, not an automatic permission.
        # Only a profile explicitly pinned by the signed reservation
        # can be treated as a stable authorization context.
        or (payload.reserved_profile_id is not None
            and server.preferred_upstream_profile is not None
            and server.preferred_upstream_profile
            != payload.reserved_profile_id)
        or bool(server.oauth_config)
        or server.status != "active"
    ):
        raise DiscoveryGenerationError("discovery_existing_server_context_changed")
    return import_discovery_payload(payload, db)


def _validate_negotiated_discovery_protocol(
    server,
) -> None:
    """Require a recognized, internally coherent observed MCP version.

    A reservation pins the request hint; a validated network negotiation
    can legitimately select another supported protocol version.
    """
    negotiated = server.negotiated_protocol_version
    version = server.protocol_version
    if negotiated is not None and version != negotiated:
        raise DiscoveryGenerationError("discovery_protocol_verdict_inconsistent")
    if (
        version is not None
        and server.supported_protocol_versions is not None
        and version not in server.supported_protocol_versions
    ):
        raise DiscoveryGenerationError("discovery_protocol_verdict_inconsistent")
    if version is not None:
        try:
            ProtocolRevisionRegistry().get(version)
        except ProtocolRevisionError as exc:
            raise DiscoveryGenerationError(
                "discovery_protocol_version_unsupported"
            ) from exc


@router.post("/import-discovery")
def import_discovery(
    payload: DiscoveryImportPayload,
    _: VerifiedServiceRequest = Depends(
        require_internal_service_permission(PERMISSION_INVENTORY_IMPORT_DISCOVERY)
    ),
    db: Session = Depends(get_db),
):
    if not payload.generation_id:
        raise HTTPException(
            status_code=status.HTTP_428_PRECONDITION_REQUIRED,
            detail="discovery_generation_required",
        )
    try:
        if (
            payload.reserved_profile_id is not None
            and payload.reserved_profile_id != payload.server.preferred_upstream_profile
        ):
            raise DiscoveryGenerationError("discovery_profile_changed")
        _validate_negotiated_discovery_protocol(payload.server)
        context_hash = trusted_discovery_context_digest(
            auth_mode=payload.server.auth_mode,
            credential_ref=payload.server.credential_ref,
            protocol_version=(
                payload.reserved_protocol_version
                if payload.reserved_protocol_version is not None
                else payload.server.protocol_version
            ),
            profile_id=payload.reserved_profile_id,
        )
        result = publish_discovery_generation(
            db, generation_id=payload.generation_id,
            expected_scope_key=discovery_scope_key(
                transport=payload.server.transport, endpoint=payload.server.endpoint,
            ),
            expected_context_hash=context_hash,
            import_callback=lambda: _import_signed_discovery_if_current(payload, db),
            validate_before_publish=lambda: _assert_discovery_context_still_current(
                expected_hash=context_hash,
                auth_mode=payload.server.auth_mode,
                credential_ref=payload.server.credential_ref,
                protocol_version=(
                    payload.reserved_protocol_version
                    if payload.reserved_protocol_version is not None
                    else payload.server.protocol_version
                ),
                profile_id=payload.reserved_profile_id,
            ),
        )
        db.commit()
        return result
    except DiscoveryGenerationError as exc:
        db.rollback()
        if exc.code == "discovery_generation_expired":
            _mark_admin_discovery_failed(db, payload.generation_id, exc.code)
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail=exc.code,
        ) from exc
    except Exception:
        _mark_admin_discovery_failed(db, payload.generation_id, "discovery_import_failed")
        raise


def _assert_discovery_context_still_current(
    *, expected_hash: str, auth_mode: str, credential_ref: str | None,
    protocol_version: str | None, profile_id: str | None,
    oauth_config: dict | None = None,
) -> None:
    current_hash = trusted_discovery_context_digest(
        auth_mode=auth_mode, credential_ref=credential_ref,
        protocol_version=protocol_version, profile_id=profile_id,
        oauth_config=oauth_config,
    )
    if current_hash != expected_hash:
        raise DiscoveryGenerationError("discovery_context_changed")


def _reserve_admin_discovery(
    db: Session, *, endpoint: str, transport: str, context_hash: str,
) -> str:
    try:
        generation = reserve_discovery_generation(
            db, endpoint=endpoint, transport=transport,
            context_hash=context_hash,
        )
        generation_id = generation.id
        db.commit()  # Reserve durably BEFORE any upstream/network call.
        return generation_id
    except Exception as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="discovery_generation_reservation_unavailable",
        ) from exc


def _mark_admin_discovery_failed(db: Session, generation_id: str, reason: str) -> None:
    db.rollback()
    try:
        fail_discovery_generation(
            db, generation_id=generation_id, error_code=reason,
        )
        db.commit()
    except Exception:
        db.rollback()
        # Do not replace the original transport/import exception with a
        # possibly broken secondary failure-logging attempt.


def _publish_admin_discovery(
    db: Session, *, generation_id: str, import_payload: DiscoveryImportPayload,
    current: AuthenticatedControlPlaneUser, endpoint: str, reason: str,
    metadata: dict,
    context_hash: str,
    import_callback: Callable[[], dict] | None = None,
    verify_context_at_commit: Callable[[], None] | None = None,
) -> dict:
    try:
        result = publish_discovery_generation(
            db, generation_id=generation_id,
            expected_scope_key=discovery_scope_key(
                transport=import_payload.server.transport,
                endpoint=import_payload.server.endpoint,
            ),
            expected_context_hash=context_hash,
            import_callback=import_callback or (
                lambda: import_discovery_payload(import_payload, db)
            ),
            validate_before_publish=verify_context_at_commit,
        )
        record_control_plane_audit(
            db, actor=current.user, action="MCP_DISCOVERY_IMPORTED",
            target_type="mcp_server", target_id=str(result["server_id"]),
            reason=reason,
            after_json={"endpoint": endpoint,
                        "tool_count": result["total_tools_imported"],
                        **metadata},
        )
        db.commit()
        return result
    except DiscoveryGenerationError as exc:
        db.rollback()
        if exc.code == "discovery_generation_expired":
            _mark_admin_discovery_failed(db, generation_id, exc.code)
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=exc.code,
        ) from exc
    except Exception:
        _mark_admin_discovery_failed(db, generation_id, "discovery_import_failed")
        raise


@router.post("/discover-http")
def discover_http_inventory(
    payload: DiscoveryRequest,
    current: AuthenticatedControlPlaneUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    context_hash = trusted_discovery_context_digest(
        auth_mode=payload.auth_mode, credential_ref=payload.credential_ref,
        protocol_version=payload.protocol_version, profile_id=None,
    )
    generation_id = _reserve_admin_discovery(
        db, endpoint=payload.endpoint, transport="streamable_http",
        context_hash=context_hash,
    )
    try:
        discovery = discover_http_mcp_server(
            mcp_endpoint=payload.endpoint,
            protocol_version=payload.protocol_version,
            auth_mode=payload.auth_mode,
            credential_ref=payload.credential_ref,
        )
    except MCPDiscoveryError as exc:
        _mark_admin_discovery_failed(db, generation_id, "mcp_discovery_failed")
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=exc.args[0]) from exc
    except Exception as exc:
        _mark_admin_discovery_failed(db, generation_id, "mcp_discovery_failed")
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="mcp_discovery_failed") from exc

    try:
        import_payload = DiscoveryImportPayload.model_validate(discovery["payload"])
    except Exception:
        _mark_admin_discovery_failed(db, generation_id, "discovery_payload_invalid")
        raise
    staged_new_catalog = False
    from os import getenv
    if getenv("MCP_DISCOVERY_STAGED_ANALYSIS") == "1":
        from app.services.discovery_analysis_staging import stage_new_catalog_analysis
        try:
            staged_new_catalog = stage_new_catalog_analysis(
                payload=import_payload,
                generation_id=generation_id,
                expected_context_hash=context_hash,
            )
        except Exception:
            _mark_admin_discovery_failed(
                db, generation_id, "discovery_stage_failed"
            )
            raise
    def import_if_same_context() -> dict:
        # BEARER material can rotate under an unchanged reference while
        # the remote tools/list call is running. Re-resolve the trusted
        # credential *inside the fenced publication callback*, not just
        # once before network discovery.
        if trusted_discovery_context_digest(
            auth_mode=payload.auth_mode, credential_ref=payload.credential_ref,
            protocol_version=payload.protocol_version, profile_id=None,
        ) != context_hash:
            raise DiscoveryGenerationError("discovery_context_changed")
        if (
            import_payload.server.auth_mode != payload.auth_mode
            or import_payload.server.credential_ref != payload.credential_ref
        ):
            raise DiscoveryGenerationError("discovery_context_changed")
        _validate_negotiated_discovery_protocol(import_payload.server)
        existing = db.scalar(
            select(MCPServer).where(
                MCPServer.endpoint == payload.endpoint,
                MCPServer.transport == "streamable_http",
            ).with_for_update().execution_options(populate_existing=True)
        )
        if existing is not None and (
            existing.auth_mode != payload.auth_mode
            or existing.credential_ref != payload.credential_ref
            or (existing.protocol_version and
                existing.protocol_version != payload.protocol_version)
            or existing.oauth_config
        ):
            raise DiscoveryGenerationError("discovery_existing_server_context_changed")
        if staged_new_catalog:
            return import_discovery_payload(
                import_payload, db, staged_generation_id=generation_id,
            )
        # Preserve the exact legacy two-argument call when staging is off:
        # signed workers and existing injector/adapter interfaces must not
        # need a new optional parameter to keep working.
        return import_discovery_payload(import_payload, db)

    return _publish_admin_discovery(
        db, generation_id=generation_id, import_payload=import_payload,
        current=current, endpoint=payload.endpoint,
        reason="Admin requested governed MCP discovery.",
        metadata={}, context_hash=context_hash,
        import_callback=import_if_same_context,
        verify_context_at_commit=lambda: _assert_discovery_context_still_current(
            expected_hash=context_hash, auth_mode=payload.auth_mode,
            credential_ref=payload.credential_ref,
            protocol_version=payload.protocol_version, profile_id=None,
        ),
    )


@router.post("/servers/{server_id}/discover")
def discover_registered_http_inventory(
    server_id: int,
    current: AuthenticatedControlPlaneUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    server = db.get(MCPServer, server_id)
    if server is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="mcp_server_not_found")
    # Capture the exact authenticated context before a commit expires the
    # ORM identity and the network call. A server credential change is
    # validated again at publication.
    endpoint = server.endpoint
    transport = server.transport
    protocol_version = server.protocol_version or "2025-11-25"
    auth_mode = server.auth_mode
    credential_ref = server.credential_ref
    oauth_config = server.oauth_config
    preferred_profile = server.preferred_upstream_profile
    server_status = server.status
    context_hash = trusted_discovery_context_digest(
        auth_mode=auth_mode, credential_ref=credential_ref,
        protocol_version=protocol_version, profile_id=preferred_profile,
        oauth_config=oauth_config,
    )
    generation_id = _reserve_admin_discovery(
        db, endpoint=endpoint, transport=transport,
        context_hash=context_hash,
    )
    try:
        discovery = discover_http_mcp_server(
            mcp_endpoint=endpoint,
            protocol_version=protocol_version,
            auth_mode=auth_mode,
            credential_ref=credential_ref,
            oauth_config=oauth_config,
        )
    except MCPDiscoveryError as exc:
        _mark_admin_discovery_failed(db, generation_id, "mcp_discovery_failed")
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=exc.args[0]) from exc
    except Exception as exc:
        _mark_admin_discovery_failed(db, generation_id, "mcp_discovery_failed")
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="mcp_discovery_failed") from exc

    try:
        import_payload = DiscoveryImportPayload.model_validate(discovery["payload"])
    except Exception:
        _mark_admin_discovery_failed(db, generation_id, "discovery_payload_invalid")
        raise

    def import_if_current() -> dict:
        db.refresh(server)
        if trusted_discovery_context_digest(
            auth_mode=auth_mode, credential_ref=credential_ref,
            protocol_version=protocol_version, profile_id=preferred_profile,
            oauth_config=oauth_config,
        ) != context_hash:
            raise DiscoveryGenerationError("discovery_context_changed")
        if (
            server.endpoint != endpoint or server.transport != transport
            or server.auth_mode != auth_mode
            or server.credential_ref != credential_ref
            or server.oauth_config != oauth_config
            or (server.protocol_version or "2025-11-25") != protocol_version
            or server.preferred_upstream_profile != preferred_profile
            or server.status != server_status
        ):
            raise DiscoveryGenerationError("discovery_credentials_changed")
        _validate_negotiated_discovery_protocol(import_payload.server)
        if (
            import_payload.server.endpoint != endpoint
            or import_payload.server.transport != transport
            or import_payload.server.auth_mode != auth_mode
            or import_payload.server.credential_ref != credential_ref
            or (import_payload.server.protocol_version is not None
                and import_payload.server.protocol_version != protocol_version)
        ):
            raise DiscoveryGenerationError("discovery_context_changed")
        return import_discovery_payload(import_payload, db)

    return _publish_admin_discovery(
        db, generation_id=generation_id, import_payload=import_payload,
        current=current, endpoint=endpoint,
        reason="Admin requested governed MCP rediscovery.",
        metadata={"auth_mode": auth_mode}, context_hash=context_hash,
        import_callback=import_if_current,
        verify_context_at_commit=lambda: _assert_discovery_context_still_current(
            expected_hash=context_hash, auth_mode=auth_mode,
            credential_ref=credential_ref,
            protocol_version=protocol_version, profile_id=preferred_profile,
            oauth_config=oauth_config,
        ),
    )


def validate_import_discovery_generation(payload: DiscoveryImportPayload) -> None:
    """Reject ambiguous profiles before modifying the inventory or analyses."""
    seen_pairs: set[tuple[str, str]] = set()
    default_profile = payload.server.preferred_upstream_profile or LEGACY_PROFILE_ID
    for tool in payload.tools:
        if not is_valid_discovery_tool_name(tool.name):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="mcp_discovery_tool_name_invalid",
            )
        profile = tool.upstream_protocol_profile_id or default_profile
        identity = (tool.name, profile)
        if identity in seen_pairs:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="mcp_discovery_duplicate_tool_profile",
            )
        seen_pairs.add(identity)


def import_discovery_payload(
    payload: DiscoveryImportPayload,
    db: Session,
    *,
    staged_generation_id: str | None = None,
) -> dict:
    validate_import_discovery_generation(payload)
    # Ensure a concurrently published config cannot invalidate the stage
    # between checking its contract hash and committing the inventory.
    # All non-staged callers retain their original locking behavior.
    if staged_generation_id is not None:
        from app.services.discovery_analysis_staging import (
            lock_staged_configuration_authority,
        )
        lock_staged_configuration_authority(db)
    # Verify immutable evidence before any inventory mutation.
    try:
        config_snapshot = PublishedConfigurationProvider(db).load_active_snapshot()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="published_configuration_unavailable",
        ) from exc
    staged = None
    if staged_generation_id is not None:
        from app.services.discovery_analysis_staging import consume_new_catalog_stage
        staged = consume_new_catalog_stage(
            db=db, payload=payload, generation_id=staged_generation_id,
            active_configuration_hash=config_snapshot.content_hash,
        )
    now = datetime.utcnow()
    server = upsert_server(payload, db, now)
    db.flush()

    created_tool_names: set[str] = set()
    updated_tool_names: set[str] = set()
    current_analysis_statuses: dict[str, str] = {}
    analysis_service = ToolAnalysisService()
    seen_tool_names: set[str] = set()
    seen_profile_pairs: set[tuple[str, str]] = set()
    server_ref = _server_ref(server)

    for tool_payload in payload.tools:
        profile_id = (
            tool_payload.upstream_protocol_profile_id
            or server.preferred_upstream_profile
            or LEGACY_PROFILE_ID
        )
        seen_tool_names.add(tool_payload.name)
        seen_profile_pairs.add((tool_payload.name, profile_id))
        existing_tool = db.scalar(
            select(MCPTool).where(
                MCPTool.server_id == server.id,
                MCPTool.name == tool_payload.name,
            )
        )
        if existing_tool is None:
            existing_tool = MCPTool(server_id=server.id, name=tool_payload.name)
            db.add(existing_tool)
            created_tool_names.add(tool_payload.name)
        else:
            updated_tool_names.add(tool_payload.name)

        apply_tool_metadata(existing_tool, tool_payload.model_dump(), now)
        db.flush()
        profile_snapshot = _tool_profile_snapshot(
            config_snapshot,
            server_ref,
            existing_tool.name,
        )
        analysis = analysis_service.observe_and_analyze(
            db=db,
            tool=existing_tool,
            server_ref=server_ref,
            profile_snapshot=profile_snapshot,
            upstream_protocol_profile_id=profile_id,
            **(
                {"precomputed_analysis": staged[(tool_payload.name, profile_id)]}
                if staged is not None else {}
            ),
        )
        current_analysis_statuses[existing_tool.name] = analysis.analysis_status

    mark_absent_discovery_observations_stale(
        db,
        server=server,
        seen_tool_names=seen_tool_names,
        seen_profile_pairs=seen_profile_pairs,
    )
    refresh_server_security_status(db, server.id, scanned_at=datetime.utcnow())
    db.flush()
    db.refresh(server)

    return {
        "server_id": server.id,
        "server_status": "created" if getattr(server, "_was_created", False) else "updated",
        "tools_created": len(created_tool_names),
        "tools_updated": len(updated_tool_names - created_tool_names),
        "total_tools_imported": len(seen_tool_names),
        "tools_quarantined": sum(
            status not in {"APPROVED", "ADMIN_ALLOWED"}
            for status in current_analysis_statuses.values()
        ),
        "tools_approved_current": sum(
            status in {"APPROVED", "ADMIN_ALLOWED"}
            for status in current_analysis_statuses.values()
        ),
    }


def upsert_server(
    payload: DiscoveryImportPayload,
    db: Session,
    now: datetime,
) -> MCPServer:
    server_payload = payload.server
    server = db.scalar(
        select(MCPServer).where(
            MCPServer.endpoint == server_payload.endpoint,
            MCPServer.transport == server_payload.transport,
        )
    )
    was_created = server is None

    if server is None:
        server = MCPServer(
            name=server_payload.server_info_name or server_payload.endpoint,
            server_type="mcp",
            endpoint=server_payload.endpoint,
            transport=server_payload.transport,
            status="active",
        )
        db.add(server)

    server.name = server_payload.server_info_name or server.name
    server.server_type = "mcp"
    server.status = "active"
    server.endpoint = server_payload.endpoint
    server.transport = server_payload.transport
    server.protocol_version = server_payload.protocol_version
    server.server_info_name = server_payload.server_info_name
    server.server_info_title = server_payload.server_info_title
    server.server_info_version = server_payload.server_info_version
    server.server_info_description = server_payload.server_info_description
    server.server_info_icons = server_payload.server_info_icons
    server.server_info_website_url = server_payload.server_info_website_url
    server.capabilities = server_payload.capabilities
    server.instructions = server_payload.instructions
    server.raw_initialize_result = server_payload.raw_initialize_result
    server.detected_protocol_era = server_payload.detected_protocol_era
    server.supported_protocol_versions = server_payload.supported_protocol_versions
    server.preferred_protocol_version = server_payload.preferred_protocol_version
    server.negotiated_protocol_version = server_payload.negotiated_protocol_version
    server.protocol_transport_kind = server_payload.protocol_transport_kind
    server.protocol_verdict_expires_at = server_payload.protocol_verdict_expires_at
    server.supported_protocol_profiles = (
        server_payload.supported_protocol_profiles or [LEGACY_PROFILE_ID]
    )
    server.preferred_upstream_profile = (
        server_payload.preferred_upstream_profile or LEGACY_PROFILE_ID
    )
    server.last_protocol_probe_at = now
    server.protocol_probe_status = server_payload.protocol_probe_status or "not_probed"
    server.protocol_probe_error = server_payload.protocol_probe_error
    server.last_seen_at = now
    server.auth_mode = server_payload.auth_mode
    server.credential_ref = server_payload.credential_ref

    if is_local_lab_endpoint(server_payload.endpoint):
        server.trust_status = "lab_trusted"
    elif was_created or server.trust_status == "archived":
        # New remote MCPs and reactivated archived remotes must start untrusted.
        # Preserve an explicit administrator trust decision across normal rediscovery.
        server.trust_status = "unknown"
    server.security_status = "pending_analysis"

    setattr(server, "_was_created", was_created)
    return server


def apply_tool_metadata(tool: MCPTool, tool_payload: dict, now: datetime) -> None:
    tool.title = tool_payload.get("title")
    tool.description = tool_payload.get("description")
    tool.icons = tool_payload.get("icons")
    tool.input_schema = tool_payload.get("input_schema")
    tool.output_schema = tool_payload.get("output_schema")
    tool.annotations = tool_payload.get("annotations")
    tool.execution = tool_payload.get("execution")
    tool.raw_tool_definition = tool_payload.get("raw_tool_definition")
    tool.status = "QUARANTINED"
    tool.status_reason = "NEWLY_DISCOVERED_NOT_ANALYZED"
    tool.last_analyzed_at = now

    enrichment = security_enrichment_for_tool(tool.name)
    tool.sensitivity = enrichment["sensitivity"]
    tool.risk_score = enrichment["risk_score"]
    tool.policy_status = enrichment["policy_status"]
    tool.is_sensitive = enrichment["is_sensitive"]


def mark_absent_discovery_observations_stale(
    db: Session,
    *,
    server: MCPServer,
    seen_tool_names: set[str],
    seen_profile_pairs: set[tuple[str, str]],
) -> None:
    profile_ids = set(server.supported_protocol_profiles or [])
    if not profile_ids:
        profile_ids.add(server.preferred_upstream_profile or LEGACY_PROFILE_ID)
    observations = db.scalars(
        select(ToolProtocolObservation)
        .join(MCPTool, MCPTool.id == ToolProtocolObservation.tool_id)
        .where(
            MCPTool.server_id == server.id,
            ToolProtocolObservation.upstream_protocol_profile_id.in_(profile_ids),
        )
    ).all()
    for observation in observations:
        pair = (observation.tool_name, observation.upstream_protocol_profile_id)
        if pair not in seen_profile_pairs:
            observation.analysis_state = STATUS_STALE

    tools = db.scalars(select(MCPTool).where(MCPTool.server_id == server.id)).all()
    for tool in tools:
        if tool.name in seen_tool_names:
            continue
        tool.analysis_status = STATUS_STALE
        tool.review_status = STATUS_STALE
        tool.policy_status = STATUS_STALE
        tool.status = STATUS_STALE
        tool.approved_fingerprint_match = False


def _server_ref(server: MCPServer) -> str:
    payload = {
        "transport": server.transport,
        "endpoint": server.endpoint,
    }
    if server_ref_for_server is not None:
        return server_ref_for_server(payload)
    return f"{server.transport or 'streamable_http'}:{server.endpoint}"


def _tool_profile_snapshot(config_snapshot, server_ref: str, tool_name: str) -> dict | None:
    try:
        contract = config_snapshot.get_tool_security_contract(
            server_ref=server_ref,
            tool_name=tool_name,
        )
    except Exception:
        return None
    return {
        "revision": config_snapshot.content_hash,
        "schema_version": 2,
        "contract_hash": contract.contract_hash,
        "contract": contract.model_dump(mode="json"),
    }


def is_local_lab_endpoint(endpoint: str) -> bool:
    return is_exact_local_lab_endpoint(endpoint)


def security_enrichment_for_tool(tool_name: str) -> dict:
    _ = tool_name
    return {
        "sensitivity": "unknown",
        "risk_score": 0,
        "policy_status": "pending_review",
        "is_sensitive": False,
    }
