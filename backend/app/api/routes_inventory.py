from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from common.mcp_endpoint import is_exact_local_lab_endpoint
from app.db.database import get_db
from app.models.mcp_server import MCPServer
from app.models.mcp_tool import MCPTool
from app.schemas.inventory import DiscoveryImportPayload, DiscoveryRequest
from app.services.control_plane_audit import record_control_plane_audit
from app.services.control_plane_auth import AuthenticatedControlPlaneUser, require_admin
from app.services.mcp_discovery import MCPDiscoveryError, discover_http_mcp_server
from app.services.published_configuration import PublishedConfigurationProvider
from app.services.signed_service_request import (
    PERMISSION_INVENTORY_IMPORT_DISCOVERY,
    VerifiedServiceRequest,
    require_internal_service_permission,
)
from app.services.tool_analysis import ToolAnalysisService
from proxy.protocol_profiles import LEGACY_PROFILE_ID

try:
    from proxy.tool_security_profiles import server_ref_for_server
except Exception:  # pragma: no cover - import fallback for unusual launch paths
    server_ref_for_server = None

router = APIRouter(prefix="/inventory", tags=["Inventory"])


@router.post("/import-discovery")
def import_discovery(
    payload: DiscoveryImportPayload,
    _: VerifiedServiceRequest = Depends(
        require_internal_service_permission(PERMISSION_INVENTORY_IMPORT_DISCOVERY)
    ),
    db: Session = Depends(get_db),
):
    result = import_discovery_payload(payload, db)
    db.commit()
    return result


@router.post("/discover-http")
def discover_http_inventory(
    payload: DiscoveryRequest,
    current: AuthenticatedControlPlaneUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    try:
        discovery = discover_http_mcp_server(
            mcp_endpoint=payload.endpoint,
            protocol_version=payload.protocol_version,
            auth_mode=payload.auth_mode,
            credential_ref=payload.credential_ref,
        )
    except MCPDiscoveryError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=exc.args[0]) from exc
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="mcp_discovery_failed") from exc

    import_payload = DiscoveryImportPayload.model_validate(discovery["payload"])
    result = import_discovery_payload(import_payload, db)
    record_control_plane_audit(
        db,
        actor=current.user,
        action="MCP_DISCOVERY_IMPORTED",
        target_type="mcp_server",
        target_id=str(result["server_id"]),
        reason="Admin requested governed MCP discovery.",
        after_json={
            "endpoint": payload.endpoint,
            "tool_count": result["total_tools_imported"],
            "tools_quarantined": result["tools_quarantined"],
            "tools_approved_current": result["tools_approved_current"],
        },
    )
    db.commit()
    return result


def import_discovery_payload(
    payload: DiscoveryImportPayload,
    db: Session,
) -> dict:
    now = datetime.utcnow()
    server = upsert_server(payload, db, now)
    db.flush()
    try:
        config_snapshot = PublishedConfigurationProvider(db).load_active_snapshot()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="published_configuration_unavailable",
        ) from exc

    tools_created = 0
    tools_updated = 0
    tools_quarantined = 0
    tools_approved_current = 0
    analysis_service = ToolAnalysisService()

    for tool_payload in payload.tools:
        existing_tool = db.scalar(
            select(MCPTool).where(
                MCPTool.server_id == server.id,
                MCPTool.name == tool_payload.name,
            )
        )
        if existing_tool is None:
            existing_tool = MCPTool(server_id=server.id, name=tool_payload.name)
            db.add(existing_tool)
            tools_created += 1
        else:
            tools_updated += 1

        apply_tool_metadata(existing_tool, tool_payload.model_dump(), now)
        db.flush()
        server_ref = _server_ref(server)
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
            upstream_protocol_profile_id=(
                tool_payload.upstream_protocol_profile_id
                or server.preferred_upstream_profile
                or LEGACY_PROFILE_ID
            ),
        )
        if analysis.analysis_status == "APPROVED":
            tools_approved_current += 1
        else:
            tools_quarantined += 1

    db.refresh(server)

    return {
        "server_id": server.id,
        "server_status": "created" if getattr(server, "_was_created", False) else "updated",
        "tools_created": tools_created,
        "tools_updated": tools_updated,
        "total_tools_imported": len(payload.tools),
        "tools_quarantined": tools_quarantined,
        "tools_approved_current": tools_approved_current,
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
    else:
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
    tool.last_analyzed_at = now

    enrichment = security_enrichment_for_tool(tool.name)
    tool.sensitivity = enrichment["sensitivity"]
    tool.risk_score = enrichment["risk_score"]
    tool.policy_status = enrichment["policy_status"]
    tool.is_sensitive = enrichment["is_sensitive"]


def _server_ref(server: MCPServer) -> str:
    payload = {
        "transport": server.transport,
        "endpoint": server.endpoint,
    }
    if server_ref_for_server is not None:
        return server_ref_for_server(payload)
    return f"{server.transport or 'streamable_http'}:{server.endpoint}"


def _tool_profile_snapshot(config_snapshot, server_ref: str, tool_name: str) -> dict | None:
    if getattr(config_snapshot, "schema_version", 1) == 2:
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
    try:
        profile = config_snapshot.get_tool_security_profile(
            server_ref=server_ref,
            tool_name=tool_name,
        )
    except Exception:
        return None
    return {
        "revision": profile.revision,
        "server_ref": profile.server_ref,
        "tool_name": profile.tool_name,
        "operation": profile.operation,
        "required_capability": profile.required_capability,
        "resource": profile.resource.model_dump(mode="json"),
    }


def is_local_lab_endpoint(endpoint: str) -> bool:
    return is_exact_local_lab_endpoint(endpoint)


def security_enrichment_for_tool(tool_name: str) -> dict:
    return {
        "sensitivity": "unknown",
        "risk_score": 50,
        "policy_status": "pending_review",
        "is_sensitive": True,
    }
