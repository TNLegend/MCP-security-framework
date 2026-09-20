from __future__ import annotations

import urllib.error
import urllib.request
import uuid
from datetime import datetime
from typing import Any

from common.canonical_json import canonical_json_bytes
from common.mcp_endpoint import MCPEndpointValidationError, validate_mcp_endpoint
from common.upstream_auth import (
    AUTH_MODE_NONE,
    UpstreamAuthError,
    resolve_upstream_bearer_token,
)
from proxy.http_mcp_client import MCPHttpClient
from proxy.mcp_transport import StreamableHTTPResponseDecoder, TransportProtocolError
from proxy.protocol_negotiation import MCP_CLIENT_USER_AGENT, ProtocolNegotiator
from proxy.protocol_profiles import (
    LEGACY_PROFILE_ID,
    MODERN_PROFILE_ID,
    ProtocolProfileRegistry,
    modern_result_server_info,
)
from proxy.protocol_revisions import ProtocolEra
from proxy.strict_json import parse_strict_json


DEFAULT_PROTOCOL_VERSION = "2025-11-25"
DISCOVERY_CLIENT_NAME = "mcp-security-framework-discovery"
DISCOVERY_CLIENT_VERSION = "0.1.0"
MCP_ACCEPT_HEADER = "application/json, text/event-stream"
MAX_DISCOVERY_RESPONSE_BYTES = 262_144


class MCPDiscoveryError(RuntimeError):
    """Raised when governed MCP discovery cannot complete safely."""


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: N802
        return None


DISCOVERY_OPENER = urllib.request.build_opener(_NoRedirectHandler)


def discover_http_mcp_server(
    *,
    mcp_endpoint: str,
    protocol_version: str = DEFAULT_PROTOCOL_VERSION,
    auth_mode: str = AUTH_MODE_NONE,
    credential_ref: str | None = None,
    oauth_config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    del protocol_version
    try:
        validate_mcp_endpoint(mcp_endpoint)
        bearer_token = resolve_upstream_bearer_token(
            auth_mode,
            credential_ref,
            oauth_config=oauth_config,
        )
        negotiation = ProtocolNegotiator(bearer_token=bearer_token).negotiate(
            endpoint=mcp_endpoint,
            registered_endpoint=mcp_endpoint,
        )
        observations: list[dict[str, Any]] = []
        profile_metadata: dict[str, dict[str, Any]] = {}
        ordered_profiles = sorted(
            negotiation.supported_protocol_profiles,
            key=lambda value: value != negotiation.preferred_upstream_profile,
        )
        for profile_id in ordered_profiles:
            profile = ProtocolProfileRegistry().get(profile_id)
            if profile.protocol_era == ProtocolEra.MODERN:
                metadata, tools = discover_modern_server(
                    mcp_endpoint,
                    profile_id,
                    bearer_token=bearer_token,
                )
            else:
                metadata, tools = discover_legacy_server(
                    mcp_endpoint,
                    profile_id,
                    bearer_token=bearer_token,
                )
            profile_metadata[profile_id] = metadata
            observations.extend({**tool, "upstream_protocol_profile_id": profile_id} for tool in tools)

        preferred_metadata = profile_metadata[negotiation.preferred_upstream_profile]
        payload = build_import_payload(
            mcp_endpoint=mcp_endpoint,
            initialize_result=preferred_metadata,
            tools=observations,
            supported_protocol_profiles=list(negotiation.supported_protocol_profiles),
            preferred_upstream_profile=negotiation.preferred_upstream_profile,
            protocol_version=negotiation.protocol_version,
            protocol_probe_status=negotiation.probe_status,
            detected_protocol_era=negotiation.detected_era,
            supported_protocol_versions=list(negotiation.supported_protocol_versions),
            preferred_protocol_version=negotiation.preferred_protocol_version,
            negotiated_protocol_version=negotiation.negotiated_protocol_version,
            protocol_transport_kind=negotiation.transport_kind,
            protocol_verdict_expires_at=negotiation.protocol_verdict_expires_at,
            auth_mode=auth_mode,
            credential_ref=credential_ref,
        )
    except (MCPEndpointValidationError, UpstreamAuthError) as exc:
        raise MCPDiscoveryError(str(exc)) from exc
    except Exception as exc:
        raise MCPDiscoveryError("mcp_discovery_failed") from exc
    return {
        "tool_names": [tool.get("name", "unknown") for tool in observations],
        "payload": payload,
    }


def discover_legacy_server(
    mcp_endpoint: str,
    profile_id: str,
    *,
    bearer_token: str | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    client = MCPHttpClient(
        mcp_endpoint,
        protocol_profile_id=profile_id,
        timeout_seconds=10,
        bearer_token=bearer_token,
    )
    try:
        initialize_result = client.initialize()
        client.send_initialized_notification()
        tools_result = client.list_tools()
    finally:
        client.close()
    return initialize_result, tools_result.get("tools", [])


def discover_modern_server(
    mcp_endpoint: str,
    profile_id: str = MODERN_PROFILE_ID,
    *,
    bearer_token: str | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    profile = ProtocolProfileRegistry().get(profile_id)
    discover_payload, discover_headers = profile.serialize_request(
        request_id=new_request_id(),
        method="server/discover",
        params={},
    )
    discover_result = parse_json_rpc_result(
        send_json_rpc(
            url=mcp_endpoint,
            payload=discover_payload,
            extra_headers=discover_headers,
            bearer_token=bearer_token,
        )["body"]
    )
    try:
        profile.validate_discover_result(discover_result)
    except Exception as exc:
        raise MCPDiscoveryError("modern_discover_response_unsupported") from exc

    tools: list[dict[str, Any]] = []
    cursor = None
    while True:
        params = {"cursor": cursor} if cursor else {}
        list_payload, list_headers = profile.serialize_request(
            request_id=new_request_id(),
            method="tools/list",
            params=params,
        )
        result = parse_json_rpc_result(
            send_json_rpc(
                url=mcp_endpoint,
                payload=list_payload,
                extra_headers=list_headers,
                bearer_token=bearer_token,
            )["body"]
        )
        try:
            profile.validate_list_tools_result(result)
        except Exception as exc:
            raise MCPDiscoveryError("modern_tools_list_response_unsupported") from exc
        tools.extend(result["tools"])
        cursor = result.get("nextCursor")
        if not cursor:
            return discover_result, tools


def build_import_payload(
    *,
    mcp_endpoint: str,
    initialize_result: dict[str, Any],
    tools: list[dict[str, Any]],
    supported_protocol_profiles: list[str] | None = None,
    preferred_upstream_profile: str = LEGACY_PROFILE_ID,
    protocol_version: str | None = None,
    protocol_probe_status: str | None = None,
    detected_protocol_era: str | None = None,
    supported_protocol_versions: list[str] | None = None,
    preferred_protocol_version: str | None = None,
    negotiated_protocol_version: str | None = None,
    protocol_transport_kind: str | None = None,
    protocol_verdict_expires_at: datetime | str | None = None,
    auth_mode: str = AUTH_MODE_NONE,
    credential_ref: str | None = None,
) -> dict[str, Any]:
    server_info = modern_result_server_info(initialize_result) or initialize_result.get("serverInfo") or {}
    return {
        "server": {
            "endpoint": mcp_endpoint,
            "transport": "streamable_http",
            "protocol_version": protocol_version or initialize_result.get("protocolVersion"),
            "detected_protocol_era": detected_protocol_era,
            "supported_protocol_versions": supported_protocol_versions,
            "preferred_protocol_version": preferred_protocol_version,
            "negotiated_protocol_version": negotiated_protocol_version,
            "protocol_transport_kind": protocol_transport_kind,
            "protocol_verdict_expires_at": (
                protocol_verdict_expires_at.isoformat()
                if hasattr(protocol_verdict_expires_at, "isoformat")
                else protocol_verdict_expires_at
            ),
            "server_info_name": server_info.get("name"),
            "server_info_title": server_info.get("title"),
            "server_info_version": server_info.get("version"),
            "server_info_description": server_info.get("description"),
            "server_info_icons": server_info.get("icons"),
            "server_info_website_url": server_info.get("websiteUrl"),
            "capabilities": initialize_result.get("capabilities"),
            "instructions": initialize_result.get("instructions"),
            "raw_initialize_result": initialize_result,
            "supported_protocol_profiles": supported_protocol_profiles or [LEGACY_PROFILE_ID],
            "preferred_upstream_profile": preferred_upstream_profile,
            "protocol_probe_status": protocol_probe_status or "legacy_supported",
            "protocol_probe_error": None,
            "auth_mode": auth_mode,
            "credential_ref": credential_ref,
        },
        "tools": [map_tool(tool) for tool in tools],
    }


def map_tool(tool: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": tool.get("name"),
        "title": tool.get("title"),
        "description": tool.get("description"),
        "icons": tool.get("icons"),
        "input_schema": tool.get("inputSchema"),
        "output_schema": tool.get("outputSchema"),
        "annotations": tool.get("annotations"),
        "execution": tool.get("execution"),
        "raw_tool_definition": tool,
        "upstream_protocol_profile_id": tool.get("upstream_protocol_profile_id"),
    }


def send_json_rpc(
    *,
    url: str,
    payload: dict[str, Any],
    protocol_version: str | None = None,
    session_id: str | None = None,
    expected_statuses: set[int] | None = None,
    routing_method: str | None = None,
    extra_headers: dict[str, str] | None = None,
    bearer_token: str | None = None,
) -> dict[str, Any]:
    expected_statuses = expected_statuses or {200}
    headers = {
        "Accept": MCP_ACCEPT_HEADER,
        "Content-Type": "application/json",
        "User-Agent": MCP_CLIENT_USER_AGENT,
    }
    if protocol_version:
        headers["MCP-Protocol-Version"] = protocol_version
    if session_id:
        headers["MCP-Session-Id"] = session_id
    if routing_method:
        headers["Mcp-Method"] = routing_method
    if extra_headers:
        headers.update(extra_headers)
    if bearer_token:
        headers["Authorization"] = f"Bearer {bearer_token}"

    try:
        validate_mcp_endpoint(url)
    except MCPEndpointValidationError as exc:
        raise MCPDiscoveryError(str(exc)) from exc

    request = urllib.request.Request(
        url,
        data=canonical_json_bytes(payload),
        headers=headers,
        method="POST",
    )
    try:
        with DISCOVERY_OPENER.open(request, timeout=10) as response:
            if response.status not in expected_statuses:
                raise MCPDiscoveryError("unexpected_discovery_http_status")
            if response.status != 200:
                raw_body = response.read(MAX_DISCOVERY_RESPONSE_BYTES + 1)
                if len(raw_body) > MAX_DISCOVERY_RESPONSE_BYTES:
                    raise MCPDiscoveryError("discovery_response_too_large")
                return {
                    "status": response.status,
                    "headers": response.headers,
                    "body": parse_strict_json(raw_body) if raw_body else None,
                }
            decoder = StreamableHTTPResponseDecoder(
                expected_request_id=payload.get("id"),
                max_response_bytes=MAX_DISCOVERY_RESPONSE_BYTES,
                max_sse_event_bytes=MAX_DISCOVERY_RESPONSE_BYTES,
            )
            try:
                message = decoder.decode(response)
            except TransportProtocolError as exc:
                raise MCPDiscoveryError(str(exc)) from exc
            return {
                "status": response.status,
                "headers": response.headers,
                "body": message,
            }
    except urllib.error.HTTPError as exc:
        raise MCPDiscoveryError("discovery_http_error") from exc


def parse_json_rpc_result(message: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(message, dict):
        raise MCPDiscoveryError("json_rpc_response_missing")
    if message.get("jsonrpc") != "2.0":
        raise MCPDiscoveryError("json_rpc_version_invalid")
    if "error" in message:
        raise MCPDiscoveryError("json_rpc_error")
    result = message.get("result")
    if not isinstance(result, dict):
        raise MCPDiscoveryError("json_rpc_result_missing")
    return result


def new_request_id() -> str:
    return str(uuid.uuid4())
