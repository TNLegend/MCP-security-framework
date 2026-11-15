from __future__ import annotations

import os
import urllib.error
import urllib.request
import unicodedata
import uuid
from datetime import datetime
from time import monotonic
from typing import Any

from common.canonical_json import canonical_json_bytes
from common.mcp_endpoint import MCPEndpointValidationError, validate_mcp_endpoint
from common.pinned_http import build_pinned_opener
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
# Remote Streamable HTTP/SSE servers may need longer to complete initialize.
# Bound each negotiation probe; keep fail-closed response and profile validation.
DISCOVERY_PROBE_TIMEOUT_SECONDS = 10.0
MAX_DISCOVERY_PAGES = 32
MAX_DISCOVERY_TOOLS = 2_000
MAX_DISCOVERY_DURATION_SECONDS = 60.0
MAX_DISCOVERY_CURSOR_LENGTH = 2_048


def is_valid_discovery_tool_name(value: Any) -> bool:
    """One definition for both remote pagination and signed import preflight.

    Match the 255-character persisted inventory field and reject invisible,
    non-NFC and padded tool identifiers without rewriting signed evidence.
    """
    return (
        isinstance(value, str)
        and 0 < len(value) <= 255
        and value == value.strip()
        and value.isprintable()
        and unicodedata.normalize("NFC", value) == value
    )


def _validate_discovery_page(
    result: dict[str, Any], *,
    seen_cursors: set[str], page_count: int, previous_count: int,
    deadline: float,
    seen_tool_names: set[str] | None = None,
    catalog_revision_state: list[str | None] | None = None,
    require_catalog_revision: bool = False,
) -> tuple[list[dict[str, Any]], str | None]:
    if monotonic() >= deadline:
        raise MCPDiscoveryError("mcp_discovery_deadline_exceeded")
    if page_count >= MAX_DISCOVERY_PAGES:
        raise MCPDiscoveryError("mcp_discovery_page_limit_exceeded")
    if not isinstance(result, dict):
        raise MCPDiscoveryError("mcp_discovery_page_invalid")
    page_tools = result.get("tools")
    if not isinstance(page_tools, list) or not all(isinstance(t, dict) for t in page_tools):
        raise MCPDiscoveryError("mcp_discovery_tools_invalid")
    if previous_count + len(page_tools) > MAX_DISCOVERY_TOOLS:
        raise MCPDiscoveryError("mcp_discovery_tool_limit_exceeded")
    # Name identity is scoped to one upstream protocol profile and one
    # COMPLETE generation. Duplicate names would overwrite observations or
    # analyses depending on page order. Validate the entire page before
    # mutating the remembered identities / next-cursor state.
    page_names = [item.get("name") for item in page_tools]
    if any(not is_valid_discovery_tool_name(name) for name in page_names):
        raise MCPDiscoveryError("mcp_discovery_tool_name_invalid")
    if (
        len(set(page_names)) != len(page_names)
        or (seen_tool_names is not None and
            bool(set(page_names).intersection(seen_tool_names)))
    ):
        raise MCPDiscoveryError("mcp_discovery_duplicate_tool_name")
    # Optional provider extension (NOT standard MCP snapshot semantics).
    # When advertised it must remain identical on every page. Its absence
    # conveys no guarantee of an immutable remote catalog.
    revision = result.get("catalogRevision")
    if require_catalog_revision and "catalogRevision" not in result:
        raise MCPDiscoveryError("mcp_discovery_catalog_revision_required")
    if "catalogRevision" in result and (
        not isinstance(revision, str)
        or not 0 < len(revision) <= 128
        or revision != revision.strip()
        or not revision.isprintable()
        or unicodedata.normalize("NFC", revision) != revision
    ):
        raise MCPDiscoveryError("mcp_discovery_catalog_revision_invalid")
    if catalog_revision_state and catalog_revision_state[0] != revision:
        raise MCPDiscoveryError("mcp_discovery_catalog_revision_changed")
    next_cursor = result.get("nextCursor")
    if next_cursor is not None and next_cursor != "":
        if not isinstance(next_cursor, str) or len(next_cursor) > MAX_DISCOVERY_CURSOR_LENGTH:
            raise MCPDiscoveryError("mcp_discovery_cursor_invalid")
        if next_cursor in seen_cursors:
            raise MCPDiscoveryError("mcp_discovery_cursor_cycle")
        seen_cursors.add(next_cursor)
    if catalog_revision_state is not None and not catalog_revision_state:
        catalog_revision_state.append(revision)
    if seen_tool_names is not None:
        seen_tool_names.update(page_names)
    return page_tools, (next_cursor or None)





class MCPDiscoveryError(RuntimeError):
    """Raised when governed MCP discovery cannot complete safely."""


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: N802
        return None


DISCOVERY_OPENER = build_pinned_opener()


def discover_http_mcp_server(
    *,
    mcp_endpoint: str,
    protocol_version: str = DEFAULT_PROTOCOL_VERSION,
    auth_mode: str = AUTH_MODE_NONE,
    credential_ref: str | None = None,
    oauth_config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    del protocol_version
    strict_catalog_policy = os.environ.get(
        "MCP_DISCOVERY_REQUIRE_CATALOG_REVISION", "0"
    ).strip()
    if strict_catalog_policy not in ("0", "1"):
        raise MCPDiscoveryError("mcp_discovery_catalog_policy_invalid")
    require_catalog_revision = strict_catalog_policy == "1"
    # One bounded budget for the entire discovery transaction (negotiation
    # and all advertised profiles), not 60 seconds reset per profile.
    discovery_deadline = monotonic() + MAX_DISCOVERY_DURATION_SECONDS
    try:
        validate_mcp_endpoint(mcp_endpoint)
        bearer_token = resolve_upstream_bearer_token(
            auth_mode,
            credential_ref,
            oauth_config=oauth_config,
        )
        negotiation = ProtocolNegotiator(
            timeout_seconds=DISCOVERY_PROBE_TIMEOUT_SECONDS,
            bearer_token=bearer_token,
        ).negotiate(
            endpoint=mcp_endpoint,
            registered_endpoint=mcp_endpoint,
        )
        observations: list[dict[str, Any]] = []
        profile_metadata: dict[str, dict[str, Any]] = {}
        # Catalog revisions, when advertised, must describe the same
        # generation across every protocol profile of this discovery.
        cross_profile_catalog_revision: list[str | None] = []
        ordered_profiles = sorted(
            negotiation.supported_protocol_profiles,
            key=lambda value: value != negotiation.preferred_upstream_profile,
        )
        if monotonic() >= discovery_deadline:
            raise MCPDiscoveryError("mcp_discovery_deadline_exceeded")
        for profile_id in ordered_profiles:
            if monotonic() >= discovery_deadline:
                raise MCPDiscoveryError("mcp_discovery_deadline_exceeded")
            profile = ProtocolProfileRegistry().get(profile_id)
            if profile.protocol_era == ProtocolEra.MODERN:
                metadata, tools = discover_modern_server(
                    mcp_endpoint,
                    profile_id,
                    bearer_token=bearer_token,
                    deadline_monotonic=discovery_deadline,
                    require_catalog_revision=require_catalog_revision,
                    catalog_revision_state=cross_profile_catalog_revision,
                )
            else:
                metadata, tools = discover_legacy_server(
                    mcp_endpoint,
                    profile_id,
                    bearer_token=bearer_token,
                    deadline_monotonic=discovery_deadline,
                    require_catalog_revision=require_catalog_revision,
                    catalog_revision_state=cross_profile_catalog_revision,
                )
            # Multi-profile enumeration cannot reset the total tool budget.
            # Reject before adding observations, building signed payload or
            # touching inventory. The per-profile page guards remain in place.
            if len(observations) + len(tools) > MAX_DISCOVERY_TOOLS:
                raise MCPDiscoveryError("mcp_discovery_tool_limit_exceeded")
            if monotonic() >= discovery_deadline:
                raise MCPDiscoveryError("mcp_discovery_deadline_exceeded")
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
    except MCPDiscoveryError:
        raise  # Preserve bounded/discovery diagnostic; no partial payload.
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
    deadline_monotonic: float | None = None,
    require_catalog_revision: bool = False,
    catalog_revision_state: list[str | None] | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    deadline = (deadline_monotonic if deadline_monotonic is not None
                else monotonic() + MAX_DISCOVERY_DURATION_SECONDS)
    if monotonic() >= deadline:
        raise MCPDiscoveryError("mcp_discovery_deadline_exceeded")
    client = MCPHttpClient(
        mcp_endpoint,
        protocol_profile_id=profile_id,
        timeout_seconds=10,
        bearer_token=bearer_token,
    )
    try:
        initialize_result = client.initialize()
        client.send_initialized_notification()
        if monotonic() >= deadline:
            raise MCPDiscoveryError("mcp_discovery_deadline_exceeded")
        cursor = None
        seen_cursors: set[str] = set()
        seen_tool_names: set[str] = set()
        if catalog_revision_state is None:
            catalog_revision_state = []
        tools: list[dict[str, Any]] = []
        for page_count in range(MAX_DISCOVERY_PAGES + 1):
            if monotonic() >= deadline:
                raise MCPDiscoveryError("mcp_discovery_deadline_exceeded")
            tools_result = client.list_tools(cursor=cursor)
            page, cursor = _validate_discovery_page(
                tools_result, seen_cursors=seen_cursors, page_count=page_count,
                previous_count=len(tools), deadline=deadline,
                seen_tool_names=seen_tool_names,
                catalog_revision_state=catalog_revision_state,
                require_catalog_revision=require_catalog_revision,
            )
            tools.extend(page)
            if cursor is None:
                break
    finally:
        client.close()
    return initialize_result, tools


def discover_modern_server(
    mcp_endpoint: str,
    profile_id: str = MODERN_PROFILE_ID,
    *,
    bearer_token: str | None = None,
    deadline_monotonic: float | None = None,
    require_catalog_revision: bool = False,
    catalog_revision_state: list[str | None] | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    deadline = (deadline_monotonic if deadline_monotonic is not None
                else monotonic() + MAX_DISCOVERY_DURATION_SECONDS)
    if monotonic() >= deadline:
        raise MCPDiscoveryError("mcp_discovery_deadline_exceeded")
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
    seen_cursors: set[str] = set()
    seen_tool_names: set[str] = set()
    if catalog_revision_state is None:
        catalog_revision_state = []
    for page_count in range(MAX_DISCOVERY_PAGES + 1):
        if monotonic() >= deadline:
            raise MCPDiscoveryError("mcp_discovery_deadline_exceeded")
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
        page, cursor = _validate_discovery_page(
            result, seen_cursors=seen_cursors,
            page_count=page_count, previous_count=len(tools), deadline=deadline,
            seen_tool_names=seen_tool_names,
            catalog_revision_state=catalog_revision_state,
            require_catalog_revision=require_catalog_revision,
        )
        tools.extend(page)
        if cursor is None:
            return discover_result, tools
    raise MCPDiscoveryError("mcp_discovery_page_limit_exceeded")


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
