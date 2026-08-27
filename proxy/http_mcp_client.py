from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from common.mcp_endpoint import MCPEndpointValidationError, validate_mcp_endpoint
from proxy.mcp_transport import (
    LegacyHTTPSSETransport,
    StreamableHTTPResponseDecoder,
    TransportHTTPError,
    TransportProtocolError,
)
from proxy.protocol_profiles import (
    LEGACY_PROFILE_ID,
    LEGACY_PROTOCOL_VERSION,
    LEGACY_PROTOCOL_VERSIONS,
    ProtocolProfileError,
    ProtocolProfileRegistry,
)
from proxy.protocol_negotiation import MCP_CLIENT_USER_AGENT
from proxy.protocol_revisions import ProtocolEra, TransportKind
from common.canonical_json import canonical_json_bytes

SUPPORTED_PROTOCOL_VERSION = LEGACY_PROTOCOL_VERSION
MCP_ACCEPT_HEADER = "application/json, text/event-stream"
MAX_ERROR_BODY_BYTES = 16_384


class MCPClientError(Exception):
    """Base exception for MCP HTTP client failures."""


class MCPHttpError(MCPClientError):
    """Raised when the MCP endpoint returns an HTTP error."""


class MCPProtocolError(MCPClientError):
    """Raised when JSON-RPC protocol handling fails."""


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: N802
        return None


class MCPHttpClient:
    def __init__(
        self,
        endpoint: str,
        protocol_version: str = SUPPORTED_PROTOCOL_VERSION,
        timeout_seconds: float = 10.0,
        protocol_profile_id: str | None = None,
        allow_legacy_counter_offer: bool = False,
        bearer_token: str | None = None,
    ) -> None:
        try:
            validate_mcp_endpoint(endpoint)
        except MCPEndpointValidationError as exc:
            raise MCPHttpError(str(exc)) from exc
        self.endpoint = endpoint
        self._registry = ProtocolProfileRegistry()
        self.protocol_profile = self._registry.get(
            protocol_profile_id or protocol_version or LEGACY_PROFILE_ID
        )
        if protocol_profile_id is not None and protocol_version not in {
            SUPPORTED_PROTOCOL_VERSION,
            self.protocol_profile.protocol_version,
        }:
            raise MCPProtocolError("protocol profile and version mismatch.")
        self.requested_protocol_version = self.protocol_profile.protocol_version
        self.negotiated_protocol_version: str | None = None
        self.session_id: str | None = None
        self.initialized = False
        self.timeout_seconds = timeout_seconds
        self.allow_legacy_counter_offer = allow_legacy_counter_offer
        self._request_id = 0
        self._legacy_http_sse_transport: LegacyHTTPSSETransport | None = None
        self._upstream_headers = {"User-Agent": MCP_CLIENT_USER_AGENT}
        if bearer_token:
            self._upstream_headers["Authorization"] = f"Bearer {bearer_token}"
        self._opener = build_opener(_NoRedirectHandler)

    def initialize(self) -> dict[str, Any]:
        if self.protocol_profile.protocol_era != ProtocolEra.LEGACY:
            raise MCPProtocolError("Only Legacy profiles use initialize.")
        if self.protocol_profile.transport_kind == TransportKind.LEGACY_HTTP_SSE:
            self._open_legacy_http_sse_post_endpoint()
        request_id = self._next_request_id()
        response = self._post_json(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": "initialize",
                "params": {
                    "protocolVersion": self.requested_protocol_version,
                    "capabilities": {},
                    "clientInfo": {
                        "name": "mcp-security-framework-proxy",
                        "version": "0.1.0",
                    },
                },
            },
            include_protocol_header=False,
        )

        result = response.get("result")
        if not isinstance(result, dict):
            raise MCPProtocolError("initialize response is missing a result object.")

        negotiated = result.get("protocolVersion") or self.requested_protocol_version
        if negotiated not in LEGACY_PROTOCOL_VERSIONS:
            raise MCPProtocolError("unsupported negotiated Legacy protocol version.")
        if negotiated != self.requested_protocol_version:
            if not self.allow_legacy_counter_offer:
                raise MCPProtocolError("Legacy server counter-offered a different protocol revision.")
            self.protocol_profile = self._registry.get_by_version(str(negotiated))
        try:
            self.protocol_profile.validate_initialize_result(result)
        except ProtocolProfileError as exc:
            raise MCPProtocolError(str(exc)) from exc
        self.negotiated_protocol_version = str(negotiated)
        return result

    def send_initialized_notification(self) -> None:
        self._post_json(
            {
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
            },
            include_protocol_header=True,
            notification=True,
        )
        self.initialized = True

    def ensure_initialized(self) -> None:
        if self.initialized:
            return

        if self.protocol_profile.protocol_era == ProtocolEra.MODERN:
            self.negotiated_protocol_version = self.protocol_profile.protocol_version
            self.initialized = True
            return

        self.initialize()
        self.send_initialized_notification()

    def close(self) -> None:
        if self._legacy_http_sse_transport is not None:
            self._legacy_http_sse_transport.close()

    def list_tools(self) -> dict[str, Any]:
        self.ensure_initialized()
        payload, profile_headers = self.protocol_profile.serialize_request(
            request_id=self._next_request_id(),
            method="tools/list",
            params={},
        )
        response = self._post_json(
            payload,
            include_protocol_header=True,
            extra_headers=profile_headers,
        )
        result = response.get("result")
        if not isinstance(result, dict):
            raise MCPProtocolError("tools/list response is missing a result object.")
        try:
            self.protocol_profile.validate_list_tools_result(result)
        except ProtocolProfileError as exc:
            raise MCPProtocolError(str(exc)) from exc
        return result

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        self.ensure_initialized()
        payload, profile_headers = self.protocol_profile.serialize_tool_call(
            request_id=self._next_request_id(),
            name=name,
            arguments=arguments,
        )
        response = self._post_json(
            payload,
            include_protocol_header=True,
            extra_headers=profile_headers,
        )
        result = response.get("result")
        if not isinstance(result, dict):
            raise MCPProtocolError("tools/call response is missing a result object.")
        try:
            self.protocol_profile.validate_tool_response(result)
        except ProtocolProfileError as exc:
            raise MCPProtocolError(str(exc)) from exc
        return result

    def _post_json(
        self,
        payload: dict[str, Any],
        *,
        include_protocol_header: bool,
        notification: bool = False,
        extra_headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        body = canonical_json_bytes(payload)
        headers = self._headers(include_protocol_header=include_protocol_header)
        if extra_headers:
            headers.update(extra_headers)
        if self.protocol_profile.transport_kind == TransportKind.LEGACY_HTTP_SSE:
            if self._legacy_http_sse_transport is None:
                self._open_legacy_http_sse_post_endpoint()
            assert self._legacy_http_sse_transport is not None
            try:
                message = self._legacy_http_sse_transport.post_json(
                    payload,
                    headers=headers,
                    notification=notification,
                )
            except TransportHTTPError as exc:
                raise MCPHttpError(str(exc)) from exc
            except TransportProtocolError as exc:
                raise MCPProtocolError(str(exc)) from exc
            error = message.get("error")
            if error:
                raise MCPProtocolError(f"MCP JSON-RPC error: {error}")
            return message

        request = Request(
            self.endpoint,
            data=body,
            headers=headers,
            method="POST",
        )

        try:
            with self._opener.open(request, timeout=self.timeout_seconds) as response:
                status_code = response.getcode()
                session_id = response.headers.get("MCP-Session-Id")
                if session_id:
                    self.session_id = session_id
                if notification:
                    if status_code != 202:
                        raise MCPProtocolError(
                            f"Expected 202 Accepted for notification, got {status_code}."
                        )
                    return {}
                decoder = StreamableHTTPResponseDecoder(expected_request_id=payload.get("id"))
                message = decoder.decode(response)
        except HTTPError as exc:
            exc.read(MAX_ERROR_BODY_BYTES + 1)
            raise MCPHttpError(f"MCP HTTP error {exc.code}") from exc
        except URLError as exc:
            raise MCPHttpError(f"MCP HTTP request failed: {exc.reason}") from exc
        except TimeoutError as exc:
            raise MCPHttpError("MCP HTTP request timed out.") from exc
        except TransportProtocolError as exc:
            raise MCPProtocolError(str(exc)) from exc

        error = message.get("error")
        if error:
            raise MCPProtocolError(f"MCP JSON-RPC error: {error}")

        return message

    def _headers(self, *, include_protocol_header: bool) -> dict[str, str]:
        headers = {
            "Accept": MCP_ACCEPT_HEADER,
            "Content-Type": "application/json",
            **self._upstream_headers,
        }

        if (
            include_protocol_header
            and self.protocol_profile.transport_kind != TransportKind.LEGACY_HTTP_SSE
        ):
            protocol_version = (
                self.negotiated_protocol_version or self.requested_protocol_version
            )
            headers["MCP-Protocol-Version"] = protocol_version

        if (
            self.session_id
            and self.protocol_profile.transport_kind != TransportKind.LEGACY_HTTP_SSE
        ):
            headers["MCP-Session-Id"] = self.session_id

        return headers

    def _open_legacy_http_sse_post_endpoint(self) -> None:
        if self._legacy_http_sse_transport is None:
            self._legacy_http_sse_transport = LegacyHTTPSSETransport(
                sse_endpoint=self.endpoint,
                timeout_seconds=self.timeout_seconds,
                opener=self._opener,
                connection_headers=self._upstream_headers,
            )
        try:
            self._legacy_http_sse_transport.open()
        except TransportHTTPError as exc:
            raise MCPHttpError(str(exc)) from exc
        except TransportProtocolError as exc:
            raise MCPProtocolError(str(exc)) from exc
        self.endpoint = str(self._legacy_http_sse_transport.post_endpoint)

    def _next_request_id(self) -> int:
        self._request_id += 1
        return self._request_id
