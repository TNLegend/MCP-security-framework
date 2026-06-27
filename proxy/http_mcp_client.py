import json
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


SUPPORTED_PROTOCOL_VERSION = "2025-11-25"
MCP_ACCEPT_HEADER = "application/json, text/event-stream"


class MCPClientError(Exception):
    """Base exception for MCP HTTP client failures."""


class MCPHttpError(MCPClientError):
    """Raised when the MCP endpoint returns an HTTP error."""


class MCPProtocolError(MCPClientError):
    """Raised when JSON-RPC protocol handling fails."""


class MCPHttpClient:
    def __init__(
        self,
        endpoint: str,
        protocol_version: str = SUPPORTED_PROTOCOL_VERSION,
        timeout_seconds: float = 10.0,
    ) -> None:
        self.endpoint = endpoint
        self.requested_protocol_version = protocol_version
        self.negotiated_protocol_version: str | None = None
        self.session_id: str | None = None
        self.initialized = False
        self.timeout_seconds = timeout_seconds
        self._request_id = 0

    def initialize(self) -> dict[str, Any]:
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

        self.negotiated_protocol_version = (
            result.get("protocolVersion") or self.requested_protocol_version
        )
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

        self.initialize()
        self.send_initialized_notification()

    def list_tools(self) -> dict[str, Any]:
        self.ensure_initialized()
        response = self._post_json(
            {
                "jsonrpc": "2.0",
                "id": self._next_request_id(),
                "method": "tools/list",
            },
            include_protocol_header=True,
        )
        result = response.get("result")
        if not isinstance(result, dict):
            raise MCPProtocolError("tools/list response is missing a result object.")
        return result

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        self.ensure_initialized()
        response = self._post_json(
            {
                "jsonrpc": "2.0",
                "id": self._next_request_id(),
                "method": "tools/call",
                "params": {
                    "name": name,
                    "arguments": arguments,
                },
            },
            include_protocol_header=True,
        )
        result = response.get("result")
        if not isinstance(result, dict):
            raise MCPProtocolError("tools/call response is missing a result object.")
        return result

    def _post_json(
        self,
        payload: dict[str, Any],
        *,
        include_protocol_header: bool,
        notification: bool = False,
    ) -> dict[str, Any]:
        body = json.dumps(payload).encode("utf-8")
        headers = self._headers(include_protocol_header=include_protocol_header)
        request = Request(
            self.endpoint,
            data=body,
            headers=headers,
            method="POST",
        )

        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:
                status_code = response.getcode()
                response_body = response.read().decode("utf-8")
                session_id = response.headers.get("MCP-Session-Id")
                if session_id:
                    self.session_id = session_id
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise MCPHttpError(
                f"MCP HTTP error {exc.code}: {detail or exc.reason}"
            ) from exc
        except URLError as exc:
            raise MCPHttpError(f"MCP HTTP request failed: {exc.reason}") from exc
        except TimeoutError as exc:
            raise MCPHttpError("MCP HTTP request timed out.") from exc

        if notification:
            if status_code != 202:
                raise MCPProtocolError(
                    f"Expected 202 Accepted for notification, got {status_code}."
                )
            return {}

        if not response_body:
            raise MCPProtocolError("MCP JSON-RPC response body is empty.")

        try:
            message = json.loads(response_body)
        except json.JSONDecodeError as exc:
            raise MCPProtocolError("MCP response is not valid JSON.") from exc

        if not isinstance(message, dict):
            raise MCPProtocolError("MCP response is not a JSON object.")

        error = message.get("error")
        if error:
            raise MCPProtocolError(f"MCP JSON-RPC error: {error}")

        return message

    def _headers(self, *, include_protocol_header: bool) -> dict[str, str]:
        headers = {
            "Accept": MCP_ACCEPT_HEADER,
            "Content-Type": "application/json",
        }

        if include_protocol_header:
            protocol_version = (
                self.negotiated_protocol_version or self.requested_protocol_version
            )
            headers["MCP-Protocol-Version"] = protocol_version

        if self.session_id:
            headers["MCP-Session-Id"] = self.session_id

        return headers

    def _next_request_id(self) -> int:
        self._request_id += 1
        return self._request_id
