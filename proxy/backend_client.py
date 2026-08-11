import json
from pathlib import Path
import sys
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

backend_path = Path(__file__).resolve().parents[1] / "backend"
if str(backend_path) not in sys.path:
    sys.path.insert(0, str(backend_path))

from app.services.signed_service_request import (  # noqa: E402
    SignedServiceRequestSigner,
    canonical_json_body,
)


DEFAULT_BACKEND_BASE_URL = "http://127.0.0.1:8000"


class BackendClientError(Exception):
    """Raised when the backend API cannot complete a proxy request."""


class BackendClient:
    def __init__(
        self,
        backend_base_url: str = DEFAULT_BACKEND_BASE_URL,
        timeout_seconds: float = 10.0,
        service_signer: SignedServiceRequestSigner | None = None,
    ) -> None:
        base_url = backend_base_url.rstrip("/")
        if base_url.endswith("/api/v1"):
            self.api_base_url = base_url
        else:
            self.api_base_url = f"{base_url}/api/v1"
        self.timeout_seconds = timeout_seconds
        self.service_signer = service_signer or SignedServiceRequestSigner.for_proxy()

    def list_servers(self) -> list[dict[str, Any]]:
        data = self._request_json("GET", "/internal/inventory/servers", sign_as_service=True)
        if not isinstance(data, list):
            raise BackendClientError("Backend internal inventory servers response is not a list.")
        return data

    def list_tools(self) -> list[dict[str, Any]]:
        data = self._request_json("GET", "/internal/inventory/tools", sign_as_service=True)
        if not isinstance(data, list):
            raise BackendClientError("Backend internal inventory tools response is not a list.")
        return data

    def find_server(
        self,
        server_id: int | None = None,
        endpoint: str | None = None,
    ) -> dict[str, Any] | None:
        servers = self.list_servers()

        if server_id is not None:
            return next((server for server in servers if server.get("id") == server_id), None)

        if endpoint is not None:
            return next(
                (server for server in servers if server.get("endpoint") == endpoint),
                None,
            )

        return next(
            (
                server
                for server in servers
                if server.get("transport") == "streamable_http"
                and is_local_http_endpoint(str(server.get("endpoint") or ""))
            ),
            None,
        )

    def find_tool(self, server_id: int, tool_name: str) -> dict[str, Any] | None:
        tools = self.list_tools()
        return next(
            (
                tool
                for tool in tools
                if tool.get("server_id") == server_id and tool.get("name") == tool_name
            ),
            None,
        )

    def request_policy_decision(
        self,
        context: dict[str, Any],
        *,
        identity_assertion: str | None = None,
    ) -> dict[str, Any]:
        data = self._request_json(
            "POST",
            "/runtime/decision",
            context,
            identity_assertion=identity_assertion,
        )
        if not isinstance(data, dict):
            raise BackendClientError("Backend policy decision response is not an object.")
        return data

    def create_runtime_log(self, log_payload: dict[str, Any]) -> dict[str, Any]:
        data = self._request_json(
            "POST",
            "/runtime/logs",
            log_payload,
            sign_as_service=True,
        )
        if not isinstance(data, dict):
            raise BackendClientError("Backend runtime log response is not an object.")
        return data

    def _request_json(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        *,
        identity_assertion: str | None = None,
        sign_as_service: bool = False,
    ) -> Any:
        body = canonical_json_body(payload)
        headers = {"Accept": "application/json"}
        if payload is not None:
            headers["Content-Type"] = "application/json"
        if identity_assertion is not None:
            if len(identity_assertion.encode("utf-8")) > 16_384:
                raise BackendClientError("Identity assertion header is too large.")
            headers["X-MCP-Identity-Assertion"] = identity_assertion
        if sign_as_service:
            headers.update(
                self.service_signer.signed_headers(
                    method=method,
                    path=f"/api/v1{path}",
                    body=body,
                )
            )

        request = Request(
            f"{self.api_base_url}{path}",
            data=body,
            headers=headers,
            method=method,
        )

        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:
                response_body = response.read().decode("utf-8")
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise BackendClientError(
                f"Backend HTTP error {exc.code}: {detail or exc.reason}"
            ) from exc
        except URLError as exc:
            raise BackendClientError(f"Backend request failed: {exc.reason}") from exc
        except TimeoutError as exc:
            raise BackendClientError("Backend request timed out.") from exc

        if not response_body:
            return None

        try:
            return json.loads(response_body)
        except json.JSONDecodeError as exc:
            raise BackendClientError("Backend response is not valid JSON.") from exc


def is_local_http_endpoint(endpoint: str) -> bool:
    return endpoint.startswith("http://127.0.0.1") or endpoint.startswith(
        "http://localhost"
    )
