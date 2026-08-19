from __future__ import annotations

import json
from pathlib import Path
import socket
import sys
import threading
import time
from types import SimpleNamespace
import unittest
from urllib.parse import urljoin
from urllib.request import Request, urlopen

import uvicorn

from fastapi.testclient import TestClient


ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend"
for path in (str(ROOT), str(BACKEND)):
    if path not in sys.path:
        sys.path.insert(0, path)

from proxy.gateway import MCPGateway  # noqa: E402
from proxy.mcp_transport import iter_sse_events, read_endpoint_event  # noqa: E402
from proxy.protocol_profiles import (  # noqa: E402
    LEGACY_2024_11_05_PROFILE_ID,
    LEGACY_2025_03_26_PROFILE_ID,
    LEGACY_2025_06_18_PROFILE_ID,
    LEGACY_PROFILE_ID,
    LEGACY_PROTOCOL_VERSION,
    LEGACY_PROTOCOL_VERSIONS,
    MODERN_META_CLIENT_CAPABILITIES,
    MODERN_META_CLIENT_INFO,
    MODERN_META_PROTOCOL_VERSION,
    MODERN_META_SERVER_INFO,
    MODERN_PROFILE_ID,
    MODERN_PROTOCOL_VERSION,
    ProtocolProfileRegistry,
)
from proxy.protocol_revisions import restricted_profile_id, ProtocolEra  # noqa: E402
from proxy.strict_json import StrictJSONError, parse_strict_json  # noqa: E402


class FakeSnapshot:
    schema_version = 1


class FakeSnapshotResolver:
    def load_active_snapshot(self):
        return FakeSnapshot()


class FakeBackend:
    def __init__(self) -> None:
        self.upstream_profile = LEGACY_PROFILE_ID
        self.server = {
            "id": 1,
            "endpoint": "http://127.0.0.1:9000/mcp",
            "transport": "streamable_http",
            "preferred_upstream_profile": self.upstream_profile,
        }
        self.tool = {
            "id": 1,
            "server_id": 1,
            "name": "send_email",
            "description": "Send one email to the declared recipient.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "recipient": {"type": "string"},
                    "subject": {"type": "string"},
                    "body": {"type": "string"},
                },
                "required": ["recipient", "subject", "body"],
                "additionalProperties": False,
            },
            "output_schema": None,
            "annotations": {},
            "analysis_status": "APPROVED",
            "review_status": "APPROVED",
            "approved_fingerprint_match": True,
            "current_fingerprint": "a" * 64,
        }

    def find_server(self, server_id=None, endpoint=None):
        self.server["preferred_upstream_profile"] = self.upstream_profile
        return self.server if server_id in {None, 1} else None

    def list_tools(self):
        return [self.tool]


class FakeSecurityProxy:
    def __init__(self, backend: FakeBackend) -> None:
        self.backend = backend
        self.calls: list[tuple[str, str, str]] = []
        self.upstream_invocations = 0
        self.metadata_authentication_count = 0

    def authenticate_framework_identity(self, identity_request):
        self.metadata_authentication_count += 1
        if identity_request.get("session_token") == "session-token":
            return SimpleNamespace(agent_id="agent-demo")
        if identity_request.get("access_token") == "test-token":
            return SimpleNamespace(agent_id="agent-demo")
        raise ValueError("framework_identity_required")

    def handle_tool_call(self, call):
        recipient = (call.get("arguments") or {}).get("recipient")
        self.calls.append(
            (
                call["client_protocol_profile_id"],
                self.backend.upstream_profile,
                str(recipient),
            )
        )
        if recipient != "alice@example.com":
            return {
                "executed": False,
                "mcp_called": False,
                "rule_id": "deny_generic_security_model_v2",
                "skip_reason": "policy_denied",
            }
        self.upstream_invocations += 1
        return {
            "executed": True,
            "mcp_called": True,
            "tool_result": {"content": [{"type": "text", "text": "sent"}]},
        }


class LiveGatewayServer:
    def __init__(self, app) -> None:
        self.port = _free_port()
        self.server = uvicorn.Server(
            uvicorn.Config(app, host="127.0.0.1", port=self.port, log_level="warning")
        )
        self.thread = threading.Thread(target=self.server.run, daemon=True)
        self.thread.start()
        deadline = time.time() + 10
        while not self.server.started and time.time() < deadline:
            time.sleep(0.05)
        if not self.server.started:
            raise RuntimeError("live_gateway_start_failed")
        self.base_url = f"http://127.0.0.1:{self.port}"

    def close(self) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=5)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class DualEraGatewayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.backend = FakeBackend()
        self.proxy = FakeSecurityProxy(self.backend)
        self.app = MCPGateway(
            proxy=self.proxy,
            backend_client=self.backend,
            snapshot_resolver=FakeSnapshotResolver(),
        ).create_app()
        self.client = TestClient(self.app)
        self.live_gateway: LiveGatewayServer | None = None

    def tearDown(self) -> None:
        if self.live_gateway is not None:
            self.live_gateway.close()

    def gateway_client_with_origins(self, *origins: str) -> TestClient:
        return TestClient(
            MCPGateway(
                proxy=self.proxy,
                backend_client=self.backend,
                snapshot_resolver=FakeSnapshotResolver(),
                allowed_origins=origins,
            ).create_app()
        )

    def modern_headers(self, method: str, name: str | None = None) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer test-token",
            "MCP-Protocol-Version": MODERN_PROTOCOL_VERSION,
            "Mcp-Method": method,
        }
        if name:
            headers["Mcp-Name"] = name
        return headers

    def modern_payload(self, method: str, params: dict | None = None) -> dict:
        value = dict(params or {})
        value["_meta"] = {
            MODERN_META_PROTOCOL_VERSION: MODERN_PROTOCOL_VERSION,
            MODERN_META_CLIENT_CAPABILITIES: {},
            MODERN_META_CLIENT_INFO: {"name": "test-client", "version": "1"},
        }
        return {"jsonrpc": "2.0", "id": 1, "method": method, "params": value}

    def legacy_session(self, version: str = LEGACY_PROTOCOL_VERSION) -> str:
        if version == "2024-11-05":
            raise AssertionError("2024-11-05 uses historical HTTP+SSE, not Mcp-Session-Id.")
        response = self.client.post(
            "/mcp/1",
            headers={"Content-Type": "application/json"},
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": version,
                    "capabilities": {},
                    "clientInfo": {"name": "legacy-test", "version": "1"},
                },
            },
        )
        self.assertEqual(response.status_code, 200)
        session = response.headers["mcp-session-id"]
        initialized = self.client.post(
            "/mcp/1",
            headers={
                "Content-Type": "application/json",
                "Mcp-Session-Id": session,
                **({"MCP-Protocol-Version": version} if version != "2024-11-05" else {}),
            },
            json={"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
        )
        self.assertEqual(initialized.status_code, 202)
        return session

    def legacy_2024_tool_call(self, params: dict) -> SimpleNamespace:
        if self.live_gateway is None:
            self.live_gateway = LiveGatewayServer(self.app)
        sse_url = f"{self.live_gateway.base_url}/mcp/1"
        sse_request = Request(sse_url, headers={"Accept": "text/event-stream"}, method="GET")
        sse_response = urlopen(sse_request, timeout=3)
        try:
            post_endpoint = urljoin(sse_url, read_endpoint_event(sse_response))
            self._legacy_2024_post(
                post_endpoint,
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {},
                        "clientInfo": {"name": "legacy-2024-test", "version": "1"},
                    },
                },
            )
            self._legacy_2024_read_message(sse_response)
            self._legacy_2024_post(
                post_endpoint,
                {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
            )
            self._legacy_2024_post(
                post_endpoint,
                {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": params},
                authorization=True,
            )
            message = self._legacy_2024_read_message(sse_response)
            status_code = 200 if "result" in message else 403
            return SimpleNamespace(status_code=status_code, json=lambda: message)
        finally:
            sse_response.close()

    def _legacy_2024_post(
        self,
        endpoint: str,
        payload: dict,
        *,
        authorization: bool = False,
    ) -> None:
        headers = {"Content-Type": "application/json"}
        if authorization:
            headers["Authorization"] = "Bearer test-token"
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        request = Request(endpoint, data=body, headers=headers, method="POST")
        with urlopen(request, timeout=3) as response:
            self.assertEqual(response.getcode(), 202)

    def _legacy_2024_read_message(self, sse_response) -> dict:
        for event in iter_sse_events(sse_response):
            if event.event != "message" or not event.data:
                continue
            return json.loads(event.data)
        raise AssertionError("legacy_2024_sse_message_missing")

    def test_origin_validation_rejects_untrusted_or_malformed_origins(self) -> None:
        origin_client = self.gateway_client_with_origins("https://example.com")
        valid = origin_client.post(
            "/mcp/1",
            headers={**self.modern_headers("server/discover"), "Origin": "https://example.com"},
            json=self.modern_payload("server/discover"),
        )
        self.assertEqual(valid.status_code, 200)

        missing = origin_client.post(
            "/mcp/1",
            headers=self.modern_headers("server/discover"),
            json=self.modern_payload("server/discover"),
        )
        self.assertEqual(missing.status_code, 200)

        rejected_origins = (
            "https://example.com.attacker.test",
            "http://example.com",
            "not an origin",
            "https://example.com, https://attacker.test",
        )
        for origin in rejected_origins:
            with self.subTest(origin=origin):
                response = origin_client.post(
                    "/mcp/1",
                    headers={**self.modern_headers("server/discover"), "Origin": origin},
                    json=self.modern_payload("server/discover"),
                )
                self.assertEqual(response.status_code, 403)

    def test_origin_validation_uses_effective_port_semantics(self) -> None:
        origin_client = self.gateway_client_with_origins("https://example.com:8443")

        valid = origin_client.post(
            "/mcp/1",
            headers={**self.modern_headers("server/discover"), "Origin": "https://example.com:8443"},
            json=self.modern_payload("server/discover"),
        )
        self.assertEqual(valid.status_code, 200)

        valid_get = origin_client.get(
            "/mcp/1",
            headers={
                "Accept": "text/event-stream",
                "MCP-Protocol-Version": MODERN_PROTOCOL_VERSION,
                "Origin": "https://example.com:8443",
            },
        )
        self.assertEqual(valid_get.status_code, 405)

        wrong_port = origin_client.post(
            "/mcp/1",
            headers={**self.modern_headers("server/discover"), "Origin": "https://example.com"},
            json=self.modern_payload("server/discover"),
        )
        self.assertEqual(wrong_port.status_code, 403)

        wrong_scheme = origin_client.get(
            "/mcp/1",
            headers={"Accept": "text/event-stream", "Origin": "http://example.com:8443"},
        )
        self.assertEqual(wrong_scheme.status_code, 403)

    def test_get_transport_routing_keeps_endpoint_event_only_for_2024_http_sse(self) -> None:
        if self.live_gateway is None:
            self.live_gateway = LiveGatewayServer(self.app)
        sse_url = f"{self.live_gateway.base_url}/mcp/1"
        sse_request = Request(sse_url, headers={"Accept": "text/event-stream"}, method="GET")
        sse_response = urlopen(sse_request, timeout=3)
        try:
            endpoint = read_endpoint_event(sse_response)
        finally:
            sse_response.close()
        self.assertIn("sse_connection_id=", endpoint)

        for profile_id, version in (
            (LEGACY_2025_03_26_PROFILE_ID, "2025-03-26"),
            (LEGACY_2025_06_18_PROFILE_ID, "2025-06-18"),
            (LEGACY_PROFILE_ID, LEGACY_PROTOCOL_VERSION),
            (MODERN_PROFILE_ID, MODERN_PROTOCOL_VERSION),
        ):
            with self.subTest(profile=profile_id, version=version):
                response = self.client.get(
                    "/mcp/1",
                    headers={
                        "Accept": "text/event-stream",
                        "MCP-Protocol-Version": version,
                    },
                )
                self.assertEqual(response.status_code, 405)
                self.assertNotIn("event: endpoint", response.text)

    def test_modern_discovery_and_inventory_are_proxy_generated(self) -> None:
        response = self.client.post(
            "/mcp/1",
            headers=self.modern_headers("server/discover"),
            json=self.modern_payload("server/discover"),
        )
        self.assertEqual(response.status_code, 200)
        discover = response.json()["result"]
        self.assertEqual(discover["resultType"], "complete")
        self.assertEqual(discover["ttlMs"], 0)
        self.assertEqual(discover["cacheScope"], "public")
        self.assertNotIn("serverInfo", discover)
        self.assertEqual(
            discover["_meta"][MODERN_META_SERVER_INFO]["name"],
            "mcp-security-framework-proxy",
        )
        response = self.client.post(
            "/mcp/1",
            headers=self.modern_headers("tools/list"),
            json=self.modern_payload("tools/list"),
        )
        tools_result = response.json()["result"]
        self.assertEqual(tools_result["resultType"], "complete")
        self.assertEqual(tools_result["ttlMs"], 0)
        self.assertEqual(tools_result["cacheScope"], "private")
        self.assertEqual([tool["name"] for tool in tools_result["tools"]], ["send_email"])

    def test_modern_tools_list_requires_valid_framework_identity(self) -> None:
        missing_headers = self.modern_headers("tools/list")
        missing_headers.pop("Authorization")
        missing = self.client.post(
            "/mcp/1",
            headers=missing_headers,
            json=self.modern_payload("tools/list"),
        )
        self.assertEqual(missing.status_code, 401)
        self.assertEqual(missing.json()["error"]["message"], "framework_identity_required")

        invalid_headers = self.modern_headers("tools/list")
        invalid_headers["Authorization"] = "Bearer invalid-token"
        invalid = self.client.post(
            "/mcp/1",
            headers=invalid_headers,
            json=self.modern_payload("tools/list"),
        )
        self.assertEqual(invalid.status_code, 401)
        self.assertEqual(invalid.json()["error"]["message"], "framework_identity_required")

        session_headers = self.modern_headers("tools/list")
        session_headers.pop("Authorization")
        session_headers["X-MCP-Framework-Session"] = "session-token"
        allowed = self.client.post(
            "/mcp/1",
            headers=session_headers,
            json=self.modern_payload("tools/list"),
        )
        self.assertEqual(allowed.status_code, 200)
        self.assertEqual(
            [tool["name"] for tool in allowed.json()["result"]["tools"]],
            ["send_email"],
        )
        self.assertEqual(self.proxy.upstream_invocations, 0)

    def test_legacy_tools_list_requires_valid_framework_identity_after_initialize(self) -> None:
        session = self.legacy_session()
        base_headers = {
            "Content-Type": "application/json",
            "MCP-Protocol-Version": LEGACY_PROTOCOL_VERSION,
            "Mcp-Session-Id": session,
        }
        missing = self.client.post(
            "/mcp/1",
            headers=base_headers,
            json={"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}},
        )
        self.assertEqual(missing.status_code, 401)
        self.assertEqual(missing.json()["error"]["message"], "framework_identity_required")

        allowed = self.client.post(
            "/mcp/1",
            headers={**base_headers, "Authorization": "Bearer test-token"},
            json={"jsonrpc": "2.0", "id": 4, "method": "tools/list", "params": {}},
        )
        self.assertEqual(allowed.status_code, 200)
        self.assertEqual([tool["name"] for tool in allowed.json()["result"]["tools"]], ["send_email"])

    def test_legacy_2024_tools_list_requires_framework_identity_after_initialize(self) -> None:
        if self.live_gateway is None:
            self.live_gateway = LiveGatewayServer(self.app)
        sse_url = f"{self.live_gateway.base_url}/mcp/1"
        sse_request = Request(sse_url, headers={"Accept": "text/event-stream"}, method="GET")
        sse_response = urlopen(sse_request, timeout=3)
        try:
            post_endpoint = urljoin(sse_url, read_endpoint_event(sse_response))
            self._legacy_2024_post(
                post_endpoint,
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {},
                        "clientInfo": {"name": "legacy-2024-test", "version": "1"},
                    },
                },
            )
            self._legacy_2024_read_message(sse_response)
            self._legacy_2024_post(
                post_endpoint,
                {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
            )

            self._legacy_2024_post(
                post_endpoint,
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            )
            missing_identity = self._legacy_2024_read_message(sse_response)
            self.assertEqual(
                missing_identity["error"]["message"],
                "framework_identity_required",
            )

            self._legacy_2024_post(
                post_endpoint,
                {"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}},
                authorization=True,
            )
            allowed = self._legacy_2024_read_message(sse_response)
            self.assertEqual(
                [tool["name"] for tool in allowed["result"]["tools"]],
                ["send_email"],
            )
        finally:
            sse_response.close()

    def test_tools_call_behavior_is_unchanged_by_tools_list_authentication(self) -> None:
        response = self.client.post(
            "/mcp/1",
            headers=self.modern_headers("tools/call", "send_email"),
            json=self.modern_payload(
                "tools/call",
                {
                    "name": "send_email",
                    "arguments": {
                        "recipient": "alice@example.com",
                        "subject": "hello",
                        "body": "world",
                    },
                },
            ),
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["result"]["content"][0]["text"], "sent")

    def test_strict_parser_and_modern_headers_fail_before_security_core(self) -> None:
        missing_header = self.client.post(
            "/mcp/1",
            headers={"Content-Type": "application/json", "MCP-Protocol-Version": MODERN_PROTOCOL_VERSION},
            json=self.modern_payload("tools/call", {"name": "send_email", "arguments": {}}),
        )
        self.assertEqual(missing_header.status_code, 400)
        duplicate = self.client.post(
            "/mcp/1",
            headers=self.modern_headers("tools/call", "send_email"),
            content=b'{"jsonrpc":"2.0","id":1,"id":2,"method":"tools/call","params":{}}',
        )
        self.assertEqual(duplicate.status_code, 400)
        batch = self.client.post(
            "/mcp/1",
            headers=self.modern_headers("tools/call", "send_email"),
            content=b'[]',
        )
        self.assertEqual(batch.status_code, 400)
        duplicate_header = self.client.post(
            "/mcp/1",
            headers=[
                ("Content-Type", "application/json"),
                ("Authorization", "Bearer test-token"),
                ("MCP-Protocol-Version", MODERN_PROTOCOL_VERSION),
                ("Mcp-Method", "tools/list"),
                ("Mcp-Method", "tools/call"),
            ],
            content=b'{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}',
        )
        self.assertEqual(duplicate_header.status_code, 400)
        self.assertEqual(self.proxy.upstream_invocations, 0)

    def test_legacy_lifecycle_and_protocol_sessions_are_isolated(self) -> None:
        first = self.legacy_session()
        second = self.legacy_session()
        self.assertNotEqual(first, second)
        wrong_server = self.client.post(
            "/mcp/2",
            headers={
                "Content-Type": "application/json",
                "MCP-Protocol-Version": LEGACY_PROTOCOL_VERSION,
                "Mcp-Session-Id": first,
            },
            json={"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}},
        )
        self.assertEqual(wrong_server.status_code, 400)

    def test_legacy_inbound_negotiates_and_pins_each_supported_revision(self) -> None:
        for version in LEGACY_PROTOCOL_VERSIONS:
            with self.subTest(version=version):
                expected_profile = restricted_profile_id(ProtocolEra.LEGACY, version)
                params = {
                    "name": "send_email",
                    "arguments": {
                        "recipient": "alice@example.com",
                        "subject": "hello",
                        "body": "world",
                    },
                }
                if version == "2024-11-05":
                    response = self.legacy_2024_tool_call(params)
                else:
                    session = self.legacy_session(version)
                    response = self.client.post(
                        "/mcp/1",
                        headers={
                            "Content-Type": "application/json",
                            "Authorization": "Bearer test-token",
                            "Mcp-Session-Id": session,
                            "MCP-Protocol-Version": version,
                        },
                        json={
                            "jsonrpc": "2.0",
                            "id": 3,
                            "method": "tools/call",
                            "params": params,
                        },
                    )
                self.assertEqual(response.status_code, 200)
                self.assertEqual(self.proxy.calls[-1][0], expected_profile)
                if version == "2024-11-05":
                    self.assertEqual(expected_profile, LEGACY_2024_11_05_PROFILE_ID)
                    self.assertEqual(
                        self.client.post(
                            "/mcp/1",
                            headers={"Content-Type": "application/json"},
                            json={
                                "jsonrpc": "2.0",
                                "id": 5,
                                "method": "initialize",
                                "params": {
                                    "protocolVersion": "2024-11-05",
                                    "capabilities": {},
                                    "clientInfo": {"name": "bad", "version": "1"},
                                },
                            },
                        ).status_code,
                        400,
                    )
                else:
                    self.assertEqual(
                        self.client.post(
                            "/mcp/1",
                            headers={
                                "Content-Type": "application/json",
                                "Mcp-Session-Id": session,
                                "MCP-Protocol-Version": "2027-01-01",
                            },
                            json={"jsonrpc": "2.0", "id": 4, "method": "tools/list", "params": {}},
                        ).status_code,
                        400,
                    )

    def test_unknown_future_protocol_revision_fails_before_security_core(self) -> None:
        response = self.client.post(
            "/mcp/1",
            headers={"Content-Type": "application/json", "MCP-Protocol-Version": "2027-01-01"},
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/list",
                "params": {"protocolVersion": "2027-01-01"},
            },
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.proxy.upstream_invocations, 0)

    def test_unsupported_method_families_are_denied_in_both_eras(self) -> None:
        modern_methods = (
            "resources/list",
            "prompts/list",
            "subscriptions/listen",
            "tasks/get",
        )
        for method in modern_methods:
            with self.subTest(profile="modern", method=method):
                response = self.client.post(
                    "/mcp/1",
                    headers=self.modern_headers(method),
                    json=self.modern_payload(method),
                )
                self.assertEqual(response.status_code, 400)

        legacy_methods = (
            "resources/list",
            "prompts/list",
            "sampling/createMessage",
            "elicitation/create",
            "roots/list",
            "tasks/get",
        )
        session = self.legacy_session()
        for method in legacy_methods:
            with self.subTest(profile="legacy", method=method):
                response = self.client.post(
                    "/mcp/1",
                    headers={
                        "Content-Type": "application/json",
                        "MCP-Protocol-Version": LEGACY_PROTOCOL_VERSION,
                        "Mcp-Session-Id": session,
                    },
                    json={"jsonrpc": "2.0", "id": 4, "method": method, "params": {}},
                )
                self.assertEqual(response.status_code, 400)
        self.assertEqual(self.proxy.upstream_invocations, 0)

    def test_four_cross_era_quadrants_share_allow_and_block_semantics(self) -> None:
        for client_profile in (MODERN_PROFILE_ID, LEGACY_PROFILE_ID):
            for upstream_profile in (MODERN_PROFILE_ID, LEGACY_PROFILE_ID):
                with self.subTest(client=client_profile, upstream=upstream_profile):
                    self.backend.upstream_profile = upstream_profile
                    for recipient, expected_status in (
                        ("alice@example.com", 200),
                        ("bob@example.com", 403),
                    ):
                        params = {
                            "name": "send_email",
                            "arguments": {
                                "recipient": recipient,
                                "subject": "hello",
                                "body": "world",
                            },
                        }
                        if client_profile == MODERN_PROFILE_ID:
                            response = self.client.post(
                                "/mcp/1",
                                headers=self.modern_headers("tools/call", "send_email"),
                                json=self.modern_payload("tools/call", params),
                            )
                        else:
                            session = self.legacy_session()
                            response = self.client.post(
                                "/mcp/1",
                                headers={
                                    "Content-Type": "application/json",
                                    "Authorization": "Bearer test-token",
                                    "MCP-Protocol-Version": LEGACY_PROTOCOL_VERSION,
                                    "Mcp-Session-Id": session,
                                },
                                json={"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": params},
                            )
                        self.assertEqual(response.status_code, expected_status)
        self.assertEqual(self.proxy.upstream_invocations, 4)
        blocked = [call for call in self.proxy.calls if call[2] == "bob@example.com"]
        self.assertEqual(len(blocked), 4)

    def test_all_revision_bridge_matrix_shares_allow_and_block_semantics(self) -> None:
        registry = ProtocolProfileRegistry()
        profile_ids = registry.supported_profile_ids()

        for client_profile_id in profile_ids:
            client_profile = registry.get(client_profile_id)
            for upstream_profile_id in profile_ids:
                with self.subTest(client=client_profile_id, upstream=upstream_profile_id):
                    self.backend.upstream_profile = upstream_profile_id
                    for recipient, expected_status in (
                        ("alice@example.com", 200),
                        ("bob@example.com", 403),
                    ):
                        params = {
                            "name": "send_email",
                            "arguments": {
                                "recipient": recipient,
                                "subject": "hello",
                                "body": "world",
                            },
                        }
                        if client_profile.protocol_era == ProtocolEra.MODERN:
                            response = self.client.post(
                                "/mcp/1",
                                headers=self.modern_headers("tools/call", "send_email"),
                                json=self.modern_payload("tools/call", params),
                            )
                        elif client_profile.protocol_version == "2024-11-05":
                            response = self.legacy_2024_tool_call(params)
                        else:
                            version = client_profile.protocol_version
                            session = self.legacy_session(version)
                            response = self.client.post(
                                "/mcp/1",
                                headers={
                                    "Content-Type": "application/json",
                                    "Authorization": "Bearer test-token",
                                    "Mcp-Session-Id": session,
                                    **({"MCP-Protocol-Version": version} if version != "2024-11-05" else {}),
                                },
                                json={"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": params},
                            )
                        self.assertEqual(response.status_code, expected_status)
                        self.assertEqual(self.proxy.calls[-1][0], client_profile_id)
                        self.assertEqual(self.proxy.calls[-1][1], upstream_profile_id)

        self.assertEqual(self.proxy.upstream_invocations, 25)
        blocked = [call for call in self.proxy.calls if call[2] == "bob@example.com"]
        self.assertEqual(len(blocked), 25)


class StrictJSONBoundaryTests(unittest.TestCase):
    def test_rejects_ambiguous_or_unsafe_json(self) -> None:
        invalid_documents = (
            b'\xef\xbb\xbf{"jsonrpc":"2.0"}',
            b'{"value":NaN}',
            b'{"value":9007199254740992}',
            b'{"value":1e400}',
            b'{"a":1,"a":2}',
        )
        for document in invalid_documents:
            with self.subTest(document=document[:24]):
                with self.assertRaises(StrictJSONError):
                    parse_strict_json(document)

    def test_rejects_excessive_depth(self) -> None:
        document = (b'{"a":' * 34) + b"0" + (b"}" * 34)
        with self.assertRaises(StrictJSONError):
            parse_strict_json(document)


if __name__ == "__main__":
    unittest.main()
