import json
import sys
import tempfile
import threading
import unittest
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend"
for path in (str(ROOT), str(BACKEND)):
    if path not in sys.path:
        sys.path.insert(0, path)

from app.schemas.server import MCPServerInternalRead, MCPServerRead  # noqa: E402
from app.services.mcp_discovery import MCPDiscoveryError, discover_http_mcp_server  # noqa: E402
from common.upstream_auth import (  # noqa: E402
    AUTH_MODE_BEARER,
    UpstreamAuthError,
    resolve_upstream_bearer_token,
)
from proxy.http_mcp_client import MCPHttpClient, MCPHttpError  # noqa: E402
from proxy.mcp_proxy import MCPProxy  # noqa: E402
from proxy.protocol_profiles import (  # noqa: E402
    MODERN_META_SERVER_INFO,
    MODERN_PROFILE_ID,
    MODERN_PROTOCOL_VERSION,
)


TEST_TOKEN = "test-secret"


class _AuthenticatedMCPHandler(BaseHTTPRequestHandler):
    authorized_requests = 0
    tool_calls = 0

    def do_POST(self):  # noqa: N802
        if self.headers.get("Authorization") != f"Bearer {TEST_TOKEN}":
            body = TEST_TOKEN.encode("utf-8")
            self.send_response(401)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        type(self).authorized_requests += 1
        length = int(self.headers.get("Content-Length", "0"))
        message = json.loads(self.rfile.read(length).decode("utf-8"))
        method = message.get("method")
        if method == "server/discover":
            self._write_json(
                {
                    "jsonrpc": "2.0",
                    "id": message.get("id"),
                    "result": {
                        "resultType": "complete",
                        "ttlMs": 0,
                        "cacheScope": "public",
                        "supportedVersions": [MODERN_PROTOCOL_VERSION],
                        "capabilities": {"tools": {}},
                        "_meta": {
                            MODERN_META_SERVER_INFO: {
                                "name": "authenticated-test",
                                "version": "1",
                            }
                        },
                    },
                }
            )
            return
        if method == "initialize":
            requested = message.get("params", {}).get("protocolVersion")
            self._write_json(
                {
                    "jsonrpc": "2.0",
                    "id": message.get("id"),
                    "result": {
                        "protocolVersion": requested,
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "authenticated-test", "version": "1"},
                    },
                },
                headers={"MCP-Session-Id": "authenticated-session"},
            )
            return
        if method == "notifications/initialized":
            self.send_response(202)
            self.end_headers()
            return
        if method == "tools/list":
            result = {
                "tools": [
                    {
                        "name": "safe_tool",
                        "description": "Return a safe value.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {},
                            "additionalProperties": False,
                        },
                    }
                ]
            }
            if self.headers.get("Mcp-Method") == "tools/list":
                result.update(
                    {"resultType": "complete", "ttlMs": 0, "cacheScope": "private"}
                )
            self._write_json(
                {"jsonrpc": "2.0", "id": message.get("id"), "result": result}
            )
            return
        if method == "tools/call":
            type(self).tool_calls += 1
            result = {"content": [{"type": "text", "text": "ok"}], "isError": False}
            if self.headers.get("Mcp-Method") == "tools/call":
                result["resultType"] = "complete"
            self._write_json(
                {"jsonrpc": "2.0", "id": message.get("id"), "result": result}
            )
            return
        self._write_json(
            {"jsonrpc": "2.0", "id": message.get("id"), "error": {"code": -32601}},
            status=400,
        )

    def _write_json(self, payload, status=200, headers=None):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):  # noqa: A003
        return


class UpstreamBearerAuthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = HTTPServer(("127.0.0.1", 0), _AuthenticatedMCPHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.endpoint = f"http://127.0.0.1:{cls.server.server_address[1]}/mcp"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.thread.join(timeout=5)
        cls.server.server_close()

    def setUp(self) -> None:
        _AuthenticatedMCPHandler.authorized_requests = 0
        _AuthenticatedMCPHandler.tool_calls = 0
        self.temp_dir = tempfile.TemporaryDirectory()
        self.secret_root = Path(self.temp_dir.name)
        (self.secret_root / "mcp" / "vendor").mkdir(parents=True)
        (self.secret_root / "mcp" / "vendor" / "service.token").write_text(
            TEST_TOKEN,
            encoding="utf-8",
        )
        self.secret_patch = patch(
            "common.upstream_auth.UPSTREAM_SECRET_DIR",
            self.secret_root,
        )
        self.secret_patch.start()

    def tearDown(self) -> None:
        self.secret_patch.stop()
        self.temp_dir.cleanup()

    def test_discovery_fails_closed_without_configured_credential(self) -> None:
        with self.assertRaises(MCPDiscoveryError) as context:
            discover_http_mcp_server(mcp_endpoint=self.endpoint)

        self.assertNotIn(TEST_TOKEN, str(context.exception))

    def test_discovery_and_runtime_use_framework_held_bearer_credential(self) -> None:
        discovery = discover_http_mcp_server(
            mcp_endpoint=self.endpoint,
            auth_mode=AUTH_MODE_BEARER,
            credential_ref="mcp/vendor/service.token",
        )
        token = resolve_upstream_bearer_token(
            AUTH_MODE_BEARER,
            "mcp/vendor/service.token",
        )
        client = MCPHttpClient(
            self.endpoint,
            protocol_profile_id=MODERN_PROFILE_ID,
            bearer_token=token,
        )
        result = client.call_tool("safe_tool", {})

        self.assertEqual(result["content"][0]["text"], "ok")
        self.assertGreater(_AuthenticatedMCPHandler.authorized_requests, 0)
        self.assertEqual(_AuthenticatedMCPHandler.tool_calls, 1)
        self.assertNotIn(TEST_TOKEN, json.dumps(discovery))

    def test_reflected_upstream_error_does_not_expose_secret(self) -> None:
        client = MCPHttpClient(
            self.endpoint,
            protocol_profile_id=MODERN_PROFILE_ID,
            bearer_token="wrong-token",
        )
        with self.assertRaises(MCPHttpError) as context:
            client.list_tools()

        self.assertNotIn(TEST_TOKEN, str(context.exception))
        self.assertEqual(str(context.exception), "MCP HTTP error 401")

    def test_secret_reference_cannot_escape_runtime_secret_root(self) -> None:
        with self.assertRaises(UpstreamAuthError):
            resolve_upstream_bearer_token(AUTH_MODE_BEARER, "../outside.token")

    def test_public_inventory_schema_never_returns_credential_reference_or_secret(self) -> None:
        payload = {
            "id": 7,
            "name": "authenticated-test",
            "server_type": "mcp",
            "endpoint": self.endpoint,
            "auth_mode": AUTH_MODE_BEARER,
            "credential_ref": "mcp/vendor/service.token",
            "created_at": datetime.utcnow(),
        }
        public = MCPServerRead.model_validate(payload).model_dump(mode="json")
        internal = MCPServerInternalRead.model_validate(payload).model_dump(mode="json")

        self.assertNotIn("credential_ref", public)
        self.assertEqual(internal["credential_ref"], "mcp/vendor/service.token")
        self.assertNotIn(TEST_TOKEN, json.dumps(public))
        self.assertNotIn(TEST_TOKEN, json.dumps(internal))

    def test_runtime_rejects_client_credential_override_fields(self) -> None:
        proxy = object.__new__(MCPProxy)
        proxy.backend_client = type(
            "Inventory",
            (),
            {"find_server": lambda self, server_id=None: None},
        )()
        for field in ("upstream_token", "authorization", "api_key", "credential"):
            with self.subTest(field=field):
                with self.assertRaisesRegex(
                    Exception,
                    "Runtime upstream credential override is not allowed",
                ):
                    proxy._resolve_server({"server_id": 1, field: "attacker-value"})


if __name__ == "__main__":
    unittest.main()
