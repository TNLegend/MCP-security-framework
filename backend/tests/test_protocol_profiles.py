import json
import queue
import time
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
from importlib.metadata import version as package_version

from proxy.http_mcp_client import MCPHttpClient, MCPProtocolError
from proxy.protocol_profiles import (
    LEGACY_2024_11_05_PROFILE_ID,
    LEGACY_2025_03_26_PROFILE_ID,
    LEGACY_2025_06_18_PROFILE_ID,
    LEGACY_PROFILE_ID,
    LEGACY_PROTOCOL_VERSION,
    LEGACY_PROTOCOL_VERSIONS,
    MODERN_CACHE_TTL_MS,
    MODERN_DISCOVER_CACHE_SCOPE,
    MODERN_PROFILE_ID,
    MODERN_META_CLIENT_CAPABILITIES,
    MODERN_META_CLIENT_INFO,
    MODERN_META_PROTOCOL_VERSION,
    MODERN_META_SERVER_INFO,
    MODERN_PROTOCOL_VERSION,
    MODERN_TOOLS_LIST_CACHE_SCOPE,
    ProtocolProfileError,
    ProtocolProfileRegistry,
    SUPPORTED_MCP_PROTOCOL_VERSIONS,
)
from proxy.protocol_negotiation import ProtocolNegotiationError, ProtocolNegotiator, protocol_rediscovery_due
from proxy.protocol_revisions import ProtocolRevisionRegistry, TransportKind
from scripts.discover_http_mcp_server import discover_server


class ProtocolProfileTests(unittest.TestCase):
    def test_mcp_types_registry_is_pinned_and_framework_revisions_are_explicit(self):
        registry = ProtocolRevisionRegistry()

        self.assertEqual(package_version("mcp-types"), "2.0.0")
        self.assertEqual(
            SUPPORTED_MCP_PROTOCOL_VERSIONS,
            ("2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25", "2026-07-28"),
        )
        self.assertEqual(
            LEGACY_PROTOCOL_VERSIONS,
            ("2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"),
        )
        for version in SUPPORTED_MCP_PROTOCOL_VERSIONS:
            self.assertIn(version, registry.official_known_versions)
            self.assertTrue(registry.is_framework_supported(version))
        self.assertTrue(registry.is_known("2024-10-07"))
        self.assertFalse(registry.is_framework_supported("2024-10-07"))
        self.assertFalse(registry.is_framework_supported("2027-01-01"))
        with self.assertRaises(ProtocolProfileError):
            ProtocolProfileRegistry().get_by_version("2027-01-01")

    def test_periodic_rediscovery_due_window(self):
        from datetime import datetime, timedelta

        now = datetime(2026, 8, 12, 12, 0, 0)
        self.assertTrue(protocol_rediscovery_due(None, now=now))
        self.assertFalse(
            protocol_rediscovery_due(
                now - timedelta(seconds=899),
                interval_seconds=900,
                now=now,
            )
        )
        self.assertTrue(
            protocol_rediscovery_due(
                now - timedelta(seconds=900),
                interval_seconds=900,
                now=now,
            )
        )

    def test_canonical_arguments_hash_ignores_json_key_order(self):
        profile = ProtocolProfileRegistry().get(LEGACY_PROFILE_ID)

        left = profile.normalize_tool_call(
            server_ref="streamable_http:http://127.0.0.1:9000/mcp",
            tool_name="send_email",
            arguments={"b": 2, "a": 1},
            client_protocol_profile_id=LEGACY_PROFILE_ID,
            request_id="req-1",
        )
        right = profile.normalize_tool_call(
            server_ref="streamable_http:http://127.0.0.1:9000/mcp",
            tool_name="send_email",
            arguments={"a": 1, "b": 2},
            client_protocol_profile_id=LEGACY_PROFILE_ID,
            request_id="req-2",
        )

        self.assertEqual(left.canonical_args_hash, right.canonical_args_hash)

    def test_canonical_arguments_hash_uses_rfc8785_for_nested_unicode_and_numbers(self):
        profile = ProtocolProfileRegistry().get(LEGACY_PROFILE_ID)
        left = profile.normalize_tool_call(
            server_ref="server-a",
            tool_name="tool",
            arguments={"nested": {"z": [0, 1.5, "é"], "a": {}}},
            client_protocol_profile_id=LEGACY_PROFILE_ID,
            request_id="req-1",
        )
        right = profile.normalize_tool_call(
            server_ref="server-a",
            tool_name="tool",
            arguments={"nested": {"a": {}, "z": [0, 1.5, "é"]}},
            client_protocol_profile_id=LEGACY_PROFILE_ID,
            request_id="req-2",
        )
        self.assertEqual(left.canonical_args_hash, right.canonical_args_hash)

    def test_all_framework_revisions_validate_wire_and_share_normalization(self):
        registry = ProtocolProfileRegistry()
        fingerprints = set()
        for version in SUPPORTED_MCP_PROTOCOL_VERSIONS:
            with self.subTest(version=version):
                profile = registry.get_by_version(version)
                payload, headers = profile.serialize_request(
                    request_id=7,
                    method="tools/list",
                    params={},
                )
                profile.validate_inbound_request(payload, headers=headers)
                result = {"tools": []}
                if version == MODERN_PROTOCOL_VERSION:
                    result.update(
                        {
                            "resultType": "complete",
                            "ttlMs": 0,
                            "cacheScope": "private",
                        }
                    )
                profile.validate_list_tools_result(result)
                call = profile.normalize_tool_call(
                    server_ref="mail-a",
                    tool_name="send_email",
                    arguments={"body": "hello", "recipient": "alice@example.com"},
                    client_protocol_profile_id=profile.profile_id,
                    request_id=f"req-{version}",
                )
                fingerprints.add(call.canonical_args_hash)
                self.assertEqual(call.client_protocol_version, version)
                self.assertEqual(call.upstream_protocol_version, version)
        self.assertEqual(len(fingerprints), 1)

    def test_wire_valid_but_framework_forbidden_method_is_rejected(self):
        registry = ProtocolProfileRegistry()
        for version in SUPPORTED_MCP_PROTOCOL_VERSIONS:
            with self.subTest(version=version):
                profile = registry.get_by_version(version)
                params = {}
                headers = {}
                if version == MODERN_PROTOCOL_VERSION:
                    params = self._modern_payload("resources/list")["params"]
                    headers = self._modern_headers("resources/list")
                payload = {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "resources/list",
                    "params": params,
                }
                with self.assertRaisesRegex(
                    ProtocolProfileError,
                    "restricted_method_surface_unsupported_feature|unsupported_mcp_method",
                ):
                    profile.validate_inbound_request(payload, headers=headers)

    @staticmethod
    def _modern_payload(method="tools/list", *, name=None):
        params = {
            "_meta": {
                MODERN_META_PROTOCOL_VERSION: MODERN_PROTOCOL_VERSION,
                MODERN_META_CLIENT_CAPABILITIES: {},
                MODERN_META_CLIENT_INFO: {"name": "test-client", "version": "1"},
            }
        }
        if name is not None:
            params.update({"name": name, "arguments": {}})
        return {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}

    @staticmethod
    def _modern_headers(method="tools/list", *, name=None):
        headers = {
            "MCP-Protocol-Version": MODERN_PROTOCOL_VERSION,
            "Mcp-Method": method,
        }
        if name is not None:
            headers["Mcp-Name"] = name
        return headers

    def test_modern_inbound_rejects_header_method_mismatch(self):
        profile = ProtocolProfileRegistry().get(MODERN_PROFILE_ID)

        with self.assertRaisesRegex(ProtocolProfileError, "modern_method_header_mismatch"):
            profile.validate_inbound_request(
                self._modern_payload(),
                headers={
                    "MCP-Protocol-Version": MODERN_PROTOCOL_VERSION,
                    "Mcp-Method": "tools/call",
                },
            )

    def test_modern_inbound_rejects_tool_name_mismatch(self):
        profile = ProtocolProfileRegistry().get(MODERN_PROFILE_ID)

        with self.assertRaisesRegex(ProtocolProfileError, "modern_tool_name_header_mismatch"):
            profile.validate_inbound_request(
                self._modern_payload("tools/call", name="safe_tool"),
                headers={
                    "MCP-Protocol-Version": MODERN_PROTOCOL_VERSION,
                    "Mcp-Method": "tools/call",
                    "Mcp-Name": "other_tool",
                },
            )

    def test_modern_inbound_requires_qualified_metadata(self):
        profile = ProtocolProfileRegistry().get(MODERN_PROFILE_ID)
        payload = self._modern_payload()
        payload["params"]["_meta"].pop(MODERN_META_PROTOCOL_VERSION)
        with self.assertRaisesRegex(ProtocolProfileError, "modern_protocol_version_mismatch"):
            profile.validate_inbound_request(payload, headers=self._modern_headers())

        payload = self._modern_payload()
        payload["params"]["_meta"].pop(MODERN_META_CLIENT_CAPABILITIES)
        with self.assertRaisesRegex(ProtocolProfileError, "modern_client_capabilities_invalid"):
            profile.validate_inbound_request(payload, headers=self._modern_headers())

    def test_modern_inbound_requires_routing_headers(self):
        profile = ProtocolProfileRegistry().get(MODERN_PROFILE_ID)
        with self.assertRaisesRegex(ProtocolProfileError, "modern_protocol_header_mismatch"):
            profile.validate_inbound_request(self._modern_payload(), headers={"Mcp-Method": "tools/list"})
        with self.assertRaisesRegex(ProtocolProfileError, "modern_method_header_mismatch"):
            profile.validate_inbound_request(
                self._modern_payload(),
                headers={"MCP-Protocol-Version": MODERN_PROTOCOL_VERSION},
            )
        with self.assertRaisesRegex(ProtocolProfileError, "modern_tool_name_header_mismatch"):
            profile.validate_inbound_request(
                self._modern_payload("tools/call", name="safe_tool"),
                headers=self._modern_headers("tools/call"),
            )

    def test_modern_inbound_rejects_malformed_or_reserved_metadata(self):
        profile = ProtocolProfileRegistry().get(MODERN_PROFILE_ID)
        payload = self._modern_payload()
        payload["params"]["_meta"][MODERN_META_CLIENT_CAPABILITIES] = []
        with self.assertRaisesRegex(ProtocolProfileError, "modern_client_capabilities_invalid"):
            profile.validate_inbound_request(payload, headers=self._modern_headers())

        payload = self._modern_payload()
        payload["params"]["_meta"]["io.modelcontextprotocol/securityOverride"] = True
        with self.assertRaisesRegex(ProtocolProfileError, "modern_security_metadata_unsupported"):
            profile.validate_inbound_request(payload, headers=self._modern_headers())

    def test_modern_inbound_accepts_exact_metadata_and_headers(self):
        profile = ProtocolProfileRegistry().get(MODERN_PROFILE_ID)
        profile.validate_inbound_request(
            self._modern_payload("tools/call", name="safe_tool"),
            headers=self._modern_headers("tools/call", name="safe_tool"),
        )

    def test_modern_response_rejects_mrtr_input_required(self):
        profile = ProtocolProfileRegistry().get(MODERN_PROFILE_ID)

        with self.assertRaisesRegex(
            ProtocolProfileError,
            "modern_mrtr_input_required_unsupported",
        ):
            profile.validate_tool_response(
                {"resultType": "input_required", "inputRequests": []}
            )

    def test_modern_response_allows_complete_result(self):
        profile = ProtocolProfileRegistry().get(MODERN_PROFILE_ID)
        profile.validate_tool_response({"resultType": "complete", "content": []})

    def test_modern_response_requires_complete_result_type(self):
        profile = ProtocolProfileRegistry().get(MODERN_PROFILE_ID)
        with self.assertRaisesRegex(ProtocolProfileError, "modern_result_type_missing"):
            profile.validate_tool_response({"content": []})
        with self.assertRaisesRegex(ProtocolProfileError, "modern_result_type_unsupported"):
            profile.validate_tool_response({"resultType": "future", "content": []})

    def test_modern_discover_requires_cache_hints_and_meta_server_info_location(self):
        profile = ProtocolProfileRegistry().get(MODERN_PROFILE_ID)
        profile.validate_discover_result(
            {
                "resultType": "complete",
                "ttlMs": MODERN_CACHE_TTL_MS,
                "cacheScope": MODERN_DISCOVER_CACHE_SCOPE,
                "supportedVersions": [MODERN_PROTOCOL_VERSION],
                "capabilities": {"tools": {}},
                "_meta": {
                    MODERN_META_SERVER_INFO: {
                        "name": "server",
                        "version": "1",
                    }
                },
            }
        )
        with self.assertRaisesRegex(ProtocolProfileError, "server_info_top_level"):
            profile.validate_discover_result(
                {
                    "resultType": "complete",
                    "ttlMs": 0,
                    "cacheScope": "public",
                    "supportedVersions": [MODERN_PROTOCOL_VERSION],
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "server", "version": "1"},
                }
            )

    def test_modern_tools_list_requires_cache_hints(self):
        profile = ProtocolProfileRegistry().get(MODERN_PROFILE_ID)
        profile.validate_list_tools_result(
            {
                "resultType": "complete",
                "ttlMs": MODERN_CACHE_TTL_MS,
                "cacheScope": MODERN_TOOLS_LIST_CACHE_SCOPE,
                "tools": [],
            }
        )
        with self.assertRaisesRegex(ProtocolProfileError, "ttl_invalid"):
            profile.validate_list_tools_result(
                {
                    "resultType": "complete",
                    "cacheScope": "private",
                    "tools": [],
                }
            )

    def test_modern_serializer_generates_list_request_metadata_and_headers(self):
        profile = ProtocolProfileRegistry().get(MODERN_PROFILE_ID)
        payload, headers = profile.serialize_request(
            request_id=7,
            method="tools/list",
            params={},
        )
        self.assertEqual(payload["method"], "tools/list")
        self.assertEqual(headers["MCP-Protocol-Version"], MODERN_PROTOCOL_VERSION)
        self.assertEqual(headers["Mcp-Method"], "tools/list")
        self.assertNotIn("Mcp-Name", headers)
        meta = payload["params"]["_meta"]
        self.assertEqual(meta[MODERN_META_PROTOCOL_VERSION], MODERN_PROTOCOL_VERSION)
        self.assertEqual(meta[MODERN_META_CLIENT_CAPABILITIES], {})
        self.assertEqual(meta[MODERN_META_CLIENT_INFO]["name"], "mcp-security-framework-proxy")

    def test_response_validators_reject_nested_resources_and_tasks(self):
        modern = ProtocolProfileRegistry().get(MODERN_PROFILE_ID)
        legacy = ProtocolProfileRegistry().get(LEGACY_PROFILE_ID)
        with self.assertRaisesRegex(ProtocolProfileError, "resource"):
            modern.validate_tool_response(
                {
                    "resultType": "complete",
                    "content": [{"type": "resource", "resource": {"uri": "file:///x"}}],
                }
            )
        with self.assertRaisesRegex(ProtocolProfileError, "task"):
            legacy.validate_tool_response(
                {"content": [{"type": "text", "text": "queued", "task": {"id": "1"}}]}
            )


class _MCPHandler(BaseHTTPRequestHandler):
    profile = LEGACY_PROFILE_ID
    requests = []

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        message = json.loads(body.decode("utf-8"))
        type(self).requests.append((dict(self.headers), message))
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
                            MODERN_META_SERVER_INFO: {"name": "modern-test", "version": "1"}
                        },
                    },
                }
            )
            return

        if method == "initialize":
            self._write_json(
                {
                    "jsonrpc": "2.0",
                    "id": message.get("id"),
                    "result": {
                        "protocolVersion": "2025-11-25",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "legacy-test", "version": "1"},
                    },
                },
                headers={"MCP-Session-Id": "test-session"},
            )
            return

        if method == "notifications/initialized":
            self.send_response(202)
            self.end_headers()
            return

        if method == "tools/call":
            result = {"content": [{"type": "text", "text": "ok"}]}
            if type(self).profile == MODERN_PROFILE_ID:
                result["resultType"] = "complete"
            self._write_json({"jsonrpc": "2.0", "id": message.get("id"), "result": result})
            return

        if method == "tools/list":
            result = {"tools": []}
            if type(self).profile == MODERN_PROFILE_ID:
                result.update({"resultType": "complete", "ttlMs": 0, "cacheScope": "private"})
            self._write_json({"jsonrpc": "2.0", "id": message.get("id"), "result": result})
            return

        self._write_json(
            {"jsonrpc": "2.0", "id": message.get("id"), "error": {"code": -32601}},
            status=400,
        )

    def log_message(self, format, *args):  # noqa: A003
        return

    def _write_json(self, payload, status=200, headers=None):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _LegacySSEHandler(BaseHTTPRequestHandler):
    requests = []
    get_count = 0
    sse_responses_delivered = 0
    events: queue.Queue[bytes | None] = queue.Queue()

    @classmethod
    def reset(cls):
        cls.requests = []
        cls.get_count = 0
        cls.sse_responses_delivered = 0
        cls.events = queue.Queue()

    def do_GET(self):  # noqa: N802
        type(self).get_count += 1
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(b"event: endpoint\ndata: /messages\n\n")
        self.wfile.flush()
        while True:
            try:
                event = type(self).events.get(timeout=30)
            except queue.Empty:
                event = b": keepalive\n\n"
            if event is None:
                return
            try:
                self.wfile.write(event)
                self.wfile.flush()
            except OSError:
                return

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        message = json.loads(self.rfile.read(length).decode("utf-8"))
        type(self).requests.append((self.path, dict(self.headers), message))
        method = message.get("method")
        if method == "initialize":
            self._enqueue_message(
                {
                    "jsonrpc": "2.0",
                    "id": message.get("id"),
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "legacy-sse", "version": "1"},
                    },
                }
            )
            self._accepted()
            return
        if method == "notifications/initialized":
            self._accepted()
            return
        if method == "tools/call":
            self._enqueue_message(
                {
                    "jsonrpc": "2.0",
                    "id": message.get("id"),
                    "result": {"content": [{"type": "text", "text": "sse-ok"}]},
                }
            )
            self._accepted()
            return
        if method == "tools/list":
            self._enqueue_message(
                {"jsonrpc": "2.0", "id": message.get("id"), "result": {"tools": []}}
            )
            self._accepted()
            return
        self._enqueue_message(
            {
                "jsonrpc": "2.0",
                "id": message.get("id"),
                "error": {"code": -32601, "message": "method not found"},
            }
        )
        self._accepted()

    def log_message(self, format, *args):  # noqa: A003
        return

    def _accepted(self):
        self.send_response(202)
        self.send_header("Content-Length", "0")
        self.send_header("X-Post-Body-Contains-Result", "false")
        self.end_headers()

    def _enqueue_message(self, payload):
        type(self).sse_responses_delivered += 1
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        type(self).events.put(b"event: message\ndata: " + body + b"\n\n")

    def _write_json(self, payload, status=200, headers=None):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class HTTPClientProtocolTests(unittest.TestCase):
    def setUp(self):
        _MCPHandler.profile = LEGACY_PROFILE_ID
        _MCPHandler.requests = []
        self.server = HTTPServer(("127.0.0.1", 0), _MCPHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.endpoint = f"http://127.0.0.1:{self.server.server_address[1]}/mcp"

    def tearDown(self):
        self.server.shutdown()
        self.thread.join(timeout=5)
        self.server.server_close()

    def test_legacy_client_executes_legacy_lifecycle(self):
        client = MCPHttpClient(self.endpoint, protocol_profile_id=LEGACY_PROFILE_ID)

        result = client.call_tool("safe_tool", {"x": 1})

        self.assertEqual(result["content"][0]["text"], "ok")
        methods = [message.get("method") for _, message in _MCPHandler.requests]
        self.assertEqual(methods, ["initialize", "notifications/initialized", "tools/call"])

    def test_legacy_2024_http_sse_client_uses_endpoint_event_transport(self):
        _LegacySSEHandler.reset()
        server = ThreadingHTTPServer(("127.0.0.1", 0), _LegacySSEHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        client = None
        try:
            endpoint = f"http://127.0.0.1:{server.server_address[1]}/sse"
            client = MCPHttpClient(endpoint, protocol_profile_id=LEGACY_2024_11_05_PROFILE_ID)

            result = client.call_tool("safe_tool", {"x": 1})

            self.assertEqual(result["content"][0]["text"], "sse-ok")
            self.assertEqual(_LegacySSEHandler.get_count, 1)
            self.assertTrue(all(path == "/messages" for path, _, _ in _LegacySSEHandler.requests))
            self.assertTrue(
                all(
                    "mcp-protocol-version"
                    not in {name.lower() for name in headers}
                    for _, headers, _ in _LegacySSEHandler.requests
                )
            )
            methods = [message.get("method") for _, _, message in _LegacySSEHandler.requests]
            self.assertEqual(methods, ["initialize", "notifications/initialized", "tools/call"])
            self.assertEqual(_LegacySSEHandler.sse_responses_delivered, 2)
        finally:
            if client is not None:
                client.close()
            _LegacySSEHandler.events.put(None)
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()

    def test_modern_client_does_not_run_legacy_initialize(self):
        _MCPHandler.profile = MODERN_PROFILE_ID
        client = MCPHttpClient(self.endpoint, protocol_profile_id=MODERN_PROFILE_ID)

        result = client.call_tool("safe_tool", {"x": 1})

        self.assertEqual(result["resultType"], "complete")
        self.assertEqual(len(_MCPHandler.requests), 1)
        headers, message = _MCPHandler.requests[0]
        self.assertEqual(message["method"], "tools/call")
        self.assertEqual(headers.get("Mcp-Method"), "tools/call")
        self.assertEqual(headers.get("Mcp-Name"), "safe_tool")
        meta = message["params"]["_meta"]
        self.assertEqual(meta[MODERN_META_PROTOCOL_VERSION], MODERN_PROTOCOL_VERSION)
        self.assertEqual(meta[MODERN_META_CLIENT_CAPABILITIES], {})
        self.assertEqual(meta[MODERN_META_CLIENT_INFO]["name"], "mcp-security-framework-proxy")

    def test_modern_client_list_tools_uses_modern_serializer(self):
        _MCPHandler.profile = MODERN_PROFILE_ID
        client = MCPHttpClient(self.endpoint, protocol_profile_id=MODERN_PROFILE_ID)

        result = client.list_tools()

        self.assertEqual(result["resultType"], "complete")
        headers, message = _MCPHandler.requests[0]
        self.assertEqual(message["method"], "tools/list")
        self.assertIn("_meta", message["params"])
        self.assertEqual(headers.get("Mcp-Method"), "tools/list")
        self.assertIsNone(headers.get("Mcp-Name"))
        meta = message["params"]["_meta"]
        self.assertEqual(meta[MODERN_META_PROTOCOL_VERSION], MODERN_PROTOCOL_VERSION)
        self.assertEqual(meta[MODERN_META_CLIENT_CAPABILITIES], {})

    def test_modern_client_blocks_unsupported_mrtr_response(self):
        class MRTRHandler(_MCPHandler):
            def do_POST(self):  # noqa: N802
                length = int(self.headers.get("Content-Length", "0"))
                message = json.loads(self.rfile.read(length).decode("utf-8"))
                self._write_json(
                    {
                        "jsonrpc": "2.0",
                        "id": message.get("id"),
                        "result": {"resultType": "input_required", "inputRequests": []},
                    }
                )

        server = HTTPServer(("127.0.0.1", 0), MRTRHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            endpoint = f"http://127.0.0.1:{server.server_address[1]}/mcp"
            client = MCPHttpClient(endpoint, protocol_profile_id=MODERN_PROFILE_ID)
            with self.assertRaisesRegex(MCPProtocolError, "modern_mrtr_input_required"):
                client.call_tool("safe_tool", {})
        finally:
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()

    def test_negotiator_prefers_modern_when_discover_succeeds(self):
        _MCPHandler.profile = MODERN_PROFILE_ID
        result = ProtocolNegotiator().negotiate(
            endpoint=self.endpoint,
            registered_endpoint=self.endpoint,
        )
        self.assertEqual(result.preferred_upstream_profile, MODERN_PROFILE_ID)
        self.assertEqual(
            result.supported_protocol_profiles,
            (MODERN_PROFILE_ID, LEGACY_PROFILE_ID),
        )

    def test_negotiator_does_not_infer_legacy_from_modern(self):
        class ModernOnlyHandler(_MCPHandler):
            def do_POST(self):  # noqa: N802
                length = int(self.headers.get("Content-Length", "0"))
                message = json.loads(self.rfile.read(length).decode("utf-8"))
                if message.get("method") == "server/discover":
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
                                        "name": "modern-only",
                                        "version": "1",
                                    }
                                },
                            },
                        }
                    )
                    return
                self._write_json(
                    {"jsonrpc": "2.0", "id": message.get("id"), "error": {"code": -32601}},
                    status=400,
                )

        server = HTTPServer(("127.0.0.1", 0), ModernOnlyHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            endpoint = f"http://127.0.0.1:{server.server_address[1]}/mcp"
            result = ProtocolNegotiator().negotiate(
                endpoint=endpoint,
                registered_endpoint=endpoint,
            )
            self.assertEqual(result.supported_protocol_profiles, (MODERN_PROFILE_ID,))
        finally:
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()

    def test_negotiator_fail_closed_probe_classification(self):
        negotiator = ProtocolNegotiator()
        for error in ("probe_timeout", "http_401", "http_403", "http_500", "http_503"):
            with self.subTest(error=error):
                self.assertTrue(negotiator._probe_error_is_terminal(error))
        for error in ("http_400", "http_404", "http_405"):
            with self.subTest(error=error):
                self.assertFalse(negotiator._probe_error_is_terminal(error))

    def test_negotiator_recognized_modern_error_does_not_fallback_to_legacy(self):
        class ModernMismatchButLegacyWorksHandler(_MCPHandler):
            def do_POST(self):  # noqa: N802
                length = int(self.headers.get("Content-Length", "0"))
                message = json.loads(self.rfile.read(length).decode("utf-8"))
                if message.get("method") == "server/discover":
                    self._write_json(
                        {
                            "jsonrpc": "2.0",
                            "id": message.get("id"),
                            "error": {
                                "code": -32022,
                                "message": "no mutually supported version",
                                "data": {"supported": ["2027-01-01"]},
                            },
                        },
                        status=400,
                    )
                    return
                if message.get("method") == "initialize":
                    self._write_json(
                        {
                            "jsonrpc": "2.0",
                            "id": message.get("id"),
                            "result": {
                                "protocolVersion": LEGACY_PROTOCOL_VERSION,
                                "capabilities": {"tools": {}},
                                "serverInfo": {"name": "legacy", "version": "1"},
                            },
                        },
                        headers={"MCP-Session-Id": "legacy-session"},
                    )
                    return
                self._write_json({"jsonrpc": "2.0", "id": message.get("id"), "result": {"tools": []}})

        server = HTTPServer(("127.0.0.1", 0), ModernMismatchButLegacyWorksHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            endpoint = f"http://127.0.0.1:{server.server_address[1]}/mcp"
            with self.assertRaisesRegex(
                ProtocolNegotiationError,
                "modern_probe_failed_closed:recognized_modern_protocol_error",
            ):
                ProtocolNegotiator().negotiate(endpoint=endpoint, registered_endpoint=endpoint)
        finally:
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()

    def test_negotiator_timeout_does_not_fallback_to_legacy(self):
        class TimeoutHandler(_MCPHandler):
            def do_POST(self):  # noqa: N802
                length = int(self.headers.get("Content-Length", "0"))
                self.rfile.read(length)
                time.sleep(0.3)
                try:
                    self._write_json({"jsonrpc": "2.0", "id": 1, "result": {}})
                except OSError:
                    return

        server = HTTPServer(("127.0.0.1", 0), TimeoutHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            endpoint = f"http://127.0.0.1:{server.server_address[1]}/mcp"
            with self.assertRaisesRegex(ProtocolNegotiationError, "probe_timeout"):
                ProtocolNegotiator(timeout_seconds=0.05).negotiate(
                    endpoint=endpoint,
                    registered_endpoint=endpoint,
                )
        finally:
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()

    def test_negotiator_records_all_supported_legacy_streamable_revisions(self):
        class MultiLegacyHandler(_MCPHandler):
            def do_POST(self):  # noqa: N802
                length = int(self.headers.get("Content-Length", "0"))
                message = json.loads(self.rfile.read(length).decode("utf-8"))
                if message.get("method") == "server/discover":
                    self._write_json(
                        {"jsonrpc": "2.0", "id": message.get("id"), "error": {"code": -32601}},
                        status=404,
                    )
                    return
                if message.get("method") == "initialize":
                    requested = message.get("params", {}).get("protocolVersion")
                    self._write_json(
                        {
                            "jsonrpc": "2.0",
                            "id": message.get("id"),
                            "result": {
                                "protocolVersion": requested,
                                "capabilities": {"tools": {}},
                                "serverInfo": {"name": "multi-legacy", "version": "1"},
                            },
                        },
                        headers={"MCP-Session-Id": f"session-{requested}"},
                    )
                    return
                self._write_json({"jsonrpc": "2.0", "id": message.get("id"), "result": {"tools": []}})

        server = HTTPServer(("127.0.0.1", 0), MultiLegacyHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            endpoint = f"http://127.0.0.1:{server.server_address[1]}/mcp"
            result = ProtocolNegotiator().negotiate(endpoint=endpoint, registered_endpoint=endpoint)
            self.assertEqual(result.detected_era, "legacy")
            self.assertEqual(result.preferred_upstream_profile, LEGACY_PROFILE_ID)
            self.assertEqual(
                set(result.supported_protocol_profiles),
                {LEGACY_PROFILE_ID, LEGACY_2025_06_18_PROFILE_ID, LEGACY_2025_03_26_PROFILE_ID},
            )
            self.assertEqual(
                set(result.supported_protocol_versions),
                {"2025-11-25", "2025-06-18", "2025-03-26"},
            )
        finally:
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()

    def test_negotiator_supports_legacy_2024_http_sse_transport(self):
        _LegacySSEHandler.reset()

        class LegacySSEOnlyHandler(_LegacySSEHandler):
            def do_POST(self):  # noqa: N802
                if self.path != "/messages":
                    length = int(self.headers.get("Content-Length", "0"))
                    self.rfile.read(length)
                    self._write_json(
                        {"jsonrpc": "2.0", "id": 1, "error": {"code": -32601}},
                        status=404,
                    )
                    return
                super().do_POST()

        server = ThreadingHTTPServer(("127.0.0.1", 0), LegacySSEOnlyHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            endpoint = f"http://127.0.0.1:{server.server_address[1]}/sse"
            result = ProtocolNegotiator().negotiate(endpoint=endpoint, registered_endpoint=endpoint)
            self.assertEqual(result.supported_protocol_profiles, (LEGACY_2024_11_05_PROFILE_ID,))
            self.assertEqual(result.supported_protocol_versions, ("2024-11-05",))
            self.assertEqual(result.transport_kind, TransportKind.LEGACY_HTTP_SSE.value)
        finally:
            LegacySSEOnlyHandler.events.put(None)
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()

    def test_discovery_records_one_observation_per_supported_profile(self):
        class DualDiscoveryHandler(_MCPHandler):
            def do_POST(self):  # noqa: N802
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
                                        "name": "dual",
                                        "version": "1",
                                    }
                                },
                            },
                        }
                    )
                    return
                if method == "initialize":
                    self._write_json(
                        {
                            "jsonrpc": "2.0",
                            "id": message.get("id"),
                            "result": {
                                "protocolVersion": LEGACY_PROTOCOL_VERSION,
                                "capabilities": {"tools": {}},
                                "serverInfo": {"name": "dual", "version": "1"},
                            },
                        },
                        headers={"MCP-Session-Id": "discovery-session"},
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
                                "name": "echo",
                                "description": "Echo text.",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {"text": {"type": "string"}},
                                    "required": ["text"],
                                    "additionalProperties": False,
                                },
                            }
                        ]
                    }
                    if self.headers.get("MCP-Protocol-Version") == MODERN_PROTOCOL_VERSION:
                        result["resultType"] = "complete"
                        result["ttlMs"] = 0
                        result["cacheScope"] = "private"
                    self._write_json(
                        {"jsonrpc": "2.0", "id": message.get("id"), "result": result}
                    )
                    return
                self._write_json(
                    {"jsonrpc": "2.0", "id": message.get("id"), "error": {"code": -32601}},
                    status=400,
                )

        server = HTTPServer(("127.0.0.1", 0), DualDiscoveryHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            endpoint = f"http://127.0.0.1:{server.server_address[1]}/mcp"
            discovery = discover_server(endpoint, LEGACY_PROTOCOL_VERSION)
            payload = discovery["payload"]
            self.assertEqual(payload["server"]["preferred_upstream_profile"], MODERN_PROFILE_ID)
            self.assertEqual(
                {tool["upstream_protocol_profile_id"] for tool in payload["tools"]},
                {MODERN_PROFILE_ID, LEGACY_PROFILE_ID},
            )
            self.assertEqual(len(payload["tools"]), 2)
        finally:
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()

    def test_discovery_records_revision_specific_observations_for_streamable_profiles(self):
        class MultiRevisionDiscoveryHandler(_MCPHandler):
            def do_POST(self):  # noqa: N802
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
                                        "name": "multi-revision",
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
                                "serverInfo": {"name": "multi-revision", "version": "1"},
                            },
                        },
                        headers={"MCP-Session-Id": f"session-{requested}"},
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
                                "name": "echo",
                                "description": "Echo text.",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {"text": {"type": "string"}},
                                    "required": ["text"],
                                    "additionalProperties": False,
                                },
                            }
                        ]
                    }
                    if self.headers.get("MCP-Protocol-Version") == MODERN_PROTOCOL_VERSION:
                        result["resultType"] = "complete"
                        result["ttlMs"] = 0
                        result["cacheScope"] = "private"
                    self._write_json({"jsonrpc": "2.0", "id": message.get("id"), "result": result})
                    return
                self._write_json(
                    {"jsonrpc": "2.0", "id": message.get("id"), "error": {"code": -32601}},
                    status=400,
                )

        server = HTTPServer(("127.0.0.1", 0), MultiRevisionDiscoveryHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            endpoint = f"http://127.0.0.1:{server.server_address[1]}/mcp"
            discovery = discover_server(endpoint, LEGACY_PROTOCOL_VERSION)
            payload = discovery["payload"]
            self.assertEqual(payload["server"]["preferred_upstream_profile"], MODERN_PROFILE_ID)
            self.assertEqual(
                set(payload["server"]["supported_protocol_versions"]),
                {"2025-11-25", "2025-06-18", "2025-03-26", MODERN_PROTOCOL_VERSION},
            )
            self.assertEqual(
                {tool["upstream_protocol_profile_id"] for tool in payload["tools"]},
                {
                    MODERN_PROFILE_ID,
                    LEGACY_PROFILE_ID,
                    LEGACY_2025_06_18_PROFILE_ID,
                    LEGACY_2025_03_26_PROFILE_ID,
                },
            )
            self.assertEqual(len(payload["tools"]), 4)
        finally:
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()


if __name__ == "__main__":
    unittest.main()
