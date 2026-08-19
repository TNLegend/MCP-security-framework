from __future__ import annotations

import json
import queue
import sys
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend"
for path in (str(ROOT), str(BACKEND)):
    if path not in sys.path:
        sys.path.insert(0, path)

from proxy.http_mcp_client import MCPHttpClient, MCPProtocolError  # noqa: E402
from proxy.mcp_transport import MAX_SSE_EVENT_BYTES  # noqa: E402
from proxy.protocol_profiles import (  # noqa: E402
    LEGACY_2024_11_05_PROFILE_ID,
    LEGACY_2025_03_26_PROFILE_ID,
    LEGACY_2025_06_18_PROFILE_ID,
    LEGACY_PROFILE_ID,
    MODERN_PROFILE_ID,
    MODERN_PROTOCOL_VERSION,
)


class _ThreadedHTTPFixture:
    def __init__(self, handler_class: type[BaseHTTPRequestHandler], path: str = "/mcp") -> None:
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler_class)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.endpoint = f"http://127.0.0.1:{self.server.server_address[1]}{path}"

    def close(self) -> None:
        self.server.shutdown()
        self.thread.join(timeout=5)
        self.server.server_close()


def _handler_version(profile_id: str) -> str:
    if profile_id == LEGACY_2025_03_26_PROFILE_ID:
        return "2025-03-26"
    if profile_id == LEGACY_2025_06_18_PROFILE_ID:
        return "2025-06-18"
    if profile_id == LEGACY_PROFILE_ID:
        return "2025-11-25"
    return MODERN_PROTOCOL_VERSION


def _streamable_handler(
    profile_id: str,
    *,
    response_mode: str = "sse",
    scenario: str = "ok",
) -> type[BaseHTTPRequestHandler]:
    version = _handler_version(profile_id)
    is_modern = profile_id == MODERN_PROFILE_ID

    class Handler(BaseHTTPRequestHandler):
        requests: list[dict] = []
        tool_call_posts = 0
        legacy_initialize_posts = 0

        def log_message(self, format, *args):  # noqa: A003
            return

        def do_POST(self):  # noqa: N802
            length = int(self.headers.get("Content-Length", "0"))
            message = json.loads(self.rfile.read(length).decode("utf-8"))
            type(self).requests.append(message)
            method = message.get("method")
            if method == "initialize":
                type(self).legacy_initialize_posts += 1
                self._json(
                    {
                        "jsonrpc": "2.0",
                        "id": message.get("id"),
                        "result": {
                            "protocolVersion": version,
                            "capabilities": {"tools": {}},
                            "serverInfo": {"name": "streamable-test", "version": "1"},
                        },
                    },
                    headers={"MCP-Session-Id": f"session-{version}"},
                )
                return
            if method == "notifications/initialized":
                self.send_response(202)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if method == "tools/list":
                result: dict = {"tools": []}
                if is_modern:
                    result.update({"resultType": "complete", "ttlMs": 0, "cacheScope": "private"})
                self._json({"jsonrpc": "2.0", "id": message.get("id"), "result": result})
                return
            if method == "tools/call":
                type(self).tool_call_posts += 1
                if response_mode == "json":
                    self._json(self._tool_response(message))
                    return
                self._sse(message)
                return
            self._json({"jsonrpc": "2.0", "id": message.get("id"), "error": {"code": -32601}}, status=400)

        def _tool_response(self, message: dict, *, response_id=None) -> dict:
            result: dict = {
                "isError": False,
                "content": [{"type": "text", "text": f"ok-{version}"}],
            }
            if is_modern:
                result["resultType"] = "complete"
            return {"jsonrpc": "2.0", "id": message.get("id") if response_id is None else response_id, "result": result}

        def _json(self, payload: dict, *, status: int = 200, headers: dict | None = None) -> None:
            body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            self.send_response(status)
            for name, value in (headers or {}).items():
                self.send_header(name, value)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _sse(self, message: dict) -> None:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.end_headers()
            if scenario == "timeout":
                self.wfile.flush()
                time.sleep(1)
                return
            if scenario == "malformed":
                self.wfile.write(b"event: message\ndata: {not-json}\n\n")
                self.wfile.flush()
                return
            if scenario == "oversized":
                self.wfile.write(b"event: message\ndata: " + (b"a" * (MAX_SSE_EVENT_BYTES + 1)) + b"\n\n")
                self.wfile.flush()
                return
            if scenario == "eof":
                self.wfile.write(
                    b'event: message\ndata: {"jsonrpc":"2.0","method":"notifications/progress","params":{}}\n\n'
                )
                self.wfile.flush()
                return
            if scenario == "unsupported_request":
                self._write_sse_json(
                    {
                        "jsonrpc": "2.0",
                        "id": "server-request-1",
                        "method": "sampling/createMessage",
                        "params": {},
                    }
                )
                return
            if scenario in {"notification", "duplicate"}:
                self._write_sse_json(
                    {
                        "jsonrpc": "2.0",
                        "method": "notifications/progress",
                        "params": {"progress": 1},
                    }
                )
            response_id = (message.get("id") or 0) + 1 if scenario == "wrong_id" else message.get("id")
            self._write_sse_json(self._tool_response(message, response_id=response_id))
            if scenario == "duplicate":
                self._write_sse_json(self._tool_response(message, response_id=response_id))

        def _write_sse_json(self, payload: dict) -> None:
            body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            self.wfile.write(b"event: message\ndata: " + body + b"\n\n")
            self.wfile.flush()

    return Handler


class _HistoricalSSEHandler(BaseHTTPRequestHandler):
    requests: list[tuple[str, dict, dict]] = []
    events: queue.Queue[bytes | None] = queue.Queue()
    sse_opened = 0
    sse_responses_delivered = 0
    scenario = "ok"

    @classmethod
    def reset(cls, *, scenario: str = "ok") -> None:
        cls.requests = []
        cls.events = queue.Queue()
        cls.sse_opened = 0
        cls.sse_responses_delivered = 0
        cls.scenario = scenario

    def log_message(self, format, *args):  # noqa: A003
        return

    def do_GET(self):  # noqa: N802
        type(self).sse_opened += 1
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(b"event: endpoint\ndata: /messages\n\n")
        self.wfile.flush()
        if type(self).scenario == "disconnect":
            return
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
        if self.path != "/messages":
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        method = message.get("method")
        if method == "initialize":
            self._enqueue(
                {
                    "jsonrpc": "2.0",
                    "id": message.get("id"),
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "historical", "version": "1"},
                    },
                }
            )
        elif method == "tools/list":
            self._enqueue({"jsonrpc": "2.0", "id": message.get("id"), "result": {"tools": []}})
        elif method == "tools/call":
            self._enqueue(
                {
                    "jsonrpc": "2.0",
                    "id": message.get("id"),
                    "result": {"content": [{"type": "text", "text": "historical-ok"}]},
                }
            )
        self.send_response(202)
        self.send_header("Content-Length", "0")
        self.send_header("X-Post-Body-Contains-Result", "false")
        self.end_headers()

    def _enqueue(self, payload: dict) -> None:
        type(self).sse_responses_delivered += 1
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        type(self).events.put(b"event: message\ndata: " + body + b"\n\n")


class MCPTransportComplianceTests(unittest.TestCase):
    def test_historical_2024_uses_persistent_sse_for_responses(self) -> None:
        _HistoricalSSEHandler.reset()
        fixture = _ThreadedHTTPFixture(_HistoricalSSEHandler, path="/sse")
        client = MCPHttpClient(
            fixture.endpoint,
            protocol_profile_id=LEGACY_2024_11_05_PROFILE_ID,
            timeout_seconds=2,
        )
        try:
            result = client.call_tool("safe_tool", {"x": 1})
        finally:
            client.close()
            _HistoricalSSEHandler.events.put(None)
            fixture.close()

        self.assertEqual(result["content"][0]["text"], "historical-ok")
        self.assertEqual(_HistoricalSSEHandler.sse_opened, 1)
        self.assertEqual(_HistoricalSSEHandler.sse_responses_delivered, 2)
        paths = [path for path, _, _ in _HistoricalSSEHandler.requests]
        self.assertEqual(paths, ["/messages", "/messages", "/messages"])
        self.assertTrue(
            all(
                "mcp-session-id" not in {name.lower() for name in headers}
                for _, headers, _ in _HistoricalSSEHandler.requests
            )
        )

    def test_historical_2024_disconnect_fails_without_replaying_tool_call(self) -> None:
        _HistoricalSSEHandler.reset(scenario="disconnect")
        fixture = _ThreadedHTTPFixture(_HistoricalSSEHandler, path="/sse")
        client = MCPHttpClient(
            fixture.endpoint,
            protocol_profile_id=LEGACY_2024_11_05_PROFILE_ID,
            timeout_seconds=0.5,
        )
        try:
            with self.assertRaises(MCPProtocolError):
                client.call_tool("safe_tool", {"x": 1})
        finally:
            client.close()
            fixture.close()
        methods = [message.get("method") for _, _, message in _HistoricalSSEHandler.requests]
        self.assertNotIn("tools/call", methods)
        self.assertLessEqual(len(methods), 1)

    def test_streamable_http_accepts_json_and_sse_for_supported_revisions(self) -> None:
        cases = (
            (LEGACY_2025_03_26_PROFILE_ID, "2025-03-26"),
            (LEGACY_2025_06_18_PROFILE_ID, "2025-06-18"),
            (LEGACY_PROFILE_ID, "2025-11-25"),
            (MODERN_PROFILE_ID, "2026-07-28"),
        )
        for profile_id, version in cases:
            for response_mode in ("json", "sse"):
                with self.subTest(version=version, response_mode=response_mode):
                    handler = _streamable_handler(profile_id, response_mode=response_mode)
                    fixture = _ThreadedHTTPFixture(handler)
                    try:
                        client = MCPHttpClient(
                            fixture.endpoint,
                            protocol_profile_id=profile_id,
                            timeout_seconds=2,
                        )
                        result = client.call_tool("safe_tool", {"x": 1})
                    finally:
                        fixture.close()
                    self.assertEqual(result["content"][0]["text"], f"ok-{version}")
                    if profile_id == MODERN_PROFILE_ID:
                        self.assertEqual(result["resultType"], "complete")
                    self.assertEqual(handler.tool_call_posts, 1)

    def test_sse_notification_before_response_does_not_complete_request(self) -> None:
        handler = _streamable_handler(MODERN_PROFILE_ID, scenario="notification")
        fixture = _ThreadedHTTPFixture(handler)
        try:
            client = MCPHttpClient(
                fixture.endpoint,
                protocol_profile_id=MODERN_PROFILE_ID,
                timeout_seconds=2,
            )
            result = client.call_tool("safe_tool", {"x": 1})
        finally:
            fixture.close()
        self.assertEqual(result["content"][0]["text"], "ok-2026-07-28")
        self.assertEqual(handler.tool_call_posts, 1)

    def test_streamable_sse_failures_fail_closed_without_retry(self) -> None:
        scenarios = (
            "wrong_id",
            "malformed",
            "oversized",
            "eof",
            "timeout",
            "unsupported_request",
        )
        for scenario in scenarios:
            with self.subTest(scenario=scenario):
                handler = _streamable_handler(MODERN_PROFILE_ID, scenario=scenario)
                fixture = _ThreadedHTTPFixture(handler)
                try:
                    client = MCPHttpClient(
                        fixture.endpoint,
                        protocol_profile_id=MODERN_PROFILE_ID,
                        timeout_seconds=0.25 if scenario == "timeout" else 2,
                    )
                    with self.assertRaises(MCPProtocolError):
                        client.call_tool("safe_tool", {"x": 1})
                finally:
                    fixture.close()
                self.assertEqual(handler.tool_call_posts, 1)

    def test_duplicate_sse_response_fails_closed_without_replaying_tool_call(self) -> None:
        handler = _streamable_handler(MODERN_PROFILE_ID, scenario="duplicate")
        fixture = _ThreadedHTTPFixture(handler)
        try:
            client = MCPHttpClient(
                fixture.endpoint,
                protocol_profile_id=MODERN_PROFILE_ID,
                timeout_seconds=2,
            )
            with self.assertRaises(MCPProtocolError):
                client.call_tool("safe_tool", {"x": 1})
        finally:
            fixture.close()
        self.assertEqual(handler.tool_call_posts, 1)


if __name__ == "__main__":
    unittest.main()
