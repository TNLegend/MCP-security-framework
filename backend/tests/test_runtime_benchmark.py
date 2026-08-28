import json
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND_DIR = REPO_ROOT / "backend"
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(BACKEND_DIR))

from proxy.protocol_profiles import LEGACY_PROTOCOL_VERSION, MODERN_PROTOCOL_VERSION  # noqa: E402
from scripts.benchmark_runtime import benchmark_gateway  # noqa: E402


class _BenchmarkHandler(BaseHTTPRequestHandler):
    observed_headers = []
    observed_methods = []
    session_id = "benchmark-session"

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        payload = json.loads(raw.decode("utf-8"))
        method = payload.get("method")
        self.__class__.observed_headers.append(dict(self.headers.items()))
        self.__class__.observed_methods.append(method)

        if method == "initialize":
            body = {
                "jsonrpc": "2.0",
                "id": payload["id"],
                "result": {
                    "protocolVersion": payload["params"]["protocolVersion"],
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": "benchmark-test", "version": "1"},
                },
            }
            encoded = json.dumps(body).encode("utf-8")
            self.send_response(200)
            self.send_header("Mcp-Session-Id", self.session_id)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)
            return

        if method == "notifications/initialized":
            self.send_response(202)
            self.end_headers()
            return

        token = self.headers.get("Authorization", "")
        if token == "Bearer allow-token":
            body = {
                "jsonrpc": "2.0",
                "id": payload["id"],
                "result": {"content": [{"type": "text", "text": "ok"}]},
            }
            encoded = json.dumps(body).encode("utf-8")
            self.send_response(200)
        else:
            body = {
                "jsonrpc": "2.0",
                "id": payload["id"],
                "error": {
                    "code": -32003,
                    "message": "tool_call_blocked",
                    "data": {"rule_id": "no_access", "skip_reason": "no_access"},
                },
            }
            encoded = json.dumps(body).encode("utf-8")
            self.send_response(403)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, format, *args):
        return


class RuntimeBenchmarkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _BenchmarkHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = "http://127.0.0.1:" + str(cls.server.server_port)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def setUp(self):
        _BenchmarkHandler.observed_headers = []
        _BenchmarkHandler.observed_methods = []

    def test_concurrent_executed_benchmark_reports_percentiles_without_token(self):
        report = benchmark_gateway(
            gateway_url=self.url,
            server_id=1,
            tool_name="list_files",
            arguments={},
            bearer_token="allow-token",
            protocol_version=MODERN_PROTOCOL_VERSION,
            requests_count=20,
            concurrency=4,
            timeout_seconds=2,
            expected_outcome="EXECUTED",
            warmup=1,
        )
        self.assertTrue(report["security_expectation_met"])
        self.assertEqual(report["warmup_requests"], 1)
        self.assertEqual(report["outcomes"]["executed"], 20)
        self.assertEqual(report["unexpected_outcomes"], 0)
        self.assertGreater(report["throughput_requests_per_second"], 0)
        self.assertGreaterEqual(report["latency_ms"]["p95"], report["latency_ms"]["p50"])
        self.assertGreaterEqual(report["latency_ms"]["p99"], report["latency_ms"]["p95"])
        self.assertNotIn("allow-token", json.dumps(report))
        tool_headers = [
            headers
            for method, headers in zip(
                _BenchmarkHandler.observed_methods,
                _BenchmarkHandler.observed_headers,
            )
            if method == "tools/call"
        ]
        self.assertTrue(tool_headers)
        self.assertEqual(len(tool_headers), 21)
        self.assertTrue(
            all(
                headers.get("Mcp-Protocol-Version") == MODERN_PROTOCOL_VERSION
                and headers.get("Mcp-Method") == "tools/call"
                and headers.get("Mcp-Name") == "list_files"
                for headers in tool_headers
            )
        )

    def test_concurrent_blocked_benchmark_detects_no_fail_open(self):
        report = benchmark_gateway(
            gateway_url=self.url,
            server_id=1,
            tool_name="list_files",
            arguments={},
            bearer_token="deny-token",
            protocol_version=LEGACY_PROTOCOL_VERSION,
            requests_count=25,
            concurrency=5,
            timeout_seconds=2,
            expected_outcome="BLOCKED",
            warmup=0,
        )
        self.assertTrue(report["security_expectation_met"])
        self.assertEqual(report["outcomes"]["blocked"], 25)
        self.assertEqual(report["outcomes"]["executed"], 0)
        self.assertEqual(report["error_codes"], {"no_access": 25})
        self.assertIn("initialize", _BenchmarkHandler.observed_methods)
        self.assertIn("notifications/initialized", _BenchmarkHandler.observed_methods)
        legacy_tool_headers = [
            headers
            for method, headers in zip(
                _BenchmarkHandler.observed_methods,
                _BenchmarkHandler.observed_headers,
            )
            if method == "tools/call"
        ]
        self.assertTrue(legacy_tool_headers)
        self.assertTrue(
            all(
                headers.get("Mcp-Session-Id") == _BenchmarkHandler.session_id
                and headers.get("Mcp-Protocol-Version") == LEGACY_PROTOCOL_VERSION
                for headers in legacy_tool_headers
            )
        )

    def test_wrong_security_expectation_is_reported(self):
        report = benchmark_gateway(
            gateway_url=self.url,
            server_id=1,
            tool_name="list_files",
            arguments={},
            bearer_token="deny-token",
            protocol_version=MODERN_PROTOCOL_VERSION,
            requests_count=5,
            concurrency=2,
            timeout_seconds=2,
            expected_outcome="EXECUTED",
            warmup=0,
        )
        self.assertFalse(report["security_expectation_met"])
        self.assertEqual(report["unexpected_outcomes"], 5)


if __name__ == "__main__":
    unittest.main()
