import threading
import unittest
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend"
for path in (str(ROOT), str(BACKEND)):
    if path not in sys.path:
        sys.path.insert(0, path)

from common.mcp_endpoint import (
    MCPEndpointValidationError,
    is_exact_local_lab_endpoint,
    validate_mcp_endpoint,
)
from app.api.routes_inventory import is_local_lab_endpoint, upsert_server
from app.schemas.inventory import DiscoveryImportPayload
from app.services.mcp_discovery import discover_http_mcp_server
from proxy.http_mcp_client import MCPHttpClient, MCPHttpError
from proxy.protocol_profiles import MODERN_PROFILE_ID, MODERN_PROTOCOL_VERSION


PUBLIC_DNS_ANSWER = [
    (2, 1, 6, "", ("203.0.113.10", 443)),
]


class MCPEndpointPolicyTests(unittest.TestCase):
    def test_localhost_remote_http_and_remote_https_are_allowed(self) -> None:
        self.assertEqual(
            validate_mcp_endpoint("http://127.0.0.1:9000/mcp").hostname,
            "127.0.0.1",
        )
        for endpoint in (
            "http://mcp.vendor.example/mcp",
            "https://mcp.vendor.example/mcp?tenant=example",
        ):
            with self.subTest(endpoint=endpoint):
                parsed = validate_mcp_endpoint(
                    endpoint,
                    resolver=lambda *args, **kwargs: PUBLIC_DNS_ANSWER,
                )
                self.assertEqual(parsed.hostname, "mcp.vendor.example")

    def test_malformed_userinfo_fragment_and_unsupported_schemes_are_rejected(self) -> None:
        for endpoint in (
            "file:///tmp/mcp",
            "ftp://example.com/mcp",
            "https://user:password@example.com/mcp",
            "https://example.com/mcp#fragment",
            "https://example.com/mcp?access_token=secret",
            "https://[invalid/mcp",
        ):
            with self.subTest(endpoint=endpoint):
                with self.assertRaises(MCPEndpointValidationError):
                    validate_mcp_endpoint(endpoint, resolve_dns=False)

    def test_metadata_link_local_and_dns_resolved_special_targets_are_rejected(self) -> None:
        for endpoint in (
            "http://169.254.169.254/latest/meta-data",
            "http://169.254.10.20/mcp",
            "http://[fe80::1]/mcp",
            "http://[fd00:ec2::254]/mcp",
            "http://metadata.google.internal/mcp",
        ):
            with self.subTest(endpoint=endpoint):
                with self.assertRaises(MCPEndpointValidationError):
                    validate_mcp_endpoint(endpoint, resolve_dns=False)

        with self.assertRaisesRegex(
            MCPEndpointValidationError,
            "endpoint_special_address_blocked",
        ):
            validate_mcp_endpoint(
                "https://rebinding.example/mcp",
                resolver=lambda *args, **kwargs: [
                    (2, 1, 6, "", ("169.254.169.254", 443))
                ],
            )

    def test_local_lab_trust_uses_exact_parsed_hostname(self) -> None:
        self.assertTrue(is_local_lab_endpoint("http://127.0.0.1:9000/mcp"))
        for endpoint in (
            "http://localhost:9000/mcp",
            "http://[::1]:9000/mcp",
            "http://localhost.attacker.example/mcp",
            "http://127.0.0.1.attacker.example/mcp",
            "http://attacker-localhost.example/mcp",
            "https://localhost/mcp",
            "http://127.0.0.1:9001/mcp",
            "http://127.0.0.1:9000/other",
            "http://127.0.0.1:9000/mcp?tenant=lab",
        ):
            with self.subTest(endpoint=endpoint):
                self.assertFalse(is_exact_local_lab_endpoint(endpoint))
                self.assertFalse(is_local_lab_endpoint(endpoint))

    def test_arbitrary_loopback_server_is_not_lab_trusted(self) -> None:
        payload = DiscoveryImportPayload.model_validate(
            {
                "server": {
                    "endpoint": "http://127.0.0.1:9100/mcp",
                    "server_info_name": "other-loopback",
                },
                "tools": [],
            }
        )
        db = MagicMock()
        db.scalar.return_value = None

        server = upsert_server(payload, db, datetime.utcnow())

        self.assertEqual(server.trust_status, "unknown")

    def test_remote_discovery_pipeline_accepts_http_and_https(self) -> None:
        negotiation = SimpleNamespace(
            supported_protocol_profiles=(MODERN_PROFILE_ID,),
            preferred_upstream_profile=MODERN_PROFILE_ID,
            protocol_version=MODERN_PROTOCOL_VERSION,
            probe_status="modern_supported",
            detected_era="modern",
            supported_protocol_versions=(MODERN_PROTOCOL_VERSION,),
            preferred_protocol_version=MODERN_PROTOCOL_VERSION,
            negotiated_protocol_version=MODERN_PROTOCOL_VERSION,
            transport_kind="modern_streamable_http",
            protocol_verdict_expires_at=None,
        )
        metadata = {
            "resultType": "complete",
            "ttlMs": 0,
            "cacheScope": "public",
            "supportedVersions": [MODERN_PROTOCOL_VERSION],
            "capabilities": {"tools": {}},
            "_meta": {
                "io.modelcontextprotocol/server-info": {
                    "name": "remote-test",
                    "version": "1",
                }
            },
        }
        with (
            patch(
                "common.mcp_endpoint.socket.getaddrinfo",
                return_value=PUBLIC_DNS_ANSWER,
            ),
            patch(
                "app.services.mcp_discovery.ProtocolNegotiator.negotiate",
                return_value=negotiation,
            ),
            patch(
                "app.services.mcp_discovery.discover_modern_server",
                return_value=(metadata, []),
            ),
        ):
            for endpoint in (
                "http://mcp.vendor.example/mcp",
                "https://mcp.vendor.example/mcp",
            ):
                with self.subTest(endpoint=endpoint):
                    result = discover_http_mcp_server(mcp_endpoint=endpoint)
                    self.assertEqual(result["payload"]["server"]["endpoint"], endpoint)

    def test_remote_success_is_not_automatically_lab_trusted(self) -> None:
        payload = DiscoveryImportPayload.model_validate(
            {
                "server": {
                    "endpoint": "https://mcp.vendor.example/mcp",
                    "server_info_name": "remote-test",
                },
                "tools": [],
            }
        )
        db = MagicMock()
        db.scalar.return_value = None

        server = upsert_server(payload, db, datetime.utcnow())

        self.assertEqual(server.trust_status, "unknown")

    def test_remote_rediscovery_preserves_explicit_admin_trust(self) -> None:
        payload = DiscoveryImportPayload.model_validate(
            {
                "server": {
                    "endpoint": "https://mcp.vendor.example/mcp",
                    "server_info_name": "remote-test",
                },
                "tools": [],
            }
        )
        existing = MagicMock()
        existing.name = "remote-test"
        existing.trust_status = "trusted"
        existing.status = "active"
        db = MagicMock()
        db.scalar.return_value = existing

        server = upsert_server(payload, db, datetime.utcnow())

        self.assertIs(server, existing)
        self.assertEqual(server.trust_status, "trusted")

    def test_remote_reactivation_does_not_restore_archived_trust(self) -> None:
        payload = DiscoveryImportPayload.model_validate(
            {
                "server": {
                    "endpoint": "https://mcp.vendor.example/mcp",
                    "server_info_name": "remote-test",
                },
                "tools": [],
            }
        )
        existing = MagicMock()
        existing.name = "remote-test"
        existing.trust_status = "archived"
        existing.status = "archived"
        db = MagicMock()
        db.scalar.return_value = existing

        server = upsert_server(payload, db, datetime.utcnow())

        self.assertIs(server, existing)
        self.assertEqual(server.trust_status, "unknown")

    def test_runtime_http_client_does_not_follow_redirects(self) -> None:
        class RedirectHandler(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                self.send_response(302)
                self.send_header("Location", "http://169.254.169.254/latest/meta-data")
                self.end_headers()

            def log_message(self, format, *args):  # noqa: A003
                return

        server = HTTPServer(("127.0.0.1", 0), RedirectHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            endpoint = f"http://127.0.0.1:{server.server_address[1]}/mcp"
            client = MCPHttpClient(endpoint, protocol_profile_id=MODERN_PROFILE_ID)
            with self.assertRaisesRegex(MCPHttpError, "MCP HTTP error 302"):
                client.list_tools()
        finally:
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()


if __name__ == "__main__":
    unittest.main()
