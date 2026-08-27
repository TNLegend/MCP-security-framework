import json
import sys
import tempfile
import threading
import unittest
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit


ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend"
for path in (str(ROOT), str(BACKEND)):
    if path not in sys.path:
        sys.path.insert(0, path)

from common.upstream_auth import (  # noqa: E402
    AUTH_MODE_OAUTH,
    write_upstream_token_bundle,
)
from common.upstream_oauth import (  # noqa: E402
    UpstreamOAuthError,
    consume_oauth_attempt,
    create_oauth_attempt,
    discover_oauth_configuration,
    exchange_authorization_code,
    register_dynamic_oauth_client,
    resolve_oauth_access_token,
)
from app.schemas.server import MCPServerInternalRead, MCPServerRead  # noqa: E402


class _OAuthProviderHandler(BaseHTTPRequestHandler):
    requests: list[dict] = []
    port = 0

    def do_GET(self):  # noqa: N802
        base = f"http://127.0.0.1:{type(self).port}"
        if self.path == "/mcp":
            self.send_response(401)
            self.send_header(
                "WWW-Authenticate",
                f'Bearer resource_metadata="{base}/metadata" scope="files:read"',
            )
            self.end_headers()
            return
        if self.path == "/metadata":
            self._write_json(
                {
                    "resource": f"{base}/mcp",
                    "authorization_servers": [f"{base}/oauth"],
                    "scopes_supported": ["files:read", "files:write"],
                }
            )
            return
        if self.path == "/mcp/.well-known/oauth-protected-resource":
            self._write_json(
                {
                    "resource": f"{base}/mcp",
                    "authorization_servers": [f"{base}/oauth"],
                    "scopes_supported": ["files:read", "files:write"],
                }
            )
            return
        if self.path == "/.well-known/oauth-authorization-server/oauth":
            self._write_json(
                {
                    "issuer": f"{base}/oauth",
                    "authorization_endpoint": f"{base}/oauth/authorize",
                    "token_endpoint": f"{base}/oauth/token",
                    "registration_endpoint": f"{base}/oauth/register",
                    "code_challenge_methods_supported": ["S256"],
                }
            )
            return
        self.send_response(404)
        self.end_headers()

    def do_POST(self):  # noqa: N802
        if self.path == "/oauth/register":
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            type(self).requests.append(payload)
            if payload.get("token_endpoint_auth_method") != "none":
                self.send_response(400)
                self.end_headers()
                return
            self._write_json({"client_id": "dynamic-client", "client_secret": "dynamic-secret"})
            return
        if self.path != "/oauth/token":
            self.send_response(404)
            self.end_headers()
            return
        length = int(self.headers.get("Content-Length", "0"))
        payload = parse_qs(self.rfile.read(length).decode("ascii"), keep_blank_values=True)
        type(self).requests.append(payload)
        if payload.get("grant_type") == ["authorization_code"]:
            if not payload.get("code_verifier") or not payload.get("resource"):
                self.send_response(400)
                self.end_headers()
                return
            self._write_json(
                {
                    "access_token": "access-token-initial",
                    "refresh_token": "refresh-token-rotated",
                    "expires_in": 3600,
                }
            )
            return
        if payload.get("grant_type") == ["refresh_token"]:
            self._write_json(
                {
                    "access_token": "access-token-refreshed",
                    "refresh_token": "refresh-token-next",
                    "expires_in": 3600,
                }
            )
            return
        self.send_response(400)
        self.end_headers()

    def _write_json(self, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):  # noqa: A003
        return


class UpstreamOAuthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = HTTPServer(("127.0.0.1", 0), _OAuthProviderHandler)
        _OAuthProviderHandler.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.endpoint = f"http://127.0.0.1:{cls.server.server_address[1]}/mcp"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.thread.join(timeout=5)
        cls.server.server_close()

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.secret_root = Path(self.temp_dir.name)
        self.secret_patch = patch("common.upstream_auth.UPSTREAM_SECRET_DIR", self.secret_root)
        self.secret_patch.start()
        _OAuthProviderHandler.requests = []

    def tearDown(self) -> None:
        self.secret_patch.stop()
        self.temp_dir.cleanup()

    def test_authorization_code_pkce_and_refresh_are_resource_bound(self) -> None:
        configuration = discover_oauth_configuration(
            mcp_endpoint=self.endpoint,
            client_id="framework-client",
            requested_scopes=[],
        )
        self.assertEqual(configuration["resource"], self.endpoint)
        self.assertEqual(configuration["scopes"], ["files:read"])

        state, authorization_url, _expires_at = create_oauth_attempt(
            attempt_directory=self.secret_root / "attempts",
            server_id=7,
            actor_user_id="admin-id",
            redirect_uri="http://127.0.0.1:8000/api/v1/control-plane/upstream-oauth/callback",
            authorization_endpoint=configuration["authorization_endpoint"],
            token_endpoint=configuration["token_endpoint"],
            client_id=configuration["client_id"],
            client_secret_ref=None,
            resource=configuration["resource"],
            scopes=configuration["scopes"],
        )
        query = parse_qs(urlsplit(authorization_url).query)
        self.assertEqual(query["state"], [state])
        self.assertEqual(query["resource"], [self.endpoint])
        self.assertEqual(query["code_challenge_method"], ["S256"])
        self.assertNotIn("code_verifier", query)

        attempt = consume_oauth_attempt(attempt_directory=self.secret_root / "attempts", state=state)
        exchange_authorization_code(
            code="authorization-code",
            attempt=attempt,
            credential_ref="oauth/tokens/test.json",
        )
        self.assertEqual(
            resolve_oauth_access_token(
                credential_ref="oauth/tokens/test.json",
                oauth_config=configuration,
            ),
            "access-token-initial",
        )

        write_upstream_token_bundle(
            "oauth/tokens/test.json",
            {
                "access_token": "expired-token",
                "refresh_token": "refresh-token-rotated",
                "expires_at": (datetime.now(UTC) - timedelta(minutes=1)).replace(tzinfo=None).isoformat(),
                "resource": self.endpoint,
                "scopes": ["files:read"],
            },
        )
        self.assertEqual(
            resolve_oauth_access_token(
                credential_ref="oauth/tokens/test.json",
                oauth_config=configuration,
            ),
            "access-token-refreshed",
        )
        self.assertEqual(_OAuthProviderHandler.requests[0]["resource"], [self.endpoint])
        self.assertIn("code_verifier", _OAuthProviderHandler.requests[0])
        self.assertEqual(_OAuthProviderHandler.requests[1]["resource"], [self.endpoint])
        self.assertNotIn("authorization-code", authorization_url)

    def test_dynamic_client_registration_uses_discovered_endpoint(self) -> None:
        configuration = discover_oauth_configuration(
            mcp_endpoint=self.endpoint,
            client_id=None,
            requested_scopes=[],
        )
        registered = register_dynamic_oauth_client(
            registration_endpoint=configuration["registration_endpoint"],
            redirect_uri="http://127.0.0.1:8000/api/v1/control-plane/upstream-oauth/callback",
            scopes=configuration["scopes"],
        )

        self.assertEqual(registered["client_id"], "dynamic-client")
        self.assertEqual(registered["client_secret"], "dynamic-secret")
        registration = _OAuthProviderHandler.requests[0]
        self.assertEqual(registration["grant_types"], ["authorization_code", "refresh_token"])
        self.assertEqual(registration["response_types"], ["code"])
        self.assertEqual(registration["scope"], "files:read")

    def test_discovery_supports_endpoint_relative_protected_resource_metadata(self) -> None:
        with patch("common.upstream_oauth._discover_challenge", return_value=(None, [])):
            configuration = discover_oauth_configuration(
                mcp_endpoint=self.endpoint,
                client_id="framework-client",
                requested_scopes=[],
            )

        self.assertEqual(configuration["resource"], self.endpoint)

    def test_oauth_mode_requires_framework_owned_configuration(self) -> None:
        with self.assertRaises(UpstreamOAuthError):
            resolve_oauth_access_token(
                credential_ref="oauth/tokens/missing.json",
                oauth_config=None,
            )

        self.assertEqual(AUTH_MODE_OAUTH, "OAUTH")

    def test_public_server_schema_excludes_oauth_configuration_and_references(self) -> None:
        payload = {
            "id": 9,
            "name": "protected-mcp",
            "server_type": "mcp",
            "endpoint": self.endpoint,
            "auth_mode": AUTH_MODE_OAUTH,
            "credential_ref": "oauth/tokens/test.json",
            "oauth_config": {"client_id": "framework-client"},
            "oauth_status": "CONNECTED",
            "created_at": datetime.now(UTC).replace(tzinfo=None),
        }
        public = MCPServerRead.model_validate(payload).model_dump(mode="json")
        internal = MCPServerInternalRead.model_validate(payload).model_dump(mode="json")

        self.assertNotIn("credential_ref", public)
        self.assertNotIn("oauth_config", public)
        self.assertEqual(internal["credential_ref"], "oauth/tokens/test.json")
        self.assertEqual(internal["oauth_config"]["client_id"], "framework-client")


if __name__ == "__main__":
    unittest.main()
