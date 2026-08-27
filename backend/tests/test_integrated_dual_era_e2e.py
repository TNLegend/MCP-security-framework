from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import queue
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import sys
import threading
import unittest
from types import SimpleNamespace

from fastapi.testclient import TestClient


ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend"
TESTS = BACKEND / "tests"
for path in (str(ROOT), str(BACKEND), str(TESTS)):
    if path not in sys.path:
        sys.path.insert(0, path)

from app.services.published_configuration import PublishedConfigurationError  # noqa: E402
from proxy.agent_identity import VerifiedExternalIdentity  # noqa: E402
from proxy.gateway import MCPGateway  # noqa: E402
from proxy.identity_binding import ResolvedIdentityBinding  # noqa: E402
from proxy.mcp_proxy import MCPProxy  # noqa: E402
from proxy.protocol_profiles import (  # noqa: E402
    LEGACY_2024_11_05_PROFILE_ID,
    LEGACY_PROFILE_ID,
    LEGACY_PROTOCOL_VERSION,
    MODERN_META_CLIENT_CAPABILITIES,
    MODERN_META_CLIENT_INFO,
    MODERN_META_PROTOCOL_VERSION,
    MODERN_META_SERVER_INFO,
    MODERN_PROFILE_ID,
    MODERN_PROTOCOL_VERSION,
)
from proxy.tool_security_v2 import (  # noqa: E402
    AuthorityResourceScope,
    ResourceBinding,
    ScopeMatchMode,
    ToolEffect,
    ToolObservationApproval,
    ToolSecurityContract,
    validate_contract_for_schema,
)
from proxy.trusted_sessions import ProxyTrustedSession  # noqa: E402
from runtime_policy_eval import evaluate_runtime_policy_with_opa_cli  # noqa: E402


SERVER_REF = "mail-a"
FINGERPRINT = "b" * 64
CONTENT_HASH = "c" * 64
EVIDENCE_HASH = "d" * 64
SEND_EMAIL_SCHEMA = {
    "type": "object",
    "properties": {
        "recipient": {"type": "string", "maxLength": 254},
        "subject": {"type": "string", "maxLength": 200},
        "body": {"type": "string", "maxLength": 10000},
    },
    "required": ["recipient", "subject", "body"],
    "additionalProperties": False,
}
SEND_EMAIL_TOOL = {
    "name": "send_email",
    "description": "Send an email to one explicit recipient.",
    "inputSchema": SEND_EMAIL_SCHEMA,
}
CONTRACT = ToolSecurityContract(
    server_ref=SERVER_REF,
    tool_name="send_email",
    effects=(
        ToolEffect(
            effect_id="mail.send",
            capability="message.send",
            resource_bindings=(
                ResourceBinding(path=("recipient",), resource_type="email_address"),
            ),
            max_resource_cardinality=1,
        ),
    ),
    unbound_arguments=(("subject",), ("body",)),
)
RESOLUTIONS = validate_contract_for_schema(CONTRACT, SEND_EMAIL_SCHEMA)
SCOPES = (
    AuthorityResourceScope(
        scope_id="mail.alice",
        authority=SERVER_REF,
        resource_type="email_address",
        canonical_value="alice@example.com",
        match_mode=ScopeMatchMode.SELF,
    ),
)


class _ThreadedHTTPFixture:
    def __init__(self, handler_class: type[BaseHTTPRequestHandler]) -> None:
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler_class)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.endpoint = f"http://127.0.0.1:{self.server.server_address[1]}/mcp"

    def close(self) -> None:
        self.server.shutdown()
        self.thread.join(timeout=5)
        self.server.server_close()


class _BaseMCPHandler(BaseHTTPRequestHandler):
    invocation_count = 0
    modern_call_count = 0
    legacy_call_count = 0
    legacy_initialize_count = 0
    fail_modern_call = False

    @classmethod
    def reset(cls) -> None:
        cls.invocation_count = 0
        cls.modern_call_count = 0
        cls.legacy_call_count = 0
        cls.legacy_initialize_count = 0
        cls.fail_modern_call = False

    def log_message(self, format, *args):  # noqa: A003
        return

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        return json.loads(self.rfile.read(length).decode("utf-8"))

    def _json(self, payload: dict, *, status: int = 200, headers: dict | None = None) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _modern_result(self, request: dict, result: dict) -> None:
        self._json(
            {
                "jsonrpc": "2.0",
                "id": request.get("id"),
                "result": {"resultType": "complete", **result},
            }
        )

    def _legacy_result(self, request: dict, result: dict) -> None:
        self._json({"jsonrpc": "2.0", "id": request.get("id"), "result": result})

    def _validate_modern_request(self, request: dict, method: str) -> None:
        if self.headers.get("MCP-Protocol-Version") != MODERN_PROTOCOL_VERSION:
            raise AssertionError("missing modern protocol header")
        if self.headers.get("Mcp-Method") != method:
            raise AssertionError("missing modern method header")
        params = request.get("params")
        if not isinstance(params, dict):
            raise AssertionError("missing params")
        meta = params.get("_meta")
        if not isinstance(meta, dict):
            raise AssertionError("missing modern meta")
        if meta.get(MODERN_META_PROTOCOL_VERSION) != MODERN_PROTOCOL_VERSION:
            raise AssertionError("modern protocol meta mismatch")
        if meta.get(MODERN_META_CLIENT_CAPABILITIES) != {}:
            raise AssertionError("modern capabilities missing")
        if not isinstance(meta.get(MODERN_META_CLIENT_INFO), dict):
            raise AssertionError("modern client info missing")


class ModernEmailHandler(_BaseMCPHandler):
    def do_POST(self):  # noqa: N802
        request = self._read_json()
        method = request.get("method")
        try:
            self._validate_modern_request(request, str(method))
            if method == "server/discover":
                self._modern_result(
                    request,
                    {
                        "ttlMs": 0,
                        "cacheScope": "public",
                        "supportedVersions": [MODERN_PROTOCOL_VERSION],
                        "capabilities": {"tools": {}},
                        "_meta": {
                            MODERN_META_SERVER_INFO: {
                                "name": "modern-mail",
                                "version": "1",
                            }
                        },
                    },
                )
                return
            if method == "tools/list":
                self._modern_result(
                    request,
                    {"ttlMs": 0, "cacheScope": "private", "tools": [SEND_EMAIL_TOOL]},
                )
                return
            if method == "tools/call":
                type(self).modern_call_count += 1
                if self.headers.get("Mcp-Name") != "send_email":
                    raise AssertionError("missing modern name header")
                if type(self).fail_modern_call:
                    self._json(
                        {
                            "jsonrpc": "2.0",
                            "id": request.get("id"),
                            "result": {
                                "resultType": "input_required",
                                "inputRequests": {},
                            },
                        }
                    )
                    return
                type(self).invocation_count += 1
                self._modern_result(
                    request,
                    {"isError": False, "content": [{"type": "text", "text": "sent"}]},
                )
                return
        except AssertionError as exc:
            self._json(
                {"jsonrpc": "2.0", "id": request.get("id"), "error": {"code": -32020, "message": str(exc)}},
                status=400,
            )
            return
        self._json({"jsonrpc": "2.0", "id": request.get("id"), "error": {"code": -32601}}, status=400)


class ModernSSEEmailHandler(ModernEmailHandler):
    def do_POST(self):  # noqa: N802
        request = self._read_json()
        method = request.get("method")
        try:
            self._validate_modern_request(request, str(method))
            if method == "tools/call":
                type(self).modern_call_count += 1
                type(self).invocation_count += 1
                response = {
                    "jsonrpc": "2.0",
                    "id": request.get("id"),
                    "result": {
                        "resultType": "complete",
                        "isError": False,
                        "content": [{"type": "text", "text": "sent"}],
                    },
                }
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.end_headers()
                notification = {
                    "jsonrpc": "2.0",
                    "method": "notifications/progress",
                    "params": {"progress": 1},
                }
                self._sse_json(notification)
                self._sse_json(response)
                return
        except AssertionError as exc:
            self._json(
                {"jsonrpc": "2.0", "id": request.get("id"), "error": {"code": -32020, "message": str(exc)}},
                status=400,
            )
            return
        super().do_POST()

    def _sse_json(self, payload: dict) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.wfile.write(b"event: message\ndata: " + body + b"\n\n")
        self.wfile.flush()


class LegacyEmailHandler(_BaseMCPHandler):
    def do_POST(self):  # noqa: N802
        request = self._read_json()
        method = request.get("method")
        if method == "initialize":
            type(self).legacy_initialize_count += 1
            self._json(
                {
                    "jsonrpc": "2.0",
                    "id": request.get("id"),
                    "result": {
                        "protocolVersion": LEGACY_PROTOCOL_VERSION,
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "legacy-mail", "version": "1"},
                    },
                },
                headers={"MCP-Session-Id": "legacy-upstream-session"},
            )
            return
        if method == "notifications/initialized":
            self.send_response(202)
            self.end_headers()
            return
        if method == "tools/list":
            self._legacy_result(request, {"tools": [SEND_EMAIL_TOOL]})
            return
        if method == "tools/call":
            type(self).legacy_call_count += 1
            type(self).invocation_count += 1
            self._legacy_result(
                request,
                {"isError": False, "content": [{"type": "text", "text": "sent"}]},
            )
            return
        self._json({"jsonrpc": "2.0", "id": request.get("id"), "error": {"code": -32601}}, status=400)


class Legacy2024SSEEmailHandler(_BaseMCPHandler):
    events: queue.Queue[bytes | None] = queue.Queue()

    @classmethod
    def reset(cls) -> None:
        super().reset()
        cls.events = queue.Queue()

    def do_GET(self):  # noqa: N802
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
        request = self._read_json()
        method = request.get("method")
        if self.path != "/messages":
            self._json({"jsonrpc": "2.0", "id": request.get("id"), "error": {"code": -32601}}, status=404)
            return
        if method == "initialize":
            type(self).legacy_initialize_count += 1
            self._enqueue(
                {
                    "jsonrpc": "2.0",
                    "id": request.get("id"),
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "legacy-2024-mail", "version": "1"},
                    },
                }
            )
        elif method == "tools/list":
            self._enqueue({"jsonrpc": "2.0", "id": request.get("id"), "result": {"tools": [SEND_EMAIL_TOOL]}})
        elif method == "tools/call":
            type(self).legacy_call_count += 1
            type(self).invocation_count += 1
            self._enqueue(
                {
                    "jsonrpc": "2.0",
                    "id": request.get("id"),
                    "result": {"isError": False, "content": [{"type": "text", "text": "sent"}]},
                }
            )
        self.send_response(202)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _enqueue(self, payload: dict) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        type(self).events.put(b"event: message\ndata: " + body + b"\n\n")


class DualEraFallbackTrapHandler(ModernEmailHandler, LegacyEmailHandler):
    def do_POST(self):  # noqa: N802
        request = self._read_json()
        method = request.get("method")
        if method == "initialize":
            type(self).legacy_initialize_count += 1
            self._json(
                {
                    "jsonrpc": "2.0",
                    "id": request.get("id"),
                    "result": {
                        "protocolVersion": LEGACY_PROTOCOL_VERSION,
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "dual-trap", "version": "1"},
                    },
                },
                headers={"MCP-Session-Id": "trap-legacy-session"},
            )
            return
        if method == "notifications/initialized":
            self.send_response(202)
            self.end_headers()
            return
        if self.headers.get("MCP-Protocol-Version") == MODERN_PROTOCOL_VERSION:
            try:
                self._validate_modern_request(request, str(method))
            except AssertionError as exc:
                self._json(
                    {"jsonrpc": "2.0", "id": request.get("id"), "error": {"code": -32020, "message": str(exc)}},
                    status=400,
                )
                return
            if method == "tools/call":
                type(self).modern_call_count += 1
                self._json(
                    {
                        "jsonrpc": "2.0",
                        "id": request.get("id"),
                        "result": {"resultType": "input_required", "inputRequests": {}},
                    }
                )
                return
            self._modern_result(
                request,
                {"ttlMs": 0, "cacheScope": "private", "tools": [SEND_EMAIL_TOOL]},
            )
            return
        if method == "tools/call":
            type(self).legacy_call_count += 1
            type(self).invocation_count += 1
            self._legacy_result(
                request,
                {"isError": False, "content": [{"type": "text", "text": "legacy fallback executed"}]},
            )
            return
        self._json({"jsonrpc": "2.0", "id": request.get("id"), "error": {"code": -32601}}, status=400)


class V2Snapshot:
    schema_version = 2
    revision_id = "revision-2"
    revision_number = 2
    content_hash = CONTENT_HASH

    def __init__(self) -> None:
        self.approved_profiles = {MODERN_PROFILE_ID, LEGACY_PROFILE_ID}
        self.content = SimpleNamespace(
            capability_catalog_version="2",
            resource_type_registry_version="2",
            security_packs=(),
        )

    def resolve(self, *, issuer: str, subject: str):
        return ResolvedIdentityBinding(agent_id=subject, revision=self.content_hash)

    def get_tool_security_contract(self, *, server_ref: str, tool_name: str):
        if (server_ref, tool_name) != (SERVER_REF, "send_email"):
            raise PublishedConfigurationError("contract_missing")
        return CONTRACT

    def get_tool_observation_approval(
        self,
        *,
        server_ref: str,
        upstream_protocol_profile_id: str,
        tool_fingerprint: str,
    ):
        if (
            server_ref != SERVER_REF
            or upstream_protocol_profile_id not in self.approved_profiles
            or tool_fingerprint != FINGERPRINT
        ):
            raise PublishedConfigurationError("profile_observation_not_approved")
        return ToolObservationApproval(
            tool_observation_id=1 if upstream_protocol_profile_id == MODERN_PROFILE_ID else 2,
            server_ref=SERVER_REF,
            upstream_protocol_profile_id=upstream_protocol_profile_id,
            tool_fingerprint=FINGERPRINT,
            contract_hash=CONTRACT.contract_hash,
            evidence_bundle_hash=EVIDENCE_HASH,
            admin_id="admin",
            approved_at="2026-01-01T00:00:00Z",
            revision_id=self.revision_id,
        )

    def get_adapter_resolutions(self, *, effect_id: str):
        return tuple(value for value in RESOLUTIONS if value.effect_id == effect_id)

    def get_authority_resource_scopes(self):
        return SCOPES

    def get_authority_context(self, authority: str):
        if authority != SERVER_REF:
            raise PublishedConfigurationError("authority_context_missing")
        return {"separator": "/", "case_sensitive": True, "max_depth": 32}


class SnapshotResolver:
    def __init__(self, snapshot: V2Snapshot) -> None:
        self.snapshot = snapshot

    def load_active_snapshot(self):
        return self.snapshot


class IdentityVerifier:
    def verify(self, _access_token: str):
        now = datetime.now(timezone.utc)
        return VerifiedExternalIdentity(
            issuer="https://issuer.example/",
            subject="agent-demo",
            audience=("mcp-security-proxy",),
            client_id=None,
            token_id="jti",
            issued_at=now,
            expires_at=now + timedelta(minutes=5),
        )


class SessionManager:
    def create_for_identity(self, *, external_identity, identity_binding):
        return self._session()

    def validate_token(self, _session_token: str):
        return self._session()

    @staticmethod
    def _session():
        return ProxyTrustedSession(
            session_reference="framework-session",
            session_token="session-token",
            agent_id="agent-demo",
            identity_issuer="https://issuer.example/",
            identity_subject="agent-demo",
            identity_binding_revision=CONTENT_HASH,
            session_status="active",
        )


class AssertionSigner:
    def sign(self, _context: dict) -> str:
        return "trusted.assertion"


class IntegratedBackend:
    def __init__(self, *, modern_endpoint: str, legacy_endpoint: str) -> None:
        self.modern_endpoint = modern_endpoint
        self.legacy_endpoint = legacy_endpoint
        self.preferred_upstream_profile = MODERN_PROFILE_ID
        self.logs: list[dict] = []

    def find_server(self, server_id=None, endpoint=None):
        profile = self.preferred_upstream_profile
        return {
            "id": 1,
            "server_ref": SERVER_REF,
            "endpoint": self.modern_endpoint if profile == MODERN_PROFILE_ID else self.legacy_endpoint,
            "transport": "streamable_http",
            "protocol_version": MODERN_PROTOCOL_VERSION if profile == MODERN_PROFILE_ID else LEGACY_PROTOCOL_VERSION,
            "preferred_upstream_profile": profile,
            "trust_status": "trusted",
            "security_status": "approved",
        }

    def list_tools(self):
        return [self.find_tool(1, "send_email")]

    def find_tool(self, _server_id: int, tool_name: str, upstream_protocol_profile_id: str | None = None):
        if tool_name != "send_email":
            return None
        return {
            "id": 1,
            "server_id": 1,
            "name": "send_email",
            "description": SEND_EMAIL_TOOL["description"],
            "input_schema": SEND_EMAIL_SCHEMA,
            "output_schema": None,
            "annotations": {},
            "analysis_status": "APPROVED",
            "current_fingerprint": FINGERPRINT,
            "approved_fingerprint_match": True,
            "risk_score": 1,
            "risk_level": "low",
            "sensitivity": "low",
            "description_risk_score": 1,
            "semantic_flagged": False,
            "deterministic_critical_finding": False,
            "consistency_status": "consistent",
            "drift_status": "NONE",
            "review_status": "APPROVED",
            "analyzer_revision": "v1",
        }

    def check_emergency_deny(self, _context):
        return {"blocked": False, "deny_id": None}

    def request_policy_decision(self, context, *, identity_assertion=None):
        trusted = dict(context)
        trusted["subject"] = {
            **context["subject"],
            "authorization_status": "resolved",
            "authorization_revision": CONTENT_HASH,
            "role": "operator",
            "grants": [{"capability": "message.send", "scopes": ["mail.alice"]}],
        }
        return evaluate_runtime_policy_with_opa_cli(trusted)

    def create_runtime_log(self, payload):
        self.logs.append(payload)
        return {"id": len(self.logs)}


class IntegratedDualEraGatewayE2ETests(unittest.TestCase):
    def setUp(self) -> None:
        ModernEmailHandler.reset()
        LegacyEmailHandler.reset()
        DualEraFallbackTrapHandler.reset()
        self.modern = _ThreadedHTTPFixture(ModernEmailHandler)
        self.legacy = _ThreadedHTTPFixture(LegacyEmailHandler)
        self.snapshot = V2Snapshot()
        self.backend = IntegratedBackend(
            modern_endpoint=self.modern.endpoint,
            legacy_endpoint=self.legacy.endpoint,
        )
        proxy = MCPProxy(
            backend_client=self.backend,
            identity_verifier=IdentityVerifier(),
            assertion_signer=AssertionSigner(),
            trusted_session_manager=SessionManager(),
            config_snapshot_resolver=SnapshotResolver(self.snapshot),
        )
        self.gateway = TestClient(
            MCPGateway(
                proxy=proxy,
                backend_client=self.backend,
                snapshot_resolver=SnapshotResolver(self.snapshot),
            ).create_app()
        )

    def tearDown(self) -> None:
        self.modern.close()
        self.legacy.close()

    def _modern_payload(self, method: str, params: dict | None = None) -> dict:
        request_params = dict(params or {})
        request_params["_meta"] = {
            MODERN_META_PROTOCOL_VERSION: MODERN_PROTOCOL_VERSION,
            MODERN_META_CLIENT_CAPABILITIES: {},
            MODERN_META_CLIENT_INFO: {"name": "integrated-test", "version": "1"},
        }
        return {"jsonrpc": "2.0", "id": 1, "method": method, "params": request_params}

    def _modern_headers(self, method: str, name: str | None = None) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer test-token",
            "MCP-Protocol-Version": MODERN_PROTOCOL_VERSION,
            "Mcp-Method": method,
        }
        if name is not None:
            headers["Mcp-Name"] = name
        return headers

    def _legacy_session(self) -> str:
        response = self.gateway.post(
            "/mcp/1",
            headers={"Content-Type": "application/json"},
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": LEGACY_PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "legacy-client", "version": "1"},
                },
            },
        )
        self.assertEqual(response.status_code, 200)
        session_id = response.headers["mcp-session-id"]
        initialized = self.gateway.post(
            "/mcp/1",
            headers={
                "Content-Type": "application/json",
                "MCP-Protocol-Version": LEGACY_PROTOCOL_VERSION,
                "Mcp-Session-Id": session_id,
            },
            json={"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
        )
        self.assertEqual(initialized.status_code, 202)
        return session_id

    def _tool_call(self, client_profile: str, recipient: str):
        params = {
            "name": "send_email",
            "arguments": {
                "recipient": recipient,
                "subject": "hello",
                "body": "world",
            },
        }
        if client_profile == MODERN_PROFILE_ID:
            return self.gateway.post(
                "/mcp/1",
                headers=self._modern_headers("tools/call", "send_email"),
                json=self._modern_payload("tools/call", params),
            )
        session_id = self._legacy_session()
        return self.gateway.post(
            "/mcp/1",
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer test-token",
                "MCP-Protocol-Version": LEGACY_PROTOCOL_VERSION,
                "Mcp-Session-Id": session_id,
            },
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": params},
        )

    def test_real_four_quadrants_allow_and_block_before_upstream_execution(self) -> None:
        for client_profile in (MODERN_PROFILE_ID, LEGACY_PROFILE_ID):
            for upstream_profile in (MODERN_PROFILE_ID, LEGACY_PROFILE_ID):
                with self.subTest(client=client_profile, upstream=upstream_profile):
                    self.backend.preferred_upstream_profile = upstream_profile
                    before = ModernEmailHandler.invocation_count + LegacyEmailHandler.invocation_count

                    allowed = self._tool_call(client_profile, "alice@example.com")

                    self.assertEqual(allowed.status_code, 200)
                    after_allow = ModernEmailHandler.invocation_count + LegacyEmailHandler.invocation_count
                    self.assertEqual(after_allow, before + 1)

                    blocked = self._tool_call(client_profile, "bob@example.com")

                    self.assertEqual(blocked.status_code, 403)
                    after_block = ModernEmailHandler.invocation_count + LegacyEmailHandler.invocation_count
                    self.assertEqual(after_block, after_allow)

    def test_cross_profile_observation_approval_is_not_reused_integrated(self) -> None:
        self.snapshot.approved_profiles = {MODERN_PROFILE_ID}
        self.backend.preferred_upstream_profile = LEGACY_PROFILE_ID
        before = LegacyEmailHandler.invocation_count

        response = self._tool_call(MODERN_PROFILE_ID, "alice@example.com")

        self.assertEqual(response.status_code, 403)
        self.assertEqual(LegacyEmailHandler.invocation_count, before)

    def test_selected_modern_failure_has_no_silent_legacy_retry_integrated(self) -> None:
        trap = _ThreadedHTTPFixture(DualEraFallbackTrapHandler)
        try:
            DualEraFallbackTrapHandler.fail_modern_call = True
            self.backend.modern_endpoint = trap.endpoint
            self.backend.legacy_endpoint = trap.endpoint
            self.backend.preferred_upstream_profile = MODERN_PROFILE_ID

            response = self._tool_call(MODERN_PROFILE_ID, "alice@example.com")

            self.assertEqual(response.status_code, 403)
            self.assertEqual(DualEraFallbackTrapHandler.modern_call_count, 1)
            self.assertEqual(DualEraFallbackTrapHandler.legacy_initialize_count, 0)
            self.assertEqual(DualEraFallbackTrapHandler.legacy_call_count, 0)
            self.assertEqual(DualEraFallbackTrapHandler.invocation_count, 0)
        finally:
            trap.close()

    def test_real_2026_streamable_sse_allow_and_block(self) -> None:
        ModernSSEEmailHandler.reset()
        sse_upstream = _ThreadedHTTPFixture(ModernSSEEmailHandler)
        try:
            self.backend.modern_endpoint = sse_upstream.endpoint
            self.backend.preferred_upstream_profile = MODERN_PROFILE_ID

            allowed = self._tool_call(MODERN_PROFILE_ID, "alice@example.com")

            self.assertEqual(allowed.status_code, 200)
            self.assertEqual(ModernSSEEmailHandler.invocation_count, 1)

            blocked = self._tool_call(MODERN_PROFILE_ID, "bob@example.com")

            self.assertEqual(blocked.status_code, 403)
            self.assertEqual(ModernSSEEmailHandler.invocation_count, 1)
        finally:
            sse_upstream.close()

    def test_real_2024_historical_sse_allow_and_block(self) -> None:
        Legacy2024SSEEmailHandler.reset()
        historical_upstream = _ThreadedHTTPFixture(Legacy2024SSEEmailHandler)
        try:
            self.snapshot.approved_profiles.add(LEGACY_2024_11_05_PROFILE_ID)
            self.backend.legacy_endpoint = historical_upstream.endpoint
            self.backend.preferred_upstream_profile = LEGACY_2024_11_05_PROFILE_ID

            allowed = self._tool_call(MODERN_PROFILE_ID, "alice@example.com")

            self.assertEqual(allowed.status_code, 200)
            self.assertEqual(Legacy2024SSEEmailHandler.invocation_count, 1)

            blocked = self._tool_call(MODERN_PROFILE_ID, "bob@example.com")

            self.assertEqual(blocked.status_code, 403)
            self.assertEqual(Legacy2024SSEEmailHandler.invocation_count, 1)
        finally:
            Legacy2024SSEEmailHandler.events.put(None)
            historical_upstream.close()


if __name__ == "__main__":
    unittest.main()
