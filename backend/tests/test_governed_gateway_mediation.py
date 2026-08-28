from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
import unittest

from fastapi.testclient import TestClient


ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend"
TESTS = BACKEND / "tests"
for path in (str(ROOT), str(BACKEND), str(TESTS)):
    if path not in sys.path:
        sys.path.insert(0, path)

from proxy.agent_identity import VerifiedExternalIdentity  # noqa: E402
from proxy.backend_client import BackendClientError  # noqa: E402
from proxy.gateway import MCPGateway  # noqa: E402
from proxy.identity_binding import IdentityBindingError  # noqa: E402
from proxy.mcp_proxy import MCPProxy  # noqa: E402
from proxy.protocol_profiles import (  # noqa: E402
    MODERN_META_CLIENT_CAPABILITIES,
    MODERN_META_CLIENT_INFO,
    MODERN_META_PROTOCOL_VERSION,
    MODERN_PROFILE_ID,
    MODERN_PROTOCOL_VERSION,
)
from proxy.trusted_sessions import ProxyTrustedSession  # noqa: E402
from runtime_policy_eval import evaluate_runtime_policy_with_opa_cli  # noqa: E402
from test_integrated_dual_era_e2e import (  # noqa: E402
    CONTENT_HASH,
    FINGERPRINT,
    SEND_EMAIL_SCHEMA,
    SEND_EMAIL_TOOL,
    SERVER_REF,
    ModernEmailHandler,
    SnapshotResolver,
    V2Snapshot,
    _ThreadedHTTPFixture,
)


class GovernedPrimaryMCPHandler(ModernEmailHandler):
    pass


class GovernedAttackerMCPHandler(ModernEmailHandler):
    pass


class IdentityVerifier:
    def verify(self, _access_token: str):
        now = datetime.now(timezone.utc)
        return VerifiedExternalIdentity(
            issuer="https://issuer.example/",
            subject="agent-demo",
            audience=("mcp-security-proxy",),
            client_id=None,
            token_id="governed-jti",
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


class GovernedBackend:
    def __init__(self, *, endpoint: str) -> None:
        self.endpoint = endpoint
        self.find_server_requests: list[dict] = []
        self.logs: list[dict] = []

    def find_server(self, server_id=None, endpoint=None):
        self.find_server_requests.append({"server_id": server_id, "endpoint": endpoint})
        if endpoint is not None or server_id != 1:
            return None
        return {
            "id": 1,
            "server_ref": SERVER_REF,
            "endpoint": self.endpoint,
            "transport": "streamable_http",
            "protocol_version": MODERN_PROTOCOL_VERSION,
            "preferred_upstream_profile": MODERN_PROFILE_ID,
            "trust_status": "trusted",
            "security_status": "approved",
        }

    def list_tools(self):
        return [self.find_tool(1, "send_email")]

    def find_tool(self, server_id: int, tool_name: str, upstream_protocol_profile_id: str | None = None):
        if server_id != 1 or tool_name != "send_email":
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


class GovernedGatewayMediationTests(unittest.TestCase):
    def setUp(self) -> None:
        GovernedPrimaryMCPHandler.reset()
        GovernedAttackerMCPHandler.reset()
        self.upstream = _ThreadedHTTPFixture(GovernedPrimaryMCPHandler)
        self.attacker = _ThreadedHTTPFixture(GovernedAttackerMCPHandler)
        self.snapshot = V2Snapshot()
        self.backend = GovernedBackend(endpoint=self.upstream.endpoint)
        self.proxy = MCPProxy(
            backend_client=self.backend,
            identity_verifier=IdentityVerifier(),
            assertion_signer=AssertionSigner(),
            trusted_session_manager=SessionManager(),
            config_snapshot_resolver=SnapshotResolver(self.snapshot),
        )
        self.gateway = TestClient(
            MCPGateway(
                proxy=self.proxy,
                backend_client=self.backend,
                snapshot_resolver=SnapshotResolver(self.snapshot),
            ).create_app()
        )

    def tearDown(self) -> None:
        self.upstream.close()
        self.attacker.close()

    def _modern_payload(self, recipient: str) -> dict:
        return {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "send_email",
                "arguments": {
                    "recipient": recipient,
                    "subject": "hello",
                    "body": "world",
                },
                "_meta": {
                    MODERN_META_PROTOCOL_VERSION: MODERN_PROTOCOL_VERSION,
                    MODERN_META_CLIENT_CAPABILITIES: {},
                    MODERN_META_CLIENT_INFO: {
                        "name": "governed-gateway-test",
                        "version": "1",
                    },
                },
            },
        }

    def _modern_headers(self) -> dict[str, str]:
        return {
            "Content-Type": "application/json",
            "Authorization": "Bearer test-token",
            "MCP-Protocol-Version": MODERN_PROTOCOL_VERSION,
            "Mcp-Method": "tools/call",
            "Mcp-Name": "send_email",
        }

    def _runtime_call(self, **overrides):
        call = {
            "access_token": "token",
            "server_id": 1,
            "tool_name": "send_email",
            "arguments": {
                "recipient": "alice@example.com",
                "subject": "hello",
                "body": "world",
            },
            "client_protocol_profile_id": MODERN_PROFILE_ID,
        }
        call.update(overrides)
        return call

    def test_gateway_mediates_plain_third_party_style_upstream(self) -> None:
        allowed = self.gateway.post(
            "/mcp/1",
            headers=self._modern_headers(),
            json=self._modern_payload("alice@example.com"),
        )
        self.assertEqual(allowed.status_code, 200)
        self.assertEqual(GovernedPrimaryMCPHandler.invocation_count, 1)
        self.assertEqual(GovernedAttackerMCPHandler.invocation_count, 0)
        self.assertIn(
            {"server_id": 1, "endpoint": None},
            self.backend.find_server_requests,
        )

        before_block = GovernedPrimaryMCPHandler.invocation_count
        blocked = self.gateway.post(
            "/mcp/1",
            headers=self._modern_headers(),
            json=self._modern_payload("bob@example.com"),
        )

        self.assertEqual(blocked.status_code, 403)
        self.assertEqual(GovernedPrimaryMCPHandler.invocation_count, before_block)
        self.assertEqual(GovernedAttackerMCPHandler.invocation_count, 0)
        blocked_calls_reaching_mcp = (
            GovernedPrimaryMCPHandler.invocation_count - before_block
        )
        self.assertEqual(blocked_calls_reaching_mcp, 0)


    def test_concurrent_allowed_calls_remain_mediated(self) -> None:
        before = GovernedPrimaryMCPHandler.invocation_count
        with ThreadPoolExecutor(max_workers=8) as executor:
            results = list(
                executor.map(
                    lambda _: self.proxy.handle_tool_call(self._runtime_call()),
                    range(24),
                )
            )

        self.assertTrue(all(result["executed"] for result in results))
        self.assertTrue(all(result["mcp_called"] for result in results))
        self.assertEqual(
            GovernedPrimaryMCPHandler.invocation_count - before,
            24,
        )
        self.assertEqual(GovernedAttackerMCPHandler.invocation_count, 0)


    def test_concurrent_identity_failures_are_logged_without_secret_leakage(self) -> None:
        class MissingBindingSnapshot(V2Snapshot):
            def resolve(self, *, issuer: str, subject: str):
                raise IdentityBindingError("agent_identity_binding_not_found")

        snapshot = MissingBindingSnapshot()
        backend = GovernedBackend(endpoint=self.upstream.endpoint)
        proxy = MCPProxy(
            backend_client=backend,
            identity_verifier=IdentityVerifier(),
            assertion_signer=AssertionSigner(),
            trusted_session_manager=SessionManager(),
            config_snapshot_resolver=SnapshotResolver(snapshot),
        )
        before = GovernedPrimaryMCPHandler.invocation_count

        with ThreadPoolExecutor(max_workers=8) as executor:
            results = list(
                executor.map(
                    lambda _: proxy.handle_tool_call(self._runtime_call()),
                    range(16),
                )
            )

        self.assertTrue(all(not result["executed"] for result in results))
        self.assertTrue(all(not result["mcp_called"] for result in results))
        self.assertTrue(
            all(
                result["skip_reason"] == "agent_identity_binding_not_found"
                for result in results
            )
        )
        self.assertTrue(all(result["runtime_log_created"] for result in results))
        self.assertEqual(GovernedPrimaryMCPHandler.invocation_count, before)
        self.assertEqual(len(backend.logs), 16)
        for payload in backend.logs:
            self.assertEqual(payload["agent_id"], "unverified")
            self.assertEqual(payload["session_id"], "unverified")
            self.assertEqual(payload["decision"], "BLOCK")
            self.assertEqual(payload["rule_id"], "trusted_identity_required")
            self.assertEqual(
                payload["error_summary"],
                "agent_identity_binding_not_found",
            )
            serialized = json.dumps(payload, sort_keys=True)
            self.assertNotIn("access_token", serialized)
            self.assertNotIn("Bearer ", serialized)
            self.assertNotIn('"token"', serialized)

    def test_concurrent_policy_failure_never_fails_open(self) -> None:
        class FailingPolicyBackend(GovernedBackend):
            def request_policy_decision(self, context, *, identity_assertion=None):
                raise BackendClientError("simulated_policy_timeout")

        backend = FailingPolicyBackend(endpoint=self.upstream.endpoint)
        proxy = MCPProxy(
            backend_client=backend,
            identity_verifier=IdentityVerifier(),
            assertion_signer=AssertionSigner(),
            trusted_session_manager=SessionManager(),
            config_snapshot_resolver=SnapshotResolver(self.snapshot),
        )
        before = GovernedPrimaryMCPHandler.invocation_count
        with ThreadPoolExecutor(max_workers=8) as executor:
            results = list(
                executor.map(
                    lambda _: proxy.handle_tool_call(self._runtime_call()),
                    range(32),
                )
            )

        self.assertTrue(all(not result["executed"] for result in results))
        self.assertTrue(all(not result["mcp_called"] for result in results))
        self.assertTrue(all(result["rule_id"] == "policy_error" for result in results))
        self.assertEqual(GovernedPrimaryMCPHandler.invocation_count, before)
        self.assertEqual(GovernedAttackerMCPHandler.invocation_count, 0)
        self.assertEqual(len(backend.logs), 32)

    def test_runtime_rejects_client_endpoint_injection(self) -> None:
        before_primary = GovernedPrimaryMCPHandler.invocation_count
        before_attacker = GovernedAttackerMCPHandler.invocation_count

        result = self.proxy.handle_tool_call(
            self._runtime_call(server_endpoint=self.attacker.endpoint)
        )

        self.assertFalse(result["executed"])
        self.assertFalse(result["mcp_called"])
        self.assertEqual(result["skip_reason"], "inventory_error")
        self.assertEqual(GovernedPrimaryMCPHandler.invocation_count, before_primary)
        self.assertEqual(GovernedAttackerMCPHandler.invocation_count, before_attacker)

    def test_runtime_rejects_url_string_server_id(self) -> None:
        before_primary = GovernedPrimaryMCPHandler.invocation_count
        before_attacker = GovernedAttackerMCPHandler.invocation_count

        result = self.proxy.handle_tool_call(
            self._runtime_call(server_id=self.attacker.endpoint)
        )

        self.assertFalse(result["executed"])
        self.assertFalse(result["mcp_called"])
        self.assertEqual(result["skip_reason"], "inventory_error")
        self.assertEqual(GovernedPrimaryMCPHandler.invocation_count, before_primary)
        self.assertEqual(GovernedAttackerMCPHandler.invocation_count, before_attacker)

    def test_runtime_rejects_missing_or_malformed_server_id(self) -> None:
        cases = [
            {"server_id": None},
            {"server_id": "1"},
            {"server_id": 0},
            {"server_id": True},
        ]
        for override in cases:
            with self.subTest(server_id=override["server_id"]):
                result = self.proxy.handle_tool_call(self._runtime_call(**override))
                self.assertFalse(result["executed"])
                self.assertFalse(result["mcp_called"])
                self.assertEqual(result["skip_reason"], "inventory_error")
        self.assertEqual(GovernedPrimaryMCPHandler.invocation_count, 0)
        self.assertEqual(GovernedAttackerMCPHandler.invocation_count, 0)

    def test_unknown_server_id_fails_closed(self) -> None:
        response = self.gateway.post(
            "/mcp/999",
            headers=self._modern_headers(),
            json=self._modern_payload("alice@example.com"),
        )

        self.assertEqual(response.status_code, 403)
        self.assertEqual(GovernedPrimaryMCPHandler.invocation_count, 0)
        self.assertEqual(GovernedAttackerMCPHandler.invocation_count, 0)


if __name__ == "__main__":
    unittest.main()
