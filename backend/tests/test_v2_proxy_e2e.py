from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
import unittest
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend"
TESTS = BACKEND / "tests"
for path in (str(ROOT), str(BACKEND), str(TESTS)):
    if path not in sys.path:
        sys.path.insert(0, path)

from app.services.published_configuration import PublishedConfigurationError  # noqa: E402
from proxy.agent_identity import VerifiedExternalIdentity  # noqa: E402
from proxy.backend_client import BackendClientError  # noqa: E402
from proxy.http_mcp_client import MCPProtocolError  # noqa: E402
from proxy.identity_binding import ResolvedIdentityBinding  # noqa: E402
from proxy.mcp_proxy import MCPProxy  # noqa: E402
from proxy.protocol_profiles import LEGACY_PROFILE_ID, MODERN_PROFILE_ID  # noqa: E402
from proxy.tool_security_v2 import (  # noqa: E402
    AuthorityResourceScope,
    FixedResourceReference,
    ResourceBinding,
    ScopeMatchMode,
    ToolEffect,
    ToolObservationApproval,
    ToolSecurityContract,
    validate_contract_for_schema,
)
from proxy.trusted_sessions import ProxyTrustedSession  # noqa: E402
from runtime_policy_eval import evaluate_runtime_policy_with_opa_cli  # noqa: E402


SERVER_REF = "streamable_http:http://127.0.0.1:9990/mcp"
FINGERPRINT = "b" * 64
CONTENT_HASH = "c" * 64
ARG_SCHEMA = {
    "type": "object",
    "properties": {
        "recipient": {"type": "string", "maxLength": 254},
        "subject": {"type": "string", "maxLength": 200},
        "body": {"type": "string", "maxLength": 10000},
    },
    "required": ["recipient", "subject", "body"],
    "additionalProperties": False,
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
RESOLUTIONS = validate_contract_for_schema(CONTRACT, ARG_SCHEMA)
SCOPES = (
    AuthorityResourceScope(
        scope_id="mail.alice",
        authority=SERVER_REF,
        resource_type="email_address",
        canonical_value="alice@example.com",
        match_mode=ScopeMatchMode.SELF,
    ),
)
FILE_FINGERPRINT = "e" * 64
FILE_ARG_SCHEMA = {
    "type": "object",
    "properties": {"path": {"type": "string", "maxLength": 4096}},
    "required": ["path"],
    "additionalProperties": False,
}
FILE_CONTRACT = ToolSecurityContract(
    server_ref=SERVER_REF,
    tool_name="read_file",
    effects=(
        ToolEffect(
            effect_id="file.read",
            capability="filesystem.read",
            resource_bindings=(
                ResourceBinding(path=("path",), resource_type="filesystem_path"),
            ),
            max_resource_cardinality=1,
        ),
    ),
)
FILE_RESOLUTIONS = validate_contract_for_schema(FILE_CONTRACT, FILE_ARG_SCHEMA)
FILE_SCOPES = (
    AuthorityResourceScope(
        scope_id="files.data",
        authority=SERVER_REF,
        resource_type="filesystem_path",
        canonical_value="data",
        match_mode=ScopeMatchMode.SUBTREE,
    ),
)
LIST_FINGERPRINT = "a" * 64
LIST_ARG_SCHEMA = {
    "type": "object",
    "properties": {},
    "additionalProperties": False,
}
LIST_CONTRACT = ToolSecurityContract(
    server_ref=SERVER_REF,
    tool_name="list_files",
    effects=(
        ToolEffect(
            effect_id="file.list",
            capability="filesystem.list",
            fixed_resource=FixedResourceReference(
                resource_type="filesystem_path",
                canonical_value="data",
            ),
            max_resource_cardinality=1,
        ),
    ),
)
LIST_RESOLUTIONS = validate_contract_for_schema(LIST_CONTRACT, LIST_ARG_SCHEMA)


class V2Snapshot:
    schema_version = 2
    revision_id = "revision-v2"
    revision_number = 2
    content_hash = CONTENT_HASH

    def __init__(self) -> None:
        self.approved_profiles = {LEGACY_PROFILE_ID, MODERN_PROFILE_ID}
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
            evidence_bundle_hash="d" * 64,
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
            raise PublishedConfigurationError("authority_missing")
        return {"separator": "/", "case_sensitive": True, "max_depth": 32}


class FileV2Snapshot(V2Snapshot):
    def get_tool_security_contract(self, *, server_ref: str, tool_name: str):
        if (server_ref, tool_name) != (SERVER_REF, "read_file"):
            raise PublishedConfigurationError("contract_missing")
        return FILE_CONTRACT

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
            or tool_fingerprint != FILE_FINGERPRINT
        ):
            raise PublishedConfigurationError("profile_observation_not_approved")
        return ToolObservationApproval(
            tool_observation_id=10,
            server_ref=SERVER_REF,
            upstream_protocol_profile_id=upstream_protocol_profile_id,
            tool_fingerprint=FILE_FINGERPRINT,
            contract_hash=FILE_CONTRACT.contract_hash,
            evidence_bundle_hash="f" * 64,
            admin_id="admin",
            approved_at="2026-01-01T00:00:00Z",
            revision_id=self.revision_id,
        )

    def get_adapter_resolutions(self, *, effect_id: str):
        return tuple(value for value in FILE_RESOLUTIONS if value.effect_id == effect_id)

    def get_authority_resource_scopes(self):
        return FILE_SCOPES

    def get_authority_context(self, authority: str):
        if authority != SERVER_REF:
            raise PublishedConfigurationError("authority_missing")
        return {"filesystem_path_mode": "RELATIVE_ROOTED"}


class ListV2Snapshot(V2Snapshot):
    def get_tool_security_contract(self, *, server_ref: str, tool_name: str):
        if (server_ref, tool_name) != (SERVER_REF, "list_files"):
            raise PublishedConfigurationError("contract_missing")
        return LIST_CONTRACT

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
            or tool_fingerprint != LIST_FINGERPRINT
        ):
            raise PublishedConfigurationError("profile_observation_not_approved")
        return ToolObservationApproval(
            tool_observation_id=11,
            server_ref=SERVER_REF,
            upstream_protocol_profile_id=upstream_protocol_profile_id,
            tool_fingerprint=LIST_FINGERPRINT,
            contract_hash=LIST_CONTRACT.contract_hash,
            evidence_bundle_hash="9" * 64,
            admin_id="admin",
            approved_at="2026-01-01T00:00:00Z",
            revision_id=self.revision_id,
        )

    def get_adapter_resolutions(self, *, effect_id: str):
        return tuple(value for value in LIST_RESOLUTIONS if value.effect_id == effect_id)

    def get_authority_resource_scopes(self):
        return FILE_SCOPES

    def get_authority_context(self, authority: str):
        if authority != SERVER_REF:
            raise PublishedConfigurationError("authority_missing")
        return {"filesystem_path_mode": "RELATIVE_ROOTED"}


class SnapshotResolver:
    def __init__(self, snapshot: V2Snapshot) -> None:
        self.snapshot = snapshot

    def load_active_snapshot(self):
        return self.snapshot


class IdentityVerifier:
    def verify(self, access_token: str):
        now = datetime.now(timezone.utc)
        return VerifiedExternalIdentity(
            issuer="https://issuer.example/",
            subject="agent-demo",
            audience=("mcp-security-proxy",),
            client_id=None,
            token_id="jti-v2",
            issued_at=now,
            expires_at=now + timedelta(minutes=5),
        )


class SessionManager:
    def create_for_identity(self, *, external_identity, identity_binding):
        return self._session()

    def validate_token(self, session_token: str):
        return self._session()

    @staticmethod
    def _session():
        return ProxyTrustedSession(
            session_reference="framework-session-v2",
            session_token="session-token",
            agent_id="agent-demo",
            identity_issuer="https://issuer.example/",
            identity_subject="agent-demo",
            identity_binding_revision=CONTENT_HASH,
            session_status="active",
        )


class AssertionSigner:
    def sign(self, context: dict) -> str:
        return "trusted.test.assertion"


class V2Backend:
    def __init__(self) -> None:
        self.upstream_profile = LEGACY_PROFILE_ID
        self.logs = []
        self.emergency_results = [False]
        self.local_analysis_status = "APPROVED"
        self.last_policy_context = None

    def find_server(self, server_id=None, endpoint=None):
        return {
            "id": 1,
            "endpoint": "http://127.0.0.1:9990/mcp",
            "transport": "streamable_http",
            "protocol_version": "2025-11-25",
            "preferred_upstream_profile": self.upstream_profile,
            "trust_status": "trusted",
            "security_status": "approved",
        }

    def find_tool(self, server_id: int, tool_name: str, upstream_protocol_profile_id: str | None = None):
        return {
            "id": 1,
            "server_id": 1,
            "name": tool_name,
            "input_schema": ARG_SCHEMA,
            "analysis_status": self.local_analysis_status,
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
            "review_status": (
                "APPROVED"
                if self.local_analysis_status == "APPROVED"
                else "REVIEW_REQUIRED"
            ),
            "analyzer_revision": "v1",
        }

    def check_emergency_deny(self, context):
        blocked = self.emergency_results.pop(0) if len(self.emergency_results) > 1 else self.emergency_results[0]
        return {"blocked": blocked, "deny_id": "deny-race" if blocked else None}

    def request_policy_decision(self, context, *, identity_assertion=None):
        trusted = dict(context)
        self.last_policy_context = trusted
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


class FileV2Backend(V2Backend):
    def find_tool(self, server_id: int, tool_name: str, upstream_protocol_profile_id: str | None = None):
        return {
            "id": 1,
            "server_id": 1,
            "name": tool_name,
            "input_schema": FILE_ARG_SCHEMA,
            "analysis_status": self.local_analysis_status,
            "current_fingerprint": FILE_FINGERPRINT,
            "approved_fingerprint_match": True,
            "risk_score": 1,
            "risk_level": "low",
            "sensitivity": "low",
            "description_risk_score": 1,
            "semantic_flagged": False,
            "deterministic_critical_finding": False,
            "consistency_status": "consistent",
            "drift_status": "NONE",
            "review_status": (
                "APPROVED"
                if self.local_analysis_status == "APPROVED"
                else "REVIEW_REQUIRED"
            ),
            "analyzer_revision": "v1",
        }

    def request_policy_decision(self, context, *, identity_assertion=None):
        trusted = dict(context)
        self.last_policy_context = trusted
        trusted["subject"] = {
            **context["subject"],
            "authorization_status": "resolved",
            "authorization_revision": CONTENT_HASH,
            "role": "operator",
            "grants": [{"capability": "filesystem.read", "scopes": ["files.data"]}],
        }
        return evaluate_runtime_policy_with_opa_cli(trusted)


class ListV2Backend(FileV2Backend):
    def find_tool(self, server_id: int, tool_name: str, upstream_protocol_profile_id: str | None = None):
        tool = super().find_tool(server_id, tool_name, upstream_protocol_profile_id)
        return {
            **tool,
            "input_schema": LIST_ARG_SCHEMA,
            "current_fingerprint": LIST_FINGERPRINT,
        }


class TrackingMCPClient:
    calls = []
    fail = False

    def __init__(
        self,
        endpoint,
        protocol_version,
        protocol_profile_id=None,
        bearer_token=None,
    ):
        self.profile_id = protocol_profile_id
        self.calls.append(("created", protocol_profile_id))

    def call_tool(self, name, arguments):
        self.calls.append((name, self.profile_id, dict(arguments)))
        if self.fail:
            raise MCPProtocolError("selected profile failed")
        result = {"isError": False, "content": [{"type": "text", "text": "sent"}]}
        if self.profile_id == MODERN_PROFILE_ID:
            result["resultType"] = "complete"
        return result


class MutatingProxy(MCPProxy):
    def _execute_tool_call(self, tool_call, server, decision, prepared_request):
        tool_call["arguments"] = {**tool_call["arguments"], "recipient": "bob@example.com"}
        return super()._execute_tool_call(tool_call, server, decision, prepared_request)


class V2ProxyE2ETests(unittest.TestCase):
    def setUp(self) -> None:
        TrackingMCPClient.calls = []
        TrackingMCPClient.fail = False
        self.snapshot = V2Snapshot()
        self.backend = V2Backend()

    def proxy(self, cls=MCPProxy):
        return cls(
            backend_client=self.backend,
            mcp_client_class=TrackingMCPClient,
            identity_verifier=IdentityVerifier(),
            assertion_signer=AssertionSigner(),
            trusted_session_manager=SessionManager(),
            config_snapshot_resolver=SnapshotResolver(self.snapshot),
        )

    def call(self, proxy, recipient, client_profile):
        return proxy.handle_tool_call(
            {
                "access_token": "token",
                "server_id": 1,
                "tool_name": "send_email",
                "arguments": {"recipient": recipient, "subject": "hello", "body": "world"},
                "client_protocol_profile_id": client_profile,
            }
        )

    def test_four_quadrants_use_same_real_generic_opa_authorization(self) -> None:
        for client_profile in (MODERN_PROFILE_ID, LEGACY_PROFILE_ID):
            for upstream_profile in (MODERN_PROFILE_ID, LEGACY_PROFILE_ID):
                with self.subTest(client=client_profile, upstream=upstream_profile):
                    self.backend.upstream_profile = upstream_profile
                    allowed = self.call(self.proxy(), "alice@example.com", client_profile)
                    self.assertTrue(allowed["executed"])
                    forwarded = [
                        call for call in TrackingMCPClient.calls if call[0] == "send_email"
                    ][-1]
                    self.assertEqual(forwarded[1], upstream_profile)
                    self.assertEqual(
                        forwarded[2],
                        {
                            "recipient": "alice@example.com",
                            "subject": "hello",
                            "body": "world",
                        },
                    )
                    self.assertEqual(
                        self.backend.logs[-1]["upstream_protocol_profile_id"],
                        upstream_profile,
                    )
                    before = len([call for call in TrackingMCPClient.calls if call[0] == "send_email"])
                    blocked = self.call(self.proxy(), "bob@example.com", client_profile)
                    self.assertFalse(blocked["executed"])
                    after = len([call for call in TrackingMCPClient.calls if call[0] == "send_email"])
                    self.assertEqual(before, after)

    def test_cross_profile_approval_is_not_reused(self) -> None:
        self.snapshot.approved_profiles = {MODERN_PROFILE_ID}
        self.backend.upstream_profile = LEGACY_PROFILE_ID
        result = self.call(self.proxy(), "alice@example.com", MODERN_PROFILE_ID)
        self.assertFalse(result["executed"])
        self.assertEqual(result["skip_reason"], "profile_observation_not_approved")

    def test_published_observation_approval_does_not_require_mutated_tool_status(self) -> None:
        self.backend.local_analysis_status = "REVIEW_REQUIRED"
        self.backend.upstream_profile = MODERN_PROFILE_ID

        result = self.call(self.proxy(), "alice@example.com", MODERN_PROFILE_ID)

        self.assertTrue(result["executed"])
        self.assertEqual(
            self.backend.last_policy_context["tool"]["analysis_status"],
            "APPROVED",
        )
        self.assertTrue(
            self.backend.last_policy_context["tool"]["approved_fingerprint_match"]
        )

    def test_blocked_current_analysis_reports_observation_gate_reason(self) -> None:
        self.backend.local_analysis_status = "BLOCKED"
        result = self.call(self.proxy(), "alice@example.com", MODERN_PROFILE_ID)

        self.assertFalse(result["executed"])
        self.assertFalse(result["mcp_called"])
        self.assertEqual(result["skip_reason"], "approved_observation_not_current")
        self.assertEqual(
            result["decision"]["reason"],
            "The current tool analysis is not eligible for the published observation approval.",
        )

    def test_arguments_mutated_after_allow_are_blocked_before_mcp(self) -> None:
        result = self.call(self.proxy(MutatingProxy), "alice@example.com", MODERN_PROFILE_ID)
        self.assertFalse(result["executed"])
        self.assertFalse(result["mcp_called"])
        self.assertEqual(result["skip_reason"], "canonical_arguments_changed_before_execution")

    def test_emergency_deny_is_rechecked_immediately_before_execution(self) -> None:
        self.backend.emergency_results = [False, True]
        result = self.call(self.proxy(), "alice@example.com", MODERN_PROFILE_ID)
        self.assertFalse(result["executed"])
        self.assertFalse(result["mcp_called"])
        self.assertEqual(result["skip_reason"], "emergency_deny_active")

    def test_opa_unavailable_blocks_without_mcp_call(self) -> None:
        def unavailable(*_args, **_kwargs):
            raise BackendClientError("OPA unavailable")

        self.backend.request_policy_decision = unavailable
        result = self.call(self.proxy(), "alice@example.com", MODERN_PROFILE_ID)
        self.assertFalse(result["executed"])
        self.assertFalse(result["mcp_called"])
        self.assertEqual(result["skip_reason"], "policy_error")
        self.assertFalse(any(call[0] == "send_email" for call in TrackingMCPClient.calls))

    def test_invalid_opa_binding_echo_blocks_without_mcp_call(self) -> None:
        valid_decision = self.backend.request_policy_decision

        def malformed(context, *, identity_assertion=None):
            result = valid_decision(context, identity_assertion=identity_assertion)
            result.pop("canonical_arguments_hash", None)
            return result

        self.backend.request_policy_decision = malformed
        result = self.call(self.proxy(), "alice@example.com", MODERN_PROFILE_ID)
        self.assertFalse(result["executed"])
        self.assertFalse(result["mcp_called"])
        self.assertEqual(result["skip_reason"], "policy_arguments_hash_binding_mismatch")
        self.assertFalse(any(call[0] == "send_email" for call in TrackingMCPClient.calls))

    def test_emergency_store_unavailable_blocks_without_mcp_call(self) -> None:
        def unavailable(_context):
            raise BackendClientError("deny store unavailable")

        self.backend.check_emergency_deny = unavailable
        result = self.call(self.proxy(), "alice@example.com", MODERN_PROFILE_ID)
        self.assertFalse(result["executed"])
        self.assertFalse(result["mcp_called"])
        self.assertEqual(result["skip_reason"], "emergency_deny_store_unavailable")
        self.assertFalse(any(call[0] == "send_email" for call in TrackingMCPClient.calls))

    def test_selected_modern_profile_failure_has_no_legacy_retry(self) -> None:
        self.backend.upstream_profile = MODERN_PROFILE_ID
        TrackingMCPClient.fail = True
        result = self.call(self.proxy(), "alice@example.com", MODERN_PROFILE_ID)
        self.assertEqual(result["execution_status"], "protocol_error")
        self.assertFalse(result["executed"])
        created_profiles = [call[1] for call in TrackingMCPClient.calls if call[0] == "created"]
        self.assertEqual(created_profiles, [MODERN_PROFILE_ID])

    def test_selected_legacy_profile_failure_has_no_revision_retry(self) -> None:
        self.backend.upstream_profile = LEGACY_PROFILE_ID
        TrackingMCPClient.fail = True
        result = self.call(self.proxy(), "alice@example.com", MODERN_PROFILE_ID)
        self.assertEqual(result["execution_status"], "protocol_error")
        self.assertFalse(result["executed"])
        created_profiles = [call[1] for call in TrackingMCPClient.calls if call[0] == "created"]
        self.assertEqual(created_profiles, [LEGACY_PROFILE_ID])

    def test_invalid_arguments_block_before_identity_and_policy(self) -> None:
        snapshot = FileV2Snapshot()
        backend = FileV2Backend()
        backend.upstream_profile = MODERN_PROFILE_ID
        proxy = MCPProxy(
            backend_client=backend,
            mcp_client_class=TrackingMCPClient,
            identity_verifier=IdentityVerifier(),
            assertion_signer=AssertionSigner(),
            trusted_session_manager=SessionManager(),
            config_snapshot_resolver=SnapshotResolver(snapshot),
        )

        result = proxy.handle_tool_call(
            {
                "access_token": "token",
                "server_id": 1,
                "tool_name": "read_file",
                "arguments": {"path": "data/file.txt", "unexpected": True},
                "client_protocol_profile_id": MODERN_PROFILE_ID,
            }
        )

        self.assertFalse(result["executed"])
        self.assertFalse(result["mcp_called"])
        self.assertEqual(result["decision"]["rule_id"], "invalid_tool_arguments_guard")
        self.assertEqual(result["skip_reason"], "invalid_tool_arguments")
        self.assertIsNone(backend.last_policy_context)
        self.assertFalse(any(call[0] == "read_file" for call in TrackingMCPClient.calls))

    def test_zero_argument_tool_rejects_extra_argument_before_identity_and_policy(self) -> None:
        snapshot = ListV2Snapshot()
        backend = ListV2Backend()
        proxy = MCPProxy(
            backend_client=backend,
            mcp_client_class=TrackingMCPClient,
            identity_verifier=IdentityVerifier(),
            assertion_signer=AssertionSigner(),
            trusted_session_manager=SessionManager(),
            config_snapshot_resolver=SnapshotResolver(snapshot),
        )

        result = proxy.handle_tool_call(
            {
                "access_token": "token",
                "server_id": 1,
                "tool_name": "list_files",
                "arguments": {"path": "contracts"},
                "client_protocol_profile_id": MODERN_PROFILE_ID,
            }
        )

        self.assertFalse(result["executed"])
        self.assertFalse(result["mcp_called"])
        self.assertEqual(result["decision"]["rule_id"], "invalid_tool_arguments_guard")
        self.assertEqual(result["skip_reason"], "invalid_tool_arguments")
        self.assertIsNone(backend.last_policy_context)
        self.assertFalse(any(call[0] == "list_files" for call in TrackingMCPClient.calls))

    def test_v2_sensitive_filesystem_reference_blocks_before_mcp_call(self) -> None:
        snapshot = FileV2Snapshot()
        backend = FileV2Backend()
        backend.upstream_profile = MODERN_PROFILE_ID
        proxy = MCPProxy(
            backend_client=backend,
            mcp_client_class=TrackingMCPClient,
            identity_verifier=IdentityVerifier(),
            assertion_signer=AssertionSigner(),
            trusted_session_manager=SessionManager(),
            config_snapshot_resolver=SnapshotResolver(snapshot),
        )

        result = proxy.handle_tool_call(
            {
                "access_token": "token",
                "server_id": 1,
                "tool_name": "read_file",
                "arguments": {"path": "data/secrets/config.json"},
                "client_protocol_profile_id": MODERN_PROFILE_ID,
            }
        )

        self.assertFalse(result["executed"])
        self.assertFalse(result["mcp_called"])
        self.assertEqual(result["decision"]["rule_id"], "deny_sensitive_resource")
        self.assertEqual(
            backend.last_policy_context["request"]["resource_sensitivity"],
            "secret",
        )
        self.assertFalse(any(call[0] == "read_file" for call in TrackingMCPClient.calls))


if __name__ == "__main__":
    unittest.main()
