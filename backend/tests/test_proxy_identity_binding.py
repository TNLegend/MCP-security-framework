import json
import unittest
from datetime import datetime, timedelta, timezone

from proxy.agent_identity import AgentIdentityError, VerifiedExternalIdentity
from proxy.identity_binding import IdentityBindingError, ResolvedIdentityBinding
from proxy.internal_identity_assertion import InternalIdentityAssertionError
from proxy.mcp_proxy import MCPProxy
from test_proxy_policy_enforcement import (
    FakeBackendClient,
    FakeAssertionSigner,
    FakeResourceRegistryResolver,
    FakeToolSecurityProfileResolver,
    FakeTrustedSessionManager,
    TrackingMCPClient,
    policy_decision,
    reset_tracking_mcp_client,
    tool_call,
)


class StaticIdentityVerifier:
    def __init__(self, subject: str = "agent-demo") -> None:
        self.subject = subject
        self.tokens = []

    def verify(self, access_token: str) -> VerifiedExternalIdentity:
        self.tokens.append(access_token)
        now = datetime.now(timezone.utc)
        return VerifiedExternalIdentity(
            issuer="https://issuer.example/",
            subject=self.subject,
            audience=("mcp-security-proxy",),
            client_id=None,
            token_id="external-jti",
            issued_at=now,
            expires_at=now + timedelta(minutes=5),
        )


class FailingIdentityVerifier:
    def __init__(self, code: str = "agent_access_token_missing") -> None:
        self.code = code

    def verify(self, access_token: str) -> VerifiedExternalIdentity:
        raise AgentIdentityError(self.code)


class UnexpectedIdentityVerifier:
    def verify(self, access_token: str) -> VerifiedExternalIdentity:
        raise RuntimeError("unexpected identity error")


class StaticBindingResolver:
    def __init__(self, agent_id: str = "agent-demo") -> None:
        self.agent_id = agent_id
        self.requests = []

    def resolve(self, *, issuer: str, subject: str) -> ResolvedIdentityBinding:
        self.requests.append((issuer, subject))
        return ResolvedIdentityBinding(
            agent_id=self.agent_id,
            revision="identity-bindings-test-v1",
        )


class FailingBindingResolver:
    def __init__(self, code: str = "agent_identity_binding_not_found") -> None:
        self.code = code

    def resolve(self, *, issuer: str, subject: str) -> ResolvedIdentityBinding:
        raise IdentityBindingError(self.code)


class UnexpectedBindingResolver:
    def resolve(self, *, issuer: str, subject: str) -> ResolvedIdentityBinding:
        raise RuntimeError("unexpected binding error")


class FailingAssertionSigner:
    def __init__(self, code: str = "identity_assertion_key_unavailable") -> None:
        self.code = code

    def sign(self, context: dict) -> str:
        raise InternalIdentityAssertionError(self.code)


class CountingBackendClient(FakeBackendClient):
    def __init__(self, decision) -> None:
        super().__init__(decision)
        self.find_server_calls = 0
        self.find_tool_calls = 0
        self.request_policy_calls = 0

    def find_server(self, server_id=None, endpoint=None):
        self.find_server_calls += 1
        return super().find_server(server_id, endpoint)

    def find_tool(self, server_id: int, tool_name: str):
        self.find_tool_calls += 1
        return super().find_tool(server_id, tool_name)

    def request_policy_decision(self, context: dict, *, identity_assertion: str | None = None):
        self.request_policy_calls += 1
        return super().request_policy_decision(
            context,
            identity_assertion=identity_assertion,
        )


def allow_decision() -> dict:
    return policy_decision("ALLOW", [{"type": "LOG", "parameters": {}}])


class ProxyTrustedIdentityTests(unittest.TestCase):
    def build_proxy(
        self,
        backend: CountingBackendClient,
        *,
        verifier=None,
        resolver=None,
        signer=None,
    ) -> MCPProxy:
        return MCPProxy(
            backend_client=backend,
            mcp_client_class=TrackingMCPClient,
            identity_verifier=verifier or StaticIdentityVerifier(),
            identity_binding_resolver=resolver or StaticBindingResolver(),
            assertion_signer=signer or FakeAssertionSigner(),
            trusted_session_manager=FakeTrustedSessionManager(),
            tool_profile_resolver=FakeToolSecurityProfileResolver(),
            resource_registry_resolver=FakeResourceRegistryResolver(),
        )

    def test_token_verified_derives_internal_agent_when_claim_absent(self) -> None:
        reset_tracking_mcp_client()
        backend = CountingBackendClient(allow_decision())
        proxy = self.build_proxy(backend)
        call = tool_call()
        call.pop("agent_id")

        result = proxy.handle_tool_call(call)

        self.assertTrue(result["executed"])
        self.assertEqual(backend.last_policy_context["subject"]["agent_id"], "agent-demo")
        self.assertEqual(
            backend.last_policy_context["subject"]["identity_status"],
            "verified",
        )

    def test_metadata_authentication_uses_existing_bearer_identity_validation(self) -> None:
        backend = CountingBackendClient(allow_decision())
        verifier = StaticIdentityVerifier()
        resolver = StaticBindingResolver()
        proxy = self.build_proxy(backend, verifier=verifier, resolver=resolver)

        trusted_session = proxy.authenticate_framework_identity(
            {"access_token": "valid-token", "session_token": None}
        )

        self.assertEqual(trusted_session.agent_id, "agent-demo")
        self.assertEqual(verifier.tokens, ["valid-token"])
        self.assertEqual(resolver.requests, [("https://issuer.example/", "agent-demo")])
        self.assertEqual(backend.find_server_calls, 0)
        self.assertEqual(backend.request_policy_calls, 0)

    def test_metadata_authentication_rejects_invalid_bearer_identity(self) -> None:
        backend = CountingBackendClient(allow_decision())
        proxy = self.build_proxy(
            backend,
            verifier=FailingIdentityVerifier("agent_access_token_signature_invalid"),
        )

        with self.assertRaises(AgentIdentityError) as raised:
            proxy.authenticate_framework_identity(
                {"access_token": "invalid-token", "session_token": None}
            )

        self.assertEqual(raised.exception.code, "agent_access_token_signature_invalid")
        self.assertEqual(backend.find_server_calls, 0)
        self.assertEqual(backend.request_policy_calls, 0)

    def test_matching_claimed_agent_is_accepted(self) -> None:
        reset_tracking_mcp_client()
        backend = CountingBackendClient(allow_decision())
        proxy = self.build_proxy(backend)

        result = proxy.handle_tool_call(tool_call())

        self.assertTrue(result["executed"])
        self.assertEqual(result["decision"]["decision"], "ALLOW")

    def test_claimed_agent_mismatch_blocks_before_inventory_backend_and_mcp(self) -> None:
        reset_tracking_mcp_client()
        backend = CountingBackendClient(allow_decision())
        proxy = self.build_proxy(
            backend,
            resolver=StaticBindingResolver(agent_id="agent-list-only"),
        )

        result = proxy.handle_tool_call(tool_call())

        self.assertFalse(result["executed"])
        self.assertFalse(result["mcp_called"])
        self.assertEqual(backend.find_server_calls, 0)
        self.assertEqual(backend.request_policy_calls, 0)
        self.assertEqual(result["skip_reason"], "claimed_identity_mismatch")
        self.assertEqual(result["decision"]["rule_id"], "trusted_identity_required")

    def test_token_missing_blocks_before_inventory_backend_and_mcp(self) -> None:
        reset_tracking_mcp_client()
        backend = CountingBackendClient(allow_decision())
        proxy = self.build_proxy(
            backend,
            verifier=FailingIdentityVerifier("agent_access_token_missing"),
        )
        call = tool_call()
        call.pop("access_token")

        result = proxy.handle_tool_call(call)

        self.assertFalse(result["mcp_called"])
        self.assertEqual(backend.find_server_calls, 0)
        self.assertEqual(backend.request_policy_calls, 0)
        self.assertEqual(result["skip_reason"], "agent_access_token_missing")

    def test_invalid_token_blocks_before_backend_and_mcp(self) -> None:
        reset_tracking_mcp_client()
        backend = CountingBackendClient(allow_decision())
        proxy = self.build_proxy(
            backend,
            verifier=FailingIdentityVerifier("agent_access_token_signature_invalid"),
        )

        result = proxy.handle_tool_call(tool_call())

        self.assertFalse(result["mcp_called"])
        self.assertEqual(backend.request_policy_calls, 0)
        self.assertEqual(result["skip_reason"], "agent_access_token_signature_invalid")

    def test_identity_binding_missing_blocks_before_inventory(self) -> None:
        reset_tracking_mcp_client()
        backend = CountingBackendClient(allow_decision())
        proxy = self.build_proxy(
            backend,
            resolver=FailingBindingResolver("agent_identity_binding_not_found"),
        )

        result = proxy.handle_tool_call(tool_call())

        self.assertFalse(result["mcp_called"])
        self.assertEqual(backend.find_server_calls, 0)
        self.assertEqual(result["skip_reason"], "agent_identity_binding_not_found")

    def test_identity_binding_unavailable_blocks_before_inventory(self) -> None:
        reset_tracking_mcp_client()
        backend = CountingBackendClient(allow_decision())
        proxy = self.build_proxy(
            backend,
            resolver=FailingBindingResolver("agent_identity_binding_unavailable"),
        )

        result = proxy.handle_tool_call(tool_call())

        self.assertFalse(result["mcp_called"])
        self.assertEqual(backend.find_server_calls, 0)
        self.assertEqual(result["skip_reason"], "agent_identity_binding_unavailable")

    def test_unexpected_identity_error_is_fail_closed(self) -> None:
        reset_tracking_mcp_client()
        backend = CountingBackendClient(allow_decision())
        proxy = self.build_proxy(backend, verifier=UnexpectedIdentityVerifier())

        result = proxy.handle_tool_call(tool_call())

        self.assertFalse(result["mcp_called"])
        self.assertEqual(result["skip_reason"], "identity_verification_unexpected_error")

    def test_unexpected_binding_error_is_fail_closed(self) -> None:
        reset_tracking_mcp_client()
        backend = CountingBackendClient(allow_decision())
        proxy = self.build_proxy(backend, resolver=UnexpectedBindingResolver())

        result = proxy.handle_tool_call(tool_call())

        self.assertFalse(result["mcp_called"])
        self.assertEqual(result["skip_reason"], "identity_verification_unexpected_error")

    def test_assertion_signer_failure_blocks_before_backend_policy(self) -> None:
        reset_tracking_mcp_client()
        backend = CountingBackendClient(allow_decision())
        proxy = self.build_proxy(backend, signer=FailingAssertionSigner())

        result = proxy.handle_tool_call(tool_call())

        self.assertFalse(result["mcp_called"])
        self.assertEqual(backend.request_policy_calls, 0)
        self.assertEqual(result["skip_reason"], "identity_assertion_key_unavailable")

    def test_assertion_is_sent_only_in_header_argument_to_backend_client(self) -> None:
        reset_tracking_mcp_client()
        backend = CountingBackendClient(allow_decision())
        proxy = self.build_proxy(backend)

        proxy.handle_tool_call(tool_call())

        self.assertEqual(backend.last_identity_assertion, "test.assertion.value")
        self.assertNotIn("identity_assertion", backend.last_policy_context)

    def test_access_token_is_not_sent_to_policy_context_or_mcp_arguments(self) -> None:
        reset_tracking_mcp_client()
        backend = CountingBackendClient(allow_decision())
        proxy = self.build_proxy(backend)

        proxy.handle_tool_call(tool_call())
        serialized_context = json.dumps(backend.last_policy_context)

        self.assertNotIn("access_token", backend.last_policy_context)
        self.assertNotIn("token:agent-demo", serialized_context)
        self.assertEqual(TrackingMCPClient.last_arguments, {"path": "contracts/contract1.txt"})

    def test_caller_role_and_grants_are_ignored_after_verified_identity(self) -> None:
        reset_tracking_mcp_client()
        backend = CountingBackendClient(allow_decision())
        proxy = self.build_proxy(backend)
        call = tool_call()
        call.update(
            {
                "agent_role": "administrator",
                "grants": [{"capability": "filesystem.admin", "scopes": ["all"]}],
                "allowed_capabilities": ["filesystem.admin"],
                "allowed_scopes": ["all"],
            }
        )

        proxy.handle_tool_call(call)
        subject = backend.last_policy_context["subject"]

        self.assertEqual(subject["role"], "unknown")
        self.assertEqual(subject["grants"], [])
        self.assertEqual(subject["allowed_capabilities"], [])
        self.assertEqual(subject["allowed_scopes"], [])

    def test_runtime_log_payload_does_not_contain_token_or_assertion(self) -> None:
        reset_tracking_mcp_client()
        backend = CountingBackendClient(allow_decision())
        proxy = self.build_proxy(backend)

        result = proxy.handle_tool_call(tool_call())
        serialized = json.dumps(result["runtime_log"])

        self.assertNotIn("token:agent-demo", serialized)
        self.assertNotIn("test.assertion.value", serialized)
        self.assertNotIn("access_token", serialized)
        self.assertNotIn("identity_assertion", serialized)

    def test_external_identity_issuer_and_binding_revision_are_in_context(self) -> None:
        reset_tracking_mcp_client()
        backend = CountingBackendClient(allow_decision())
        resolver = StaticBindingResolver(agent_id="agent-demo")
        proxy = self.build_proxy(backend, resolver=resolver)

        proxy.handle_tool_call(tool_call())
        subject = backend.last_policy_context["subject"]

        self.assertEqual(resolver.requests, [("https://issuer.example/", "agent-demo")])
        self.assertEqual(subject["identity_issuer"], "https://issuer.example/")
        self.assertEqual(subject["identity_binding_revision"], "identity-bindings-test-v1")


if __name__ == "__main__":
    unittest.main()
