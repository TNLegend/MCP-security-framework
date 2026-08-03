import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND_DIR = REPO_ROOT / "backend"

sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(BACKEND_DIR))

from app.schemas.policy_decision import PolicyDecision
from app.services import policy_runtime
from app.services.identity_replay_store import IdentityReplayError
from app.services.internal_identity_assertion import (
    InternalIdentityAssertionError,
    VerifiedInternalIdentityAssertion,
)
from app.services.subject_authorization import (
    ResolvedCapabilityGrant,
    ResolvedSubjectAuthorization,
)
from identity_test_helpers import runtime_context
from runtime_policy_eval import evaluate_runtime_policy_with_opa_cli


class RecordingAssertionVerifier:
    def __init__(self, *, subject: str = "agent-demo", token_id: str = "jti-001") -> None:
        self.subject = subject
        self.token_id = token_id
        self.contexts = []

    def verify(self, *, assertion: str | None, context: dict):
        self.contexts.append(context)
        now = datetime.now(timezone.utc)
        return VerifiedInternalIdentityAssertion(
            issuer="mcp-security-proxy",
            subject=self.subject,
            audience=("mcp-security-backend",),
            token_id=self.token_id,
            session_id=context["runtime"]["session_id"],
            binding_revision=context["subject"]["identity_binding_revision"],
            issued_at=now,
            expires_at=now + timedelta(seconds=30),
        )


class FailingAssertionVerifier:
    def __init__(self, code: str) -> None:
        self.code = code

    def verify(self, *, assertion: str | None, context: dict):
        raise InternalIdentityAssertionError(self.code)


class RecordingAuthorizationResolver:
    def __init__(self) -> None:
        self.agent_ids = []

    def resolve(self, agent_id: str):
        self.agent_ids.append(agent_id)
        return ResolvedSubjectAuthorization(
            agent_id=agent_id,
            role="legal_agent",
            authorization_status="resolved",
            authorization_revision="test-authorization-v1",
            grants=(
                ResolvedCapabilityGrant(
                    "filesystem.read",
                    ("fs.project_workspace", "sensitive"),
                ),
                ResolvedCapabilityGrant("filesystem.list", ("fs.project_workspace",)),
            ),
            allowed_capabilities=("filesystem.read", "filesystem.list"),
            allowed_scopes=("fs.project_workspace", "sensitive"),
        )


class RegoOPAClient:
    def __init__(self) -> None:
        self.contexts = []

    def evaluate(self, context: dict) -> PolicyDecision:
        self.contexts.append(context)
        return PolicyDecision.model_validate(evaluate_runtime_policy_with_opa_cli(context))


class TrustedIdentityRuntimeTests(unittest.TestCase):
    def evaluate(
        self,
        *,
        context: dict | None = None,
        verifier=None,
        replay_consumer=None,
        resolver=None,
        opa_client=None,
    ):
        client = opa_client or RegoOPAClient()
        with patch.object(policy_runtime, "OPAClient", return_value=client):
            return policy_runtime.evaluate_runtime_policy(
                context=context or runtime_context(),
                identity_assertion="test.assertion",
                db=object(),
                assertion_verifier=verifier or RecordingAssertionVerifier(),
                replay_consumer=replay_consumer or (lambda **kwargs: None),
                resolver=resolver or RecordingAuthorizationResolver(),
            )

    def test_missing_assertion_fails_closed_before_resolver_and_opa(self) -> None:
        resolver = Mock()

        with patch.object(policy_runtime, "OPAClient") as opa:
            decision = self.evaluate(
                verifier=FailingAssertionVerifier("identity_assertion_missing"),
                resolver=resolver,
            )

        resolver.resolve.assert_not_called()
        opa.assert_not_called()
        self.assertEqual(decision.rule_id, "trusted_identity_required")
        self.assertEqual(
            decision.evidence["identity_error_code"],
            "identity_assertion_missing",
        )

    def test_signature_error_fails_closed_before_policy(self) -> None:
        with patch.object(policy_runtime, "OPAClient") as opa:
            decision = self.evaluate(
                verifier=FailingAssertionVerifier("identity_assertion_signature_invalid")
            )

        opa.assert_not_called()
        self.assertEqual(decision.effect, "DENY")
        self.assertEqual(
            decision.evidence["identity_error_code"],
            "identity_assertion_signature_invalid",
        )

    def test_replay_error_fails_closed_before_resolver(self) -> None:
        resolver = Mock()

        def replay_consumer(**kwargs):
            raise IdentityReplayError("identity_assertion_replayed")

        decision = self.evaluate(
            replay_consumer=replay_consumer,
            resolver=resolver,
        )

        resolver.resolve.assert_not_called()
        self.assertEqual(decision.rule_id, "trusted_identity_required")
        self.assertEqual(
            decision.evidence["identity_error_code"],
            "identity_assertion_replayed",
        )

    def test_replay_database_unavailable_fails_closed(self) -> None:
        def replay_consumer(**kwargs):
            raise IdentityReplayError("identity_replay_store_unavailable")

        decision = self.evaluate(replay_consumer=replay_consumer)

        self.assertEqual(decision.effect, "DENY")
        self.assertEqual(
            decision.evidence["identity_error_code"],
            "identity_replay_store_unavailable",
        )

    def test_db_none_fails_closed(self) -> None:
        decision = policy_runtime.evaluate_runtime_policy(
            context=runtime_context(),
            identity_assertion="test.assertion",
            db=None,
            assertion_verifier=RecordingAssertionVerifier(),
            replay_consumer=lambda **kwargs: None,
            resolver=RecordingAuthorizationResolver(),
        )

        self.assertEqual(decision.rule_id, "trusted_identity_required")
        self.assertEqual(
            decision.evidence["identity_error_code"],
            "identity_replay_store_unavailable",
        )

    def test_body_unverified_identity_fails_before_authorization(self) -> None:
        context = runtime_context(
            subject={
                "identity_status": "unverified",
                "identity_issuer": "unknown",
                "identity_binding_revision": "unknown",
            }
        )
        resolver = Mock()

        decision = self.evaluate(context=context, resolver=resolver)

        resolver.resolve.assert_not_called()
        self.assertEqual(
            decision.evidence["identity_error_code"],
            "identity_assertion_request_mismatch",
        )

    def test_verified_assertion_identity_replaces_body_agent_before_authorization(self) -> None:
        context = runtime_context(subject={"agent_id": "body-attacker"})
        resolver = RecordingAuthorizationResolver()

        decision = self.evaluate(
            context=context,
            verifier=RecordingAssertionVerifier(subject="agent-demo"),
            resolver=resolver,
        )

        self.assertEqual(resolver.agent_ids, ["agent-demo"])
        self.assertEqual(decision.rule_id, "allow_contracts_read")

    def test_opa_receives_verified_identity_only(self) -> None:
        opa_client = RegoOPAClient()

        self.evaluate(opa_client=opa_client)

        context = opa_client.contexts[0]
        self.assertEqual(context["subject"]["identity_status"], "verified")
        self.assertEqual(context["subject"]["agent_id"], "agent-demo")
        self.assertNotIn("access_token", context)

    def test_identity_invalid_does_not_call_opa(self) -> None:
        with patch.object(policy_runtime, "OPAClient") as opa:
            decision = policy_runtime.evaluate_runtime_policy(
                context=runtime_context(),
                identity_assertion="test.assertion",
                db=object(),
                assertion_verifier=FailingAssertionVerifier(
                    "identity_assertion_key_unknown"
                ),
                replay_consumer=lambda **kwargs: None,
                resolver=RecordingAuthorizationResolver(),
            )

        opa.assert_not_called()
        self.assertEqual(decision.rule_id, "trusted_identity_required")

    def test_opa_unavailable_after_valid_identity_is_fail_closed(self) -> None:
        with patch.object(policy_runtime, "OPAClient") as opa_client:
            opa_client.side_effect = RuntimeError("opa unavailable")
            decision = policy_runtime.evaluate_runtime_policy(
                context=runtime_context(),
                identity_assertion="test.assertion",
                db=object(),
                assertion_verifier=RecordingAssertionVerifier(),
                replay_consumer=lambda **kwargs: None,
                resolver=RecordingAuthorizationResolver(),
            )

        self.assertEqual(decision.effect, "DENY")
        self.assertEqual(decision.decision, "BLOCK")
        self.assertEqual(decision.rule_id, "opa_authoritative_unexpected_error")

    def test_invalid_arguments_remain_prioritized_after_identity_verification(self) -> None:
        context = runtime_context(
            request={
                "resource_scope": "invalid",
                "canonical_resource": None,
                "arguments": {},
                "arguments_valid": False,
                "validation_error_codes": ["missing_required:path"],
            }
        )

        decision = self.evaluate(context=context)

        self.assertEqual(decision.rule_id, "deny_invalid_arguments")

    def test_sensitive_path_remains_blocked_after_identity_verification(self) -> None:
        context = runtime_context(
            request={
                "resource_scope": "sensitive",
                "canonical_resource": ".env",
                "arguments": {"path": ".env"},
            }
        )

        decision = self.evaluate(context=context)

        self.assertEqual(decision.rule_id, "deny_sensitive_paths")

    def test_non_lab_scope_passes_identity_contract(self) -> None:
        context = runtime_context(
            request={
                "resource_scope": "db.postgresql.production.customers",
                "canonical_resource": "customers/query.sql",
                "arguments": {"path": "customers/query.sql"},
            }
        )

        decision = self.evaluate(context=context)

        self.assertIn(
            decision.rule_id,
            {"deny_scope_not_granted", "log_normal_runtime_call"},
        )


if __name__ == "__main__":
    unittest.main()
