import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from fastapi import BackgroundTasks
from pydantic import ValidationError


REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND_DIR = REPO_ROOT / "backend"

sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(BACKEND_DIR))

from app.core.config import PolicyEngineMode, Settings, settings  # noqa: E402
from app.schemas.policy_decision import PolicyDecision  # noqa: E402
from app.services import policy_runtime  # noqa: E402
from app.services.internal_identity_assertion import (  # noqa: E402
    VerifiedInternalIdentityAssertion,
)
from app.services.opa_client import OPAClientError  # noqa: E402
from app.services.subject_authorization import (  # noqa: E402
    ResolvedCapabilityGrant,
    ResolvedSubjectAuthorization,
    SubjectAuthorizationError,
)
from test_policy_context import valid_context  # noqa: E402
from test_policy_decision import valid_decision_payload  # noqa: E402


def opa_decision_payload() -> dict:
    payload = valid_decision_payload()
    payload["policy_revision"] = "opa-runtime-v1"
    return payload


class FakeOPAClient:
    def __init__(self, decision=None, error=None) -> None:
        self.decision = decision or PolicyDecision.model_validate(opa_decision_payload())
        self.error = error
        self.evaluate_calls = []

    def evaluate(self, context: dict):
        self.evaluate_calls.append(context)
        if self.error is not None:
            raise self.error
        return self.decision


class FakeAuthorizationResolver:
    def __init__(self, status: str = "resolved", error_code: str | None = None) -> None:
        self.status = status
        self.error_code = error_code

    def resolve(self, agent_id: str) -> ResolvedSubjectAuthorization:
        if self.error_code is not None:
            raise SubjectAuthorizationError(self.error_code)
        if self.status == "unknown":
            return ResolvedSubjectAuthorization(
                agent_id=agent_id,
                role="unknown",
                authorization_status="unknown",
                authorization_revision="test-authorization-v1",
                grants=(),
                allowed_capabilities=(),
                allowed_scopes=(),
            )
        grants = (
            ResolvedCapabilityGrant("filesystem.read", ("fs.project_workspace",)),
            ResolvedCapabilityGrant("filesystem.list", ("fs.project_workspace",)),
        )
        return ResolvedSubjectAuthorization(
            agent_id=agent_id,
            role="legal_agent",
            authorization_status="resolved",
            authorization_revision="test-authorization-v1",
            grants=grants,
            allowed_capabilities=("filesystem.read", "filesystem.list"),
            allowed_scopes=("fs.project_workspace",),
        )


class FakeAssertionVerifier:
    def verify(
        self,
        *,
        assertion: str | None,
        context: dict,
    ) -> VerifiedInternalIdentityAssertion:
        now = datetime.now(timezone.utc)
        return VerifiedInternalIdentityAssertion(
            issuer="mcp-security-proxy",
            subject=context["subject"]["agent_id"],
            audience=("mcp-security-backend",),
            token_id=f"jti-{context['runtime']['session_id']}",
            session_id=context["runtime"]["session_id"],
            binding_revision=context["subject"]["identity_binding_revision"],
            issued_at=now,
            expires_at=now + timedelta(seconds=30),
        )


def noop_replay_consumer(**kwargs) -> None:
    return None


def evaluate_with_trusted_identity(**kwargs) -> PolicyDecision:
    return policy_runtime.evaluate_runtime_policy(
        identity_assertion="test.assertion.value",
        db=object(),
        assertion_verifier=FakeAssertionVerifier(),
        replay_consumer=noop_replay_consumer,
        **kwargs,
    )


class PolicyRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.original_mode = settings.policy_engine_mode

    def tearDown(self) -> None:
        settings.policy_engine_mode = self.original_mode

    def test_legacy_mode_returns_yaml_without_opa_or_shadow(self) -> None:
        settings.policy_engine_mode = PolicyEngineMode.LEGACY
        background_tasks = BackgroundTasks()

        with patch.object(policy_runtime, "evaluate_policy") as yaml, patch.object(
            policy_runtime,
            "OPAClient",
        ) as opa_client:
            yaml.return_value = valid_decision_payload()
            decision = evaluate_with_trusted_identity(
                context=valid_context(),
                background_tasks=background_tasks,
                resolver=FakeAuthorizationResolver(),
            )

        yaml.assert_called_once()
        opa_client.assert_not_called()
        self.assertEqual(len(background_tasks.tasks), 0)
        self.assertEqual(decision.decision, "ALLOW")

    def test_shadow_mode_returns_yaml_and_adds_background_task(self) -> None:
        settings.policy_engine_mode = PolicyEngineMode.SHADOW
        background_tasks = BackgroundTasks()

        with patch.object(policy_runtime, "evaluate_policy") as yaml:
            yaml.return_value = valid_decision_payload()
            decision = evaluate_with_trusted_identity(
                context=valid_context(),
                background_tasks=background_tasks,
                resolver=FakeAuthorizationResolver(),
            )

        yaml.assert_called_once()
        self.assertEqual(decision.decision, "ALLOW")
        self.assertEqual(len(background_tasks.tasks), 1)

    def test_opa_mode_returns_opa_decision_without_yaml(self) -> None:
        settings.policy_engine_mode = PolicyEngineMode.OPA
        fake_client = FakeOPAClient()

        with patch.object(policy_runtime, "evaluate_policy") as yaml, patch.object(
            policy_runtime,
            "OPAClient",
            return_value=fake_client,
        ):
            decision = evaluate_with_trusted_identity(
                context=valid_context(),
                background_tasks=BackgroundTasks(),
                resolver=FakeAuthorizationResolver(),
            )

        yaml.assert_not_called()
        self.assertEqual(len(fake_client.evaluate_calls), 1)
        self.assertEqual(decision.policy_revision, "opa-runtime-v1")

    def test_opa_unavailable_fails_closed_without_yaml(self) -> None:
        decision = self.assert_opa_error_fails_closed(
            OPAClientError("opa_unavailable", "OPA unavailable."),
            "opa_unavailable",
        )

        self.assertEqual(decision.policy_revision, "opa-authoritative-fail-closed-v1")

    def test_opa_timeout_fails_closed(self) -> None:
        self.assert_opa_error_fails_closed(
            OPAClientError("opa_timeout", "OPA timeout."),
            "opa_timeout",
        )

    def test_opa_http_error_fails_closed(self) -> None:
        self.assert_opa_error_fails_closed(
            OPAClientError("opa_http_error", "OPA HTTP error."),
            "opa_http_error",
        )

    def test_opa_invalid_decision_fails_closed(self) -> None:
        self.assert_opa_error_fails_closed(
            OPAClientError("opa_invalid_decision", "OPA invalid decision."),
            "opa_invalid_decision",
        )

    def test_opa_unexpected_error_fails_closed(self) -> None:
        settings.policy_engine_mode = PolicyEngineMode.OPA
        fake_client = FakeOPAClient(error=RuntimeError("boom"))

        with patch.object(policy_runtime, "evaluate_policy") as yaml, patch.object(
            policy_runtime,
            "OPAClient",
            return_value=fake_client,
        ):
            decision = evaluate_with_trusted_identity(
                context=valid_context(),
                background_tasks=BackgroundTasks(),
                resolver=FakeAuthorizationResolver(),
            )

        yaml.assert_not_called()
        self.assertEqual(decision.effect, "DENY")
        self.assertEqual(decision.decision, "BLOCK")
        self.assertEqual(decision.rule_id, "opa_authoritative_unexpected_error")

    def test_enrich_subject_replaces_caller_role_capabilities_scopes_and_grants(self) -> None:
        context = valid_context()
        context["subject"].update(
            {
                "role": "admin",
                "allowed_capabilities": ["filesystem.admin"],
                "allowed_scopes": ["everything"],
                "grants": [{"capability": "filesystem.admin", "scopes": ["everything"]}],
            }
        )

        enriched = policy_runtime.enrich_subject_authorization(
            context,
            FakeAuthorizationResolver(),
        )

        self.assertEqual(enriched["subject"]["role"], "legal_agent")
        self.assertEqual(enriched["subject"]["allowed_capabilities"], ["filesystem.read", "filesystem.list"])
        self.assertEqual(enriched["subject"]["allowed_scopes"], ["fs.project_workspace"])
        self.assertEqual(
            enriched["subject"]["grants"],
            [
                {"capability": "filesystem.read", "scopes": ["fs.project_workspace"]},
                {"capability": "filesystem.list", "scopes": ["fs.project_workspace"]},
            ],
        )

    def test_enrich_unknown_agent_sets_unknown_without_grants(self) -> None:
        enriched = policy_runtime.enrich_subject_authorization(
            valid_context(),
            FakeAuthorizationResolver(status="unknown"),
        )

        self.assertEqual(enriched["subject"]["authorization_status"], "unknown")
        self.assertEqual(enriched["subject"]["grants"], [])

    def test_legacy_receives_enriched_context(self) -> None:
        settings.policy_engine_mode = PolicyEngineMode.LEGACY

        with patch.object(policy_runtime, "evaluate_policy") as yaml:
            yaml.return_value = valid_decision_payload()
            evaluate_with_trusted_identity(
                context=valid_context(),
                background_tasks=BackgroundTasks(),
                resolver=FakeAuthorizationResolver(),
            )

        context = yaml.call_args.args[0]
        self.assertEqual(context["subject"]["role"], "legal_agent")

    def test_shadow_yaml_and_opa_receive_same_enriched_context(self) -> None:
        settings.policy_engine_mode = PolicyEngineMode.SHADOW
        background_tasks = BackgroundTasks()

        with patch.object(policy_runtime, "evaluate_policy") as yaml:
            yaml.return_value = valid_decision_payload()
            evaluate_with_trusted_identity(
                context=valid_context(),
                background_tasks=background_tasks,
                resolver=FakeAuthorizationResolver(),
            )

        yaml_context = yaml.call_args.args[0]
        shadow_kwargs = background_tasks.tasks[0].kwargs
        self.assertEqual(shadow_kwargs["context"], yaml_context)
        self.assertEqual(yaml_context["subject"]["authorization_status"], "resolved")

    def test_opa_receives_enriched_context(self) -> None:
        settings.policy_engine_mode = PolicyEngineMode.OPA
        fake_client = FakeOPAClient()

        with patch.object(policy_runtime, "OPAClient", return_value=fake_client):
            evaluate_with_trusted_identity(
                context=valid_context(),
                background_tasks=BackgroundTasks(),
                resolver=FakeAuthorizationResolver(),
            )

        self.assertEqual(
            fake_client.evaluate_calls[0]["subject"]["authorization_status"],
            "resolved",
        )

    def test_resolver_error_skips_yaml_opa_and_background_tasks(self) -> None:
        settings.policy_engine_mode = PolicyEngineMode.SHADOW
        background_tasks = BackgroundTasks()

        with patch.object(policy_runtime, "evaluate_policy") as yaml, patch.object(
            policy_runtime,
            "OPAClient",
        ) as opa_client:
            decision = evaluate_with_trusted_identity(
                context=valid_context(),
                background_tasks=background_tasks,
                resolver=FakeAuthorizationResolver(
                    error_code="subject_authorization_invalid_yaml"
                ),
            )

        yaml.assert_not_called()
        opa_client.assert_not_called()
        self.assertEqual(len(background_tasks.tasks), 0)
        self.assertEqual(decision.effect, "DENY")
        self.assertEqual(decision.decision, "BLOCK")
        self.assertEqual(decision.rule_id, "subject_authorization_unavailable")
        self.assertEqual(
            decision.evidence["authorization_error_code"],
            "subject_authorization_invalid_yaml",
        )

    def test_fail_closed_decision_is_valid_policy_decision(self) -> None:
        decision = policy_runtime.build_opa_fail_closed_decision(
            error_code="opa_unavailable",
        )

        validated = PolicyDecision.model_validate(decision.model_dump(mode="json"))

        self.assertEqual(validated.rule_id, "opa_unavailable")

    def test_invalid_policy_engine_mode_is_rejected_by_settings(self) -> None:
        with self.assertRaises(ValidationError):
            Settings(policy_engine_mode="automatic")

    def assert_opa_error_fails_closed(
        self,
        error: OPAClientError,
        expected_rule_id: str,
    ) -> PolicyDecision:
        settings.policy_engine_mode = PolicyEngineMode.OPA
        fake_client = FakeOPAClient(error=error)

        with patch.object(policy_runtime, "evaluate_policy") as yaml, patch.object(
            policy_runtime,
            "OPAClient",
            return_value=fake_client,
        ):
            decision = evaluate_with_trusted_identity(
                context=valid_context(),
                background_tasks=BackgroundTasks(),
                resolver=FakeAuthorizationResolver(),
            )

        yaml.assert_not_called()
        self.assertEqual(decision.effect, "DENY")
        self.assertEqual(decision.decision, "BLOCK")
        self.assertEqual(decision.rule_id, expected_rule_id)
        self.assertEqual(decision.rule_ids, [expected_rule_id])
        self.assertEqual(decision.evidence["policy_engine"], "opa")
        self.assertEqual(decision.evidence["error_code"], expected_rule_id)
        return decision


if __name__ == "__main__":
    unittest.main()
