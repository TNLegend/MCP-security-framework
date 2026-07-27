import sys
import unittest
from copy import deepcopy
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND_DIR = REPO_ROOT / "backend"

sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(BACKEND_DIR))

from app.schemas.policy_decision import PolicyDecision  # noqa: E402
from app.schemas.policy_shadow import PolicyShadowStatus  # noqa: E402
from app.services.opa_client import OPAClientError  # noqa: E402
from app.services.policy_engine import evaluate_policy  # noqa: E402
from app.services.policy_shadow import (  # noqa: E402
    compare_policy_decisions,
    run_opa_shadow_evaluation,
)
from test_policy_context import valid_context  # noqa: E402
from test_policy_decision import valid_decision_payload  # noqa: E402


def decision_payload(
    *,
    effect: str = "ALLOW",
    obligations: list[dict] | None = None,
    rule_id: str = "allow_contracts_read",
    rule_ids: list[str] | None = None,
    severity: str = "low",
    legacy_decision: str = "ALLOW",
    policy_revision: str = "test-policy-v1",
) -> dict:
    payload = valid_decision_payload()
    payload.update(
        {
            "effect": effect,
            "obligations": obligations or [{"type": "LOG", "parameters": {}}],
            "rule_ids": rule_ids or [rule_id],
            "severity": severity,
            "policy_revision": policy_revision,
            "decision": legacy_decision,
            "rule_id": rule_id,
        }
    )
    return payload


def policy_decision(**kwargs) -> PolicyDecision:
    return PolicyDecision.model_validate(decision_payload(**kwargs))


class FakeOPAClient:
    def __init__(self, decision: PolicyDecision | None = None, error: Exception | None = None):
        self.decision = decision
        self.error = error

    def evaluate(self, context: dict):
        if self.error is not None:
            raise self.error
        return self.decision


class PolicyShadowComparisonTests(unittest.TestCase):
    def test_full_match(self) -> None:
        authoritative = policy_decision()
        shadow = policy_decision(policy_revision="opa-shadow-v1")

        comparison = compare_policy_decisions(authoritative, shadow)

        self.assertEqual(comparison.status, "match")
        self.assertTrue(comparison.match)
        self.assertEqual(comparison.mismatch_fields, [])
        self.assertEqual(comparison.mismatch_risk, "none")

    def test_obligation_order_does_not_matter(self) -> None:
        authoritative = policy_decision(
            effect="DENY",
            obligations=[
                {"type": "LOG", "parameters": {}},
                {"type": "ALERT", "parameters": {}},
            ],
            rule_id="deny_sensitive_paths",
            severity="high",
            legacy_decision="BLOCK",
        )
        shadow = policy_decision(
            effect="DENY",
            obligations=[
                {"type": "ALERT", "parameters": {}},
                {"type": "LOG", "parameters": {}},
            ],
            rule_id="deny_sensitive_paths",
            severity="high",
            legacy_decision="BLOCK",
        )

        comparison = compare_policy_decisions(authoritative, shadow)

        self.assertEqual(comparison.status, "match")
        self.assertEqual(comparison.mismatch_fields, [])

    def test_effect_mismatch_dangerous(self) -> None:
        authoritative = policy_decision(
            effect="DENY",
            obligations=[
                {"type": "LOG", "parameters": {}},
                {"type": "ALERT", "parameters": {}},
            ],
            rule_id="deny_sensitive_paths",
            severity="high",
            legacy_decision="BLOCK",
        )
        shadow = policy_decision()

        comparison = compare_policy_decisions(authoritative, shadow)

        self.assertEqual(comparison.status, "mismatch")
        self.assertEqual(comparison.mismatch_risk, "dangerous")
        self.assertIn("effect", comparison.mismatch_fields)

    def test_effect_mismatch_conservative(self) -> None:
        authoritative = policy_decision()
        shadow = policy_decision(
            effect="DENY",
            obligations=[
                {"type": "LOG", "parameters": {}},
                {"type": "ALERT", "parameters": {}},
            ],
            rule_id="deny_sensitive_paths",
            severity="high",
            legacy_decision="BLOCK",
        )

        comparison = compare_policy_decisions(authoritative, shadow)

        self.assertEqual(comparison.mismatch_risk, "conservative")

    def test_obligation_mismatch_is_behavioral(self) -> None:
        authoritative = policy_decision(
            obligations=[
                {"type": "WARN", "parameters": {}},
                {"type": "LOG", "parameters": {}},
            ],
            rule_id="warn_high_risk_tool",
            severity="medium",
            legacy_decision="WARN",
        )
        shadow = policy_decision(
            rule_id="warn_high_risk_tool",
            severity="medium",
        )

        comparison = compare_policy_decisions(authoritative, shadow)

        self.assertEqual(comparison.mismatch_risk, "behavioral")
        self.assertIn("obligations", comparison.mismatch_fields)

    def test_rule_ids_mismatch(self) -> None:
        comparison = compare_policy_decisions(
            policy_decision(rule_id="allow_contracts_read"),
            policy_decision(rule_id="log_normal_runtime_call", legacy_decision="LOG_ONLY"),
        )

        self.assertIn("rule_ids", comparison.mismatch_fields)

    def test_severity_mismatch(self) -> None:
        comparison = compare_policy_decisions(
            policy_decision(severity="low"),
            policy_decision(severity="medium"),
        )

        self.assertIn("severity", comparison.mismatch_fields)

    def test_multiple_differences_have_expected_order(self) -> None:
        authoritative = policy_decision(
            effect="DENY",
            obligations=[
                {"type": "LOG", "parameters": {}},
                {"type": "ALERT", "parameters": {}},
            ],
            rule_id="deny_sensitive_paths",
            severity="high",
            legacy_decision="BLOCK",
        )
        shadow = policy_decision(rule_id="log_normal_runtime_call", legacy_decision="LOG_ONLY")

        comparison = compare_policy_decisions(authoritative, shadow)

        self.assertEqual(
            [field.value for field in comparison.mismatch_fields],
            ["effect", "obligations", "rule_ids", "severity"],
        )

    def test_opa_client_error_returns_error_comparison(self) -> None:
        comparison = run_opa_shadow_evaluation(
            context=valid_context(),
            authoritative_decision=policy_decision(),
            opa_client=FakeOPAClient(
                error=OPAClientError("opa_unavailable", "OPA unavailable.")
            ),
        )

        self.assertEqual(comparison.status, "error")
        self.assertIsNone(comparison.match)
        self.assertEqual(comparison.mismatch_risk, "unknown")
        self.assertEqual(comparison.error_code, "opa_unavailable")

    def test_unexpected_error_returns_error_comparison(self) -> None:
        comparison = run_opa_shadow_evaluation(
            context=valid_context(),
            authoritative_decision=policy_decision(),
            opa_client=FakeOPAClient(error=RuntimeError("boom")),
        )

        self.assertEqual(comparison.error_code, "opa_shadow_unexpected_error")

    def test_run_opa_shadow_evaluation_always_returns_comparison(self) -> None:
        comparison = run_opa_shadow_evaluation(
            context=valid_context(),
            authoritative_decision=policy_decision(),
            opa_client=FakeOPAClient(error=RuntimeError("boom")),
        )

        self.assertIsNotNone(comparison)
        self.assertIsInstance(comparison.status, PolicyShadowStatus)

    def test_logs_are_safe_and_have_expected_levels(self) -> None:
        sensitive_context = deepcopy(valid_context())
        sensitive_context["subject"]["agent_id"] = "agent-test"
        sensitive_context["runtime"]["session_id"] = "session-test"
        sensitive_context["request"]["arguments"] = {"path": "contracts/contract1.txt"}
        sensitive_context["server"]["endpoint"] = "http://127.0.0.1:9000/mcp"

        cases = [
            (policy_decision(), None, "INFO", "policy_shadow_match"),
            (
                policy_decision(rule_id="log_normal_runtime_call", legacy_decision="LOG_ONLY"),
                None,
                "WARNING",
                "policy_shadow_mismatch",
            ),
            (
                None,
                OPAClientError("opa_unavailable", "OPA unavailable."),
                "WARNING",
                "policy_shadow_error",
            ),
        ]

        for shadow_decision, error, level, message in cases:
            with self.subTest(message=message):
                client = FakeOPAClient(decision=shadow_decision, error=error)
                with self.assertLogs("app.services.policy_shadow", level=level) as logs:
                    run_opa_shadow_evaluation(
                        context=sensitive_context,
                        authoritative_decision=policy_decision(),
                        opa_client=client,
                    )

                output = "\n".join(logs.output)
                self.assertIn(message, output)
                self.assertNotIn("contracts/contract1.txt", output)
                self.assertNotIn(".env", output)
                self.assertNotIn("agent-test", output)
                self.assertNotIn("session-test", output)
                self.assertNotIn("http://127.0.0.1:9000/mcp", output)

    def test_high_risk_yaml_warn_matches_migrated_opa_warn(self) -> None:
        context = valid_context()
        context["tool"]["risk_score"] = 80.0
        authoritative = PolicyDecision.model_validate(evaluate_policy(context))
        shadow = policy_decision(
            obligations=[
                {"type": "WARN", "parameters": {}},
                {"type": "LOG", "parameters": {}},
            ],
            rule_id="warn_high_risk_tool",
            severity="medium",
            legacy_decision="WARN",
            policy_revision="opa-runtime-v1",
        )

        comparison = compare_policy_decisions(authoritative, shadow)

        self.assertEqual(comparison.status, "match")
        self.assertTrue(comparison.match)
        self.assertEqual(comparison.mismatch_fields, [])
        self.assertEqual(comparison.mismatch_risk, "none")


if __name__ == "__main__":
    unittest.main()
