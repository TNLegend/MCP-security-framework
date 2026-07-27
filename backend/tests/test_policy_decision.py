import unittest

from pydantic import ValidationError

from app.schemas.policy_decision import PolicyDecision
from app.services.policy_engine import _to_policy_decision, evaluate_policy
from test_policy_context import TestClient, app, valid_context


def valid_decision_payload() -> dict:
    return {
        "effect": "ALLOW",
        "obligations": [
            {
                "type": "LOG",
                "parameters": {},
            }
        ],
        "rule_ids": ["allow_contracts_read"],
        "reason": "The request is allowed.",
        "severity": "low",
        "evidence": {},
        "recommended_action": None,
        "policy_revision": "legacy-yaml-v1",
        "decision": "ALLOW",
        "rule_id": "allow_contracts_read",
    }


class PolicyDecisionSchemaTests(unittest.TestCase):
    def test_valid_decision_is_accepted(self) -> None:
        decision = PolicyDecision.model_validate(valid_decision_payload())

        self.assertEqual(decision.effect, "ALLOW")
        self.assertEqual(decision.obligations[0].type, "LOG")

    def test_invalid_effect_is_rejected(self) -> None:
        payload = valid_decision_payload()
        payload["effect"] = "PERMIT"

        with self.assertRaises(ValidationError):
            PolicyDecision.model_validate(payload)

    def test_invalid_severity_is_rejected(self) -> None:
        payload = valid_decision_payload()
        payload["severity"] = "urgent"

        with self.assertRaises(ValidationError):
            PolicyDecision.model_validate(payload)

    def test_unknown_obligation_is_rejected(self) -> None:
        payload = valid_decision_payload()
        payload["obligations"] = [{"type": "SEND_DATA", "parameters": {}}]

        with self.assertRaises(ValidationError):
            PolicyDecision.model_validate(payload)

    def test_unknown_field_is_rejected(self) -> None:
        payload = valid_decision_payload()
        payload["unexpected_field"] = True

        with self.assertRaises(ValidationError):
            PolicyDecision.model_validate(payload)

    def test_empty_rule_ids_are_rejected(self) -> None:
        payload = valid_decision_payload()
        payload["rule_ids"] = []

        with self.assertRaises(ValidationError):
            PolicyDecision.model_validate(payload)

    def test_rule_id_must_be_present_in_rule_ids(self) -> None:
        payload = valid_decision_payload()
        payload["rule_ids"] = ["another_rule"]

        with self.assertRaises(ValidationError):
            PolicyDecision.model_validate(payload)

    def test_effect_must_match_legacy_decision(self) -> None:
        payload = valid_decision_payload()
        payload["effect"] = "DENY"

        with self.assertRaises(ValidationError):
            PolicyDecision.model_validate(payload)

    def test_duplicate_obligations_are_rejected(self) -> None:
        payload = valid_decision_payload()
        payload["obligations"] = [
            {"type": "LOG", "parameters": {}},
            {"type": "LOG", "parameters": {}},
        ]

        with self.assertRaises(ValidationError):
            PolicyDecision.model_validate(payload)

    def test_block_requires_log_and_alert(self) -> None:
        payload = valid_decision_payload()
        payload.update(
            {
                "effect": "DENY",
                "obligations": [{"type": "LOG", "parameters": {}}],
                "decision": "BLOCK",
                "rule_id": "deny_sensitive_paths",
                "rule_ids": ["deny_sensitive_paths"],
            }
        )

        with self.assertRaises(ValidationError):
            PolicyDecision.model_validate(payload)

    def test_warn_requires_warn_and_log(self) -> None:
        payload = valid_decision_payload()
        payload.update(
            {
                "obligations": [{"type": "LOG", "parameters": {}}],
                "decision": "WARN",
                "rule_id": "warn_high_risk_tool",
                "rule_ids": ["warn_high_risk_tool"],
            }
        )

        with self.assertRaises(ValidationError):
            PolicyDecision.model_validate(payload)

    def test_limit_requires_limit_output_and_log(self) -> None:
        payload = valid_decision_payload()
        payload.update(
            {
                "obligations": [{"type": "LOG", "parameters": {}}],
                "decision": "LIMIT",
                "rule_id": "limit_large_outputs",
                "rule_ids": ["limit_large_outputs"],
            }
        )

        with self.assertRaises(ValidationError):
            PolicyDecision.model_validate(payload)


class LegacyPolicyDecisionMappingTests(unittest.TestCase):
    def assert_legacy_mapping(
        self,
        legacy_decision: str,
        expected_effect: str,
        expected_obligations: set[str],
    ) -> None:
        decision = _to_policy_decision(
            {
                "decision": legacy_decision,
                "rule_id": "test_rule",
                "reason": "Test reason.",
                "severity": "medium",
            }
        )

        self.assertEqual(decision["effect"], expected_effect)
        self.assertEqual(
            {obligation["type"] for obligation in decision["obligations"]},
            expected_obligations,
        )
        self.assertEqual(decision["decision"], legacy_decision)
        self.assertEqual(decision["rule_id"], "test_rule")

    def test_allow_maps_to_allow_with_log(self) -> None:
        self.assert_legacy_mapping("ALLOW", "ALLOW", {"LOG"})

    def test_block_maps_to_deny_with_log_and_alert(self) -> None:
        self.assert_legacy_mapping("BLOCK", "DENY", {"LOG", "ALERT"})

    def test_warn_maps_to_allow_with_warn_and_log(self) -> None:
        self.assert_legacy_mapping("WARN", "ALLOW", {"WARN", "LOG"})

    def test_ask_approval_maps_to_defer_with_required_approval_and_log(self) -> None:
        self.assert_legacy_mapping(
            "ASK_APPROVAL",
            "DEFER",
            {"REQUIRE_APPROVAL", "LOG"},
        )

    def test_limit_maps_to_allow_with_limit_output_and_log(self) -> None:
        self.assert_legacy_mapping("LIMIT", "ALLOW", {"LIMIT_OUTPUT", "LOG"})

    def test_log_only_maps_to_allow_with_log(self) -> None:
        self.assert_legacy_mapping("LOG_ONLY", "ALLOW", {"LOG"})

    def test_unknown_legacy_decision_fails_closed(self) -> None:
        decision = _to_policy_decision(
            {
                "decision": "UNKNOWN",
                "rule_id": "unknown",
                "reason": "Unknown",
                "severity": "high",
            }
        )

        self.assertEqual(decision["effect"], "DENY")
        self.assertEqual(decision["decision"], "BLOCK")
        self.assertEqual(decision["rule_id"], "invalid_legacy_policy_decision")
        self.assertEqual(decision["severity"], "critical")


class PolicyDecisionRegressionTests(unittest.TestCase):
    def test_contract_read_policy_decision_is_allow(self) -> None:
        decision = evaluate_policy(valid_context())

        self.assertEqual(decision["decision"], "ALLOW")
        self.assertEqual(decision["effect"], "ALLOW")
        self.assertIn(
            "LOG",
            {obligation["type"] for obligation in decision["obligations"]},
        )
        self.assertEqual(decision["rule_id"], "allow_contracts_read")

    def test_sensitive_path_policy_decision_is_block(self) -> None:
        payload = valid_context()
        payload["request"]["arguments"] = {"path": ".env"}
        payload["request"]["canonical_resource"] = ".env"

        decision = evaluate_policy(payload)

        self.assertEqual(decision["decision"], "BLOCK")
        self.assertEqual(decision["effect"], "DENY")
        self.assertEqual(
            {obligation["type"] for obligation in decision["obligations"]},
            {"LOG", "ALERT"},
        )
        self.assertEqual(decision["rule_id"], "deny_sensitive_paths")

    def test_sensitive_path_policy_decision_is_case_insensitive(self) -> None:
        cases = [
            ".ENV",
            ".Env",
            "SECRETS/api.txt",
            "folder/ID_RSA",
            ".AWS/CREDENTIALS",
        ]
        for canonical_resource in cases:
            with self.subTest(canonical_resource=canonical_resource):
                payload = valid_context()
                payload["request"]["arguments"] = {"path": canonical_resource}
                payload["request"]["canonical_resource"] = canonical_resource

                decision = evaluate_policy(payload)

                self.assertEqual(decision["decision"], "BLOCK")
                self.assertEqual(decision["effect"], "DENY")
                self.assertEqual(decision["rule_id"], "deny_sensitive_paths")

    def test_contract_allow_rule_keeps_case_sensitive_prefix(self) -> None:
        payload = valid_context()
        payload["request"]["arguments"] = {"path": "CONTRACTS/contract1.txt"}
        payload["request"]["canonical_resource"] = "CONTRACTS/contract1.txt"
        payload["request"]["resource_scope"] = "lab_root"
        payload["subject"]["grants"] = [
            {
                "capability": "filesystem.read",
                "scopes": ["lab_root"],
            }
        ]
        payload["subject"]["allowed_scopes"] = ["lab_root"]

        decision = evaluate_policy(payload)

        self.assertEqual(decision["decision"], "LOG_ONLY")
        self.assertEqual(decision["rule_id"], "log_normal_runtime_call")


class RuntimeDecisionHttpContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(app)

    def test_runtime_decision_route_returns_canonical_decision(self) -> None:
        response = self.client.post("/api/v1/runtime/decision", json=valid_context())

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertIn("effect", payload)
        self.assertIn("obligations", payload)
        self.assertIn("rule_ids", payload)
        self.assertIn("decision", payload)

    def test_runtime_decision_route_rejects_invalid_context(self) -> None:
        payload = valid_context()
        del payload["tool"]["name"]

        response = self.client.post("/api/v1/runtime/decision", json=payload)

        self.assertEqual(response.status_code, 422)
