import unittest

from pydantic import ValidationError

from app.schemas.policy_decision import PolicyDecision


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
        "policy_revision": "opa-runtime-v1",
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

    def test_effect_must_match_decision(self) -> None:
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


if __name__ == "__main__":
    unittest.main()
