import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND_DIR = REPO_ROOT / "backend"

sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(BACKEND_DIR))
sys.path.insert(0, str(BACKEND_DIR / "tests"))

from app.schemas.policy_context import RuntimePolicyInput  # noqa: E402
from app.schemas.policy_decision import PolicyDecision  # noqa: E402
from app.services.policy_engine import evaluate_policy  # noqa: E402
from policy_parity_cases import POLICY_PARITY_CASES  # noqa: E402
from scripts.validate_policy_parity import normalized_policy_decision  # noqa: E402
from test_policy_decision import valid_decision_payload  # noqa: E402


class PolicyParityMatrixTests(unittest.TestCase):
    def test_case_ids_are_unique(self) -> None:
        case_ids = [case.case_id for case in POLICY_PARITY_CASES]

        self.assertEqual(len(case_ids), len(set(case_ids)))

    def test_matrix_has_at_least_61_cases(self) -> None:
        self.assertGreaterEqual(len(POLICY_PARITY_CASES), 61)

    def test_all_contexts_are_valid_runtime_policy_inputs(self) -> None:
        for case in POLICY_PARITY_CASES:
            with self.subTest(case_id=case.case_id):
                RuntimePolicyInput.model_validate(case.context)

    def test_yaml_decisions_match_expected_rule_ids(self) -> None:
        for case in POLICY_PARITY_CASES:
            with self.subTest(case_id=case.case_id):
                context = RuntimePolicyInput.model_validate(case.context).model_dump(
                    mode="json"
                )
                decision = evaluate_policy(context)

                self.assertEqual(decision["rule_id"], case.expected_rule_id)

    def test_threshold_and_priority_cases_are_present_and_correct(self) -> None:
        expected = {
            "risk_below_threshold": "log_normal_runtime_call",
            "risk_at_threshold": "warn_high_risk_tool",
            "risk_above_threshold": "warn_high_risk_tool",
            "size_equal_threshold": "log_normal_runtime_call",
            "size_above_threshold": "limit_large_outputs",
            "size_large": "limit_large_outputs",
            "priority_unknown_server_env": "block_unknown_server",
            "priority_blocked_server_env": "block_unknown_server",
            "priority_unknown_server_contract": "block_unknown_server",
            "priority_unknown_server_all_lower": "block_unknown_server",
            "priority_sensitive_path_high_sensitivity": "deny_sensitive_paths",
            "priority_sensitive_path_large_output": "deny_sensitive_paths",
            "priority_sensitive_path_high_risk": "deny_sensitive_paths",
            "priority_contract_env": "deny_sensitive_paths",
            "sensitive_env_uppercase": "deny_sensitive_paths",
            "sensitive_env_mixed_case": "deny_sensitive_paths",
            "sensitive_secrets_uppercase": "deny_sensitive_paths",
            "sensitive_id_rsa_uppercase": "deny_sensitive_paths",
            "sensitive_aws_credentials_uppercase": "deny_sensitive_paths",
            "canonical_uppercase_env_over_raw_contract": "deny_sensitive_paths",
            "priority_high_sensitivity_limit_warn_contract": (
                "require_approval_for_sensitive_tool"
            ),
            "priority_large_output_warn_contract": "limit_large_outputs",
            "priority_high_risk_contract": "warn_high_risk_tool",
            "priority_contract_only": "allow_contracts_read",
            "priority_high_sensitivity_high_risk": (
                "require_approval_for_sensitive_tool"
            ),
            "priority_large_output_high_risk": "limit_large_outputs",
            "invalid_arguments_only": "deny_invalid_arguments",
            "unknown_server_and_invalid_arguments": "block_unknown_server",
            "invalid_arguments_and_sensitive_path": "deny_invalid_arguments",
            "invalid_arguments_and_contract": "deny_invalid_arguments",
            "invalid_arguments_and_high_risk": "deny_invalid_arguments",
            "invalid_arguments_and_sensitive_tool": "deny_invalid_arguments",
            "invalid_arguments_and_large_output": "deny_invalid_arguments",
            "canonical_sensitive_over_raw_contract": "deny_sensitive_paths",
            "canonical_contract_over_raw_sensitive": "allow_contracts_read",
            "unknown_subject": "deny_unknown_subject",
            "unclassified_capability": "deny_unclassified_capability",
            "capability_not_granted": "deny_capability_not_granted",
            "scope_not_granted": "deny_scope_not_granted",
            "exact_read_contract_grant": "allow_contracts_read",
            "exact_list_root_grant": "log_normal_runtime_call",
            "cross_product_scope_attack": "deny_scope_not_granted",
            "unknown_server_and_unknown_subject": "block_unknown_server",
            "invalid_arguments_and_unknown_subject": "deny_invalid_arguments",
            "unknown_subject_and_sensitive": "deny_unknown_subject",
            "known_subject_without_grant_and_sensitive": "deny_sensitive_paths",
            "capability_denied_and_high_risk": "deny_capability_not_granted",
            "scope_denied_and_large_output": "deny_scope_not_granted",
        }
        cases_by_id = {case.case_id: case for case in POLICY_PARITY_CASES}

        for case_id, expected_rule_id in expected.items():
            with self.subTest(case_id=case_id):
                case = cases_by_id[case_id]
                decision = evaluate_policy(case.context)

                self.assertEqual(decision["rule_id"], expected_rule_id)

    def test_normalizer_ignores_only_policy_revision(self) -> None:
        left = PolicyDecision.model_validate(valid_decision_payload())
        right_payload = valid_decision_payload()
        right_payload["policy_revision"] = "opa-runtime-v1"
        right = PolicyDecision.model_validate(right_payload)

        self.assertEqual(
            normalized_policy_decision(left),
            normalized_policy_decision(right),
        )

        changed = valid_decision_payload()
        changed["reason"] = "Changed reason."
        self.assertNotEqual(
            normalized_policy_decision(left),
            normalized_policy_decision(PolicyDecision.model_validate(changed)),
        )

    def test_normalizer_sorts_obligations(self) -> None:
        left_payload = valid_decision_payload()
        left_payload.update(
            {
                "effect": "ALLOW",
                "obligations": [
                    {"type": "WARN", "parameters": {}},
                    {"type": "LOG", "parameters": {}},
                ],
                "rule_ids": ["warn_high_risk_tool"],
                "reason": "High-risk MCP tool call detected.",
                "severity": "medium",
                "decision": "WARN",
                "rule_id": "warn_high_risk_tool",
            }
        )
        right_payload = dict(left_payload)
        right_payload["obligations"] = [
            {"type": "LOG", "parameters": {}},
            {"type": "WARN", "parameters": {}},
        ]

        self.assertEqual(
            normalized_policy_decision(PolicyDecision.model_validate(left_payload)),
            normalized_policy_decision(PolicyDecision.model_validate(right_payload)),
        )

    def test_normalizer_sorts_rule_ids(self) -> None:
        left_payload = valid_decision_payload()
        right_payload = valid_decision_payload()
        left_payload["rule_ids"] = ["allow_contracts_read", "z_rule"]
        right_payload["rule_ids"] = ["z_rule", "allow_contracts_read"]

        self.assertEqual(
            normalized_policy_decision(PolicyDecision.model_validate(left_payload)),
            normalized_policy_decision(PolicyDecision.model_validate(right_payload)),
        )

    def test_warn_and_log_only_are_not_equivalent(self) -> None:
        warn_payload = valid_decision_payload()
        warn_payload.update(
            {
                "obligations": [
                    {"type": "WARN", "parameters": {}},
                    {"type": "LOG", "parameters": {}},
                ],
                "rule_ids": ["warn_high_risk_tool"],
                "reason": "High-risk MCP tool call detected.",
                "severity": "medium",
                "decision": "WARN",
                "rule_id": "warn_high_risk_tool",
            }
        )
        log_only_payload = valid_decision_payload()
        log_only_payload.update(
            {
                "rule_ids": ["log_normal_runtime_call"],
                "reason": "Runtime call logged for audit purposes.",
                "decision": "LOG_ONLY",
                "rule_id": "log_normal_runtime_call",
            }
        )

        self.assertNotEqual(
            normalized_policy_decision(PolicyDecision.model_validate(warn_payload)),
            normalized_policy_decision(PolicyDecision.model_validate(log_only_payload)),
        )


if __name__ == "__main__":
    unittest.main()
