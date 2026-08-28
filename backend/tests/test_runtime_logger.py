import json
import sys
import time
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND_DIR = REPO_ROOT / "backend"

sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(BACKEND_DIR))

from proxy.runtime_logger import build_runtime_log, summarize_arguments  # noqa: E402


class RuntimeLoggerArgumentSummaryTests(unittest.TestCase):
    def test_valid_path_value_is_not_logged(self) -> None:
        summary = summarize_arguments(
            {
                "arguments": {"path": "contracts/contract1.txt"},
                "arguments_valid": True,
                "validation_error_codes": [],
                "resource_type": "file",
                "resource_scope": "contracts",
                "canonical_resource": "contracts/contract1.txt",
            }
        )
        serialized = json.dumps(summary, sort_keys=True)

        self.assertNotIn("contracts/contract1.txt", serialized)
        self.assertNotIn("canonical_resource", serialized)
        self.assertEqual(summary["argument_names"], ["path"])
        self.assertEqual(summary["argument_types"], {"path": "string"})

    def test_sensitive_path_value_is_not_logged(self) -> None:
        summary = summarize_arguments(
            {
                "arguments": {"path": ".env"},
                "arguments_valid": False,
                "validation_error_codes": ["invalid_type:path"],
                "resource_type": "file",
                "resource_scope": "invalid",
            }
        )
        serialized = json.dumps(summary, sort_keys=True)

        self.assertNotIn(".env", serialized)
        self.assertIn("invalid_type:path", summary["validation_error_codes"])

    def test_sensitive_variants_and_schema_uri_are_not_logged(self) -> None:
        summary = summarize_arguments(
            {
                "arguments": {
                    "path": ".ENV",
                    "other": "SECRETS/api.txt",
                    "key": "folder/ID_RSA",
                    "schema": "https://unknown.example/custom-dialect",
                },
                "arguments_valid": False,
                "validation_error_codes": ["input_schema_unsupported_draft"],
                "resource_type": "file",
                "resource_scope": "invalid",
                "canonical_resource": ".ENV",
                "input_schema": {
                    "$schema": "https://unknown.example/custom-dialect",
                    "type": "object",
                },
            }
        )
        serialized = json.dumps(summary, sort_keys=True)

        self.assertNotIn(".ENV", serialized)
        self.assertNotIn("SECRETS/api.txt", serialized)
        self.assertNotIn("ID_RSA", serialized)
        self.assertNotIn("unknown.example", serialized)
        self.assertNotIn("custom-dialect", serialized)
        self.assertNotIn('"$schema"', serialized)
        self.assertNotIn('"type": "object"', serialized)
        self.assertIn(
            "input_schema_unsupported_draft",
            summary["validation_error_codes"],
        )

    def test_string_values_and_tokens_are_not_logged(self) -> None:
        summary = summarize_arguments(
            {
                "arguments": {
                    "token": "super-secret-value",
                    "query": "hello",
                    "count": 1,
                    "enabled": True,
                },
                "arguments_valid": True,
                "validation_error_codes": [],
                "resource_type": "unknown",
                "resource_scope": "unknown",
                "input_schema": {"type": "object"},
            }
        )
        serialized = json.dumps(summary, sort_keys=True)

        self.assertNotIn("super-secret-value", serialized)
        self.assertNotIn("hello", serialized)
        self.assertNotIn("input_schema", serialized)
        self.assertEqual(summary["argument_types"]["token"], "string")
        self.assertEqual(summary["argument_types"]["count"], "number")
        self.assertEqual(summary["argument_types"]["enabled"], "boolean")

    def test_codes_and_names_are_limited_and_sanitized(self) -> None:
        summary = summarize_arguments(
            {
                "arguments": {f"bad/name/{index}": "value" for index in range(30)},
                "arguments_valid": False,
                "validation_error_codes": ["bad code with spaces" for _ in range(30)],
                "resource_type": "file",
                "resource_scope": "invalid",
            }
        )

        self.assertLessEqual(len(summary["argument_names"]), 20)
        self.assertLessEqual(len(summary["validation_error_codes"]), 20)
        self.assertEqual(summary["validation_error_codes"], ["bad_code_with_spaces"])
        self.assertTrue(all("/" not in name for name in summary["argument_names"]))



    def test_runtime_timings_are_internal_bounded_and_do_not_log_markers(self) -> None:
        tool_call = {
            "agent_id": "agent-demo",
            "session_id": "session-demo",
            "tool_name": "list_files",
            "arguments": {},
            "arguments_valid": True,
            "_runtime_started_monotonic": time.perf_counter() - 0.01,
            "_runtime_policy_duration_ms": 2.34567,
            "_runtime_upstream_duration_ms": 5.67891,
            "_runtime_result_guard_duration_ms": 1.23456,
        }
        payload = build_runtime_log(
            tool_call,
            {"decision": "ALLOW", "rule_id": "allow"},
            executed=True,
            execution_status="success",
        )
        serialized = json.dumps(payload, sort_keys=True)

        self.assertGreaterEqual(payload["total_duration_ms"], 0)
        self.assertEqual(payload["policy_duration_ms"], 2.346)
        self.assertEqual(payload["upstream_duration_ms"], 5.679)
        self.assertEqual(payload["result_guard_duration_ms"], 1.235)
        self.assertNotIn("_runtime_", serialized)

    def test_invalid_or_untrusted_timing_shapes_are_ignored(self) -> None:
        payload = build_runtime_log(
            {
                "tool_name": "list_files",
                "arguments": {},
                "_runtime_started_monotonic": "spoofed",
                "_runtime_policy_duration_ms": -1,
                "_runtime_upstream_duration_ms": float("inf"),
                "_runtime_result_guard_duration_ms": True,
            },
            {"decision": "BLOCK"},
            executed=False,
            execution_status="blocked",
        )
        self.assertIsNone(payload["total_duration_ms"])
        self.assertIsNone(payload["policy_duration_ms"])
        self.assertIsNone(payload["upstream_duration_ms"])
        self.assertIsNone(payload["result_guard_duration_ms"])


if __name__ == "__main__":
    unittest.main()
