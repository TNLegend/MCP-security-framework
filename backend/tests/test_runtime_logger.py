import json
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND_DIR = REPO_ROOT / "backend"

sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(BACKEND_DIR))

from proxy.runtime_logger import summarize_arguments  # noqa: E402


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


if __name__ == "__main__":
    unittest.main()
