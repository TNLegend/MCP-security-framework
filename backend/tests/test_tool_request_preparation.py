import sys
import unittest
from pathlib import Path
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND_DIR = REPO_ROOT / "backend"

sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(BACKEND_DIR))

from proxy.tool_request_preparation import (  # noqa: E402
    MAX_ARGUMENTS_BYTES,
    MAX_PATH_LENGTH,
    MAX_PATH_SEGMENTS,
    MAX_SCHEMA_BYTES,
    PreparedToolRequest,
    prepare_tool_request,
)


READ_FILE_SCHEMA = {
    "type": "object",
    "properties": {
        "path": {
            "type": "string",
            "minLength": 1,
            "maxLength": 4096,
        }
    },
    "required": ["path"],
    "additionalProperties": False,
}

READ_FILE_SCHEMA_WITHOUT_MAX_LENGTH = {
    "type": "object",
    "properties": {
        "path": {"type": "string"},
    },
    "required": ["path"],
    "additionalProperties": False,
}

LIST_FILES_SCHEMA = {
    "type": "object",
    "properties": {},
    "additionalProperties": False,
}

GENERIC_NESTED_SCHEMA = {
    "type": "object",
    "properties": {
        "database": {
            "type": "object",
            "properties": {
                "host": {"type": "string"},
            },
            "required": ["host"],
            "additionalProperties": False,
        }
    },
    "required": ["database"],
    "additionalProperties": False,
}

DRAFT_7_SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "properties": {"mode": {"enum": ["safe"]}},
    "required": ["mode"],
}

SUPPORTED_SCHEMA_URIS = (
    "https://json-schema.org/draft/2020-12/schema",
    "https://json-schema.org/draft/2020-12/schema#",
    "http://json-schema.org/draft-07/schema",
    "http://json-schema.org/draft-07/schema#",
    "https://json-schema.org/draft-07/schema",
    "https://json-schema.org/draft-07/schema#",
)


class ToolRequestPreparationTests(unittest.TestCase):
    def assert_invalid_code(
        self,
        result: PreparedToolRequest,
        code: str,
    ) -> None:
        self.assertFalse(result.arguments_valid)
        self.assertIn(code, result.validation_error_codes)
        self.assertEqual(result.arguments, {})
        self.assertIsNone(result.canonical_resource)
        self.assertEqual(result.resource_scope, "invalid")

    def test_none_arguments_for_parameterless_tool_are_valid(self) -> None:
        result = prepare_tool_request(
            tool_name="list_files",
            raw_arguments=None,
            input_schema=LIST_FILES_SCHEMA,
        )

        self.assertTrue(result.arguments_valid)
        self.assertEqual(result.arguments, {})
        self.assertEqual(result.operation, "list")
        self.assertEqual(result.resource_type, "directory")
        self.assertEqual(result.resource_scope, "lab_root")
        self.assertEqual(result.canonical_resource, ".")
        self.assertEqual(result.required_capability, "filesystem.list")

    def test_non_object_arguments_are_rejected(self) -> None:
        for raw_arguments in ([], "string", 123, True):
            with self.subTest(raw_arguments=raw_arguments):
                result = prepare_tool_request(
                    tool_name="read_file",
                    raw_arguments=raw_arguments,
                    input_schema=READ_FILE_SCHEMA,
                )
                self.assert_invalid_code(result, "arguments_not_object")
                self.assertEqual(result.required_capability, "filesystem.read")

    def test_schema_missing_non_object_invalid_unserializable_and_too_large(self) -> None:
        cases = [
            (None, "input_schema_missing"),
            ([], "input_schema_not_object"),
            ({"type": 123}, "input_schema_invalid"),
            ({"x": object()}, "input_schema_not_json_serializable"),
            ({"description": "x" * (MAX_SCHEMA_BYTES + 1)}, "input_schema_too_large"),
        ]
        for schema, expected_code in cases:
            with self.subTest(expected_code=expected_code):
                result = prepare_tool_request(
                    tool_name="read_file",
                    raw_arguments={"path": "contracts/contract1.txt"},
                    input_schema=schema,
                )
                self.assert_invalid_code(result, expected_code)

    def test_arguments_unserializable_and_too_large_are_rejected(self) -> None:
        cases = [
            ({"value": object()}, "arguments_not_json_serializable"),
            ({"value": "x" * (MAX_ARGUMENTS_BYTES + 1)}, "arguments_too_large"),
        ]
        for arguments, expected_code in cases:
            with self.subTest(expected_code=expected_code):
                result = prepare_tool_request(
                    tool_name="generic_tool",
                    raw_arguments=arguments,
                    input_schema={},
                )
                self.assert_invalid_code(result, expected_code)

    def test_external_refs_are_rejected_and_local_refs_are_allowed(self) -> None:
        for ref in (
            "https://example.com/schema.json",
            "http://example.com/schema.json",
            "file:///etc/passwd",
            "ftp://example.com/schema.json",
            "urn:example:schema",
            "C:\\schema.json",
        ):
            with self.subTest(ref=ref):
                result = prepare_tool_request(
                    tool_name="generic_tool",
                    raw_arguments={},
                    input_schema={"$ref": ref},
                )
                self.assert_invalid_code(result, "input_schema_external_ref")

        local_schema = {
            "$defs": {
                "path": {"type": "string"},
            },
            "type": "object",
            "properties": {"path": {"$ref": "#/$defs/path"}},
            "required": ["path"],
        }
        result = prepare_tool_request(
            tool_name="read_file",
            raw_arguments={"path": "contracts/contract1.txt"},
            input_schema=local_schema,
        )
        self.assertTrue(result.arguments_valid)

    def test_schema_depth_and_complexity_are_limited(self) -> None:
        too_deep = current = {}
        for _ in range(70):
            child = {}
            current["child"] = child
            current = child

        too_complex = {"items": [{} for _ in range(10_100)]}

        cases = [
            (too_deep, "input_schema_too_deep"),
            (too_complex, "input_schema_too_complex"),
        ]
        for schema, expected_code in cases:
            with self.subTest(expected_code=expected_code):
                result = prepare_tool_request(
                    tool_name="generic_tool",
                    raw_arguments={},
                    input_schema=schema,
                )
                self.assert_invalid_code(result, expected_code)

    def test_default_draft_202012_and_explicit_draft7_work(self) -> None:
        default_result = prepare_tool_request(
            tool_name="generic_tool",
            raw_arguments={},
            input_schema={},
        )
        draft7_result = prepare_tool_request(
            tool_name="generic_tool",
            raw_arguments={"mode": "safe"},
            input_schema=DRAFT_7_SCHEMA,
        )

        self.assertTrue(default_result.arguments_valid)
        self.assertTrue(draft7_result.arguments_valid)

    def test_supported_json_schema_dialects_are_accepted(self) -> None:
        for schema_uri in SUPPORTED_SCHEMA_URIS:
            with self.subTest(schema_uri=schema_uri):
                result = prepare_tool_request(
                    tool_name="generic_tool",
                    raw_arguments={},
                    input_schema={
                        "$schema": schema_uri,
                        "type": "object",
                        "properties": {},
                        "additionalProperties": False,
                    },
                )

                self.assertTrue(result.arguments_valid)

    def test_missing_schema_uri_uses_draft_202012(self) -> None:
        result = prepare_tool_request(
            tool_name="generic_tool",
            raw_arguments={"value": "ok"},
            input_schema={
                "type": "object",
                "properties": {"value": {"type": "string"}},
                "required": ["value"],
                "additionalProperties": False,
            },
        )

        self.assertTrue(result.arguments_valid)

    def test_unknown_and_non_string_schema_dialects_are_rejected(self) -> None:
        cases = [
            "https://unknown.example/custom-dialect",
            "https://json-schema.org.evil.example/draft/2020-12/schema",
            None,
            123,
            {},
            [],
            "https://json-schema.org/draft/2020-12/schema extra",
        ]
        for schema_uri in cases:
            with self.subTest(schema_uri=schema_uri):
                result = prepare_tool_request(
                    tool_name="generic_tool",
                    raw_arguments={},
                    input_schema={
                        "$schema": schema_uri,
                        "type": "object",
                        "properties": {},
                        "additionalProperties": False,
                    },
                )

                self.assert_invalid_code(result, "input_schema_unsupported_draft")
                joined = " ".join(result.validation_error_codes)
                self.assertNotIn("unknown.example", joined)
                self.assertNotIn("json-schema.org.evil.example", joined)

    def test_schema_dialect_selection_does_not_access_network_or_filesystem(self) -> None:
        with patch("urllib.request.urlopen", side_effect=AssertionError("network")):
            with patch("pathlib.Path.open", side_effect=AssertionError("filesystem")):
                result = prepare_tool_request(
                    tool_name="generic_tool",
                    raw_arguments={},
                    input_schema={
                        "$schema": "https://json-schema.org/draft/2020-12/schema",
                        "type": "object",
                        "properties": {},
                        "additionalProperties": False,
                    },
                )

        self.assertTrue(result.arguments_valid)

    def test_json_schema_error_codes_are_safe_and_deterministic(self) -> None:
        schema = {
            "type": "object",
            "properties": {
                "path": {"type": "string", "minLength": 2, "maxLength": 3},
                "mode": {"enum": ["safe"]},
                "count": {"type": "number", "minimum": 1, "maximum": 3},
                "items": {"type": "array", "minItems": 2, "maxItems": 3},
                "name": {"type": "string", "pattern": "^[a-z]+$"},
            },
            "required": ["path"],
            "additionalProperties": False,
        }
        checks = [
            ({}, "missing_required:path"),
            ({"path": None}, "invalid_type:path"),
            ({"path": "a"}, "too_short:path"),
            ({"path": "abcd"}, "too_long:path"),
            ({"path": "abc", "admin": True}, "unexpected_argument:admin"),
            ({"path": "abc", "mode": "unsafe"}, "invalid_enum:mode"),
            ({"path": "abc", "count": 0}, "below_minimum:count"),
            ({"path": "abc", "count": 4}, "above_maximum:count"),
            ({"path": "abc", "items": [1]}, "too_few_items:items"),
            ({"path": "abc", "items": [1, 2, 3, 4]}, "too_many_items:items"),
            ({"path": "abc", "name": "ABC"}, "pattern_mismatch:name"),
        ]
        for arguments, expected_code in checks:
            with self.subTest(expected_code=expected_code):
                result = prepare_tool_request(
                    tool_name="generic_tool",
                    raw_arguments=arguments,
                    input_schema=schema,
                )
                self.assert_invalid_code(result, expected_code)

    def test_nested_schema_paths_are_safe(self) -> None:
        valid = prepare_tool_request(
            tool_name="generic_tool",
            raw_arguments={"database": {"host": "localhost"}},
            input_schema=GENERIC_NESTED_SCHEMA,
        )
        invalid = prepare_tool_request(
            tool_name="generic_tool",
            raw_arguments={"database": {"host": 123}},
            input_schema=GENERIC_NESTED_SCHEMA,
        )

        self.assertTrue(valid.arguments_valid)
        self.assert_invalid_code(invalid, "invalid_type:database.host")

    def test_multiple_errors_are_limited_sanitized_and_value_free(self) -> None:
        schema = {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        }
        arguments = {f"secret-{index}": "super-secret-value" for index in range(40)}

        result = prepare_tool_request(
            tool_name="generic_tool",
            raw_arguments=arguments,
            input_schema=schema,
        )

        self.assertFalse(result.arguments_valid)
        self.assertLessEqual(len(result.validation_error_codes), 20)
        self.assertEqual(
            result.validation_error_codes,
            tuple(dict.fromkeys(result.validation_error_codes)),
        )
        joined = " ".join(result.validation_error_codes)
        self.assertNotIn("super-secret-value", joined)

    def test_valid_path_normalization(self) -> None:
        cases = [
            ("contracts/contract1.txt", "contracts/contract1.txt", "contracts"),
            ("contracts/./contract1.txt", "contracts/contract1.txt", "contracts"),
            ("contracts\\contract1.txt", "contracts/contract1.txt", "contracts"),
            ("contracts//contract1.txt", "contracts/contract1.txt", "contracts"),
            ("contracts/../.env", ".env", "sensitive"),
            ("contracts/subfolder/../../.env", ".env", "sensitive"),
            (".ENV", ".ENV", "sensitive"),
            (".Env", ".Env", "sensitive"),
            ("contracts/../.ENV", ".ENV", "sensitive"),
            ("SECRETS/api.txt", "SECRETS/api.txt", "sensitive"),
            ("Secrets/api.txt", "Secrets/api.txt", "sensitive"),
            ("folder/ID_RSA", "folder/ID_RSA", "sensitive"),
            (".AWS/CREDENTIALS", ".AWS/CREDENTIALS", "sensitive"),
            ("environment.txt", "environment.txt", "lab_root"),
            ("CONTRACTS/contract1.txt", "CONTRACTS/contract1.txt", "lab_root"),
        ]
        for raw_path, canonical, scope in cases:
            with self.subTest(raw_path=raw_path):
                result = prepare_tool_request(
                    tool_name="read_file",
                    raw_arguments={"path": raw_path},
                    input_schema=READ_FILE_SCHEMA,
                )
                self.assertTrue(result.arguments_valid)
                self.assertEqual(result.canonical_resource, canonical)
                self.assertEqual(result.arguments["path"], canonical)
                self.assertEqual(result.resource_scope, scope)

    def test_invalid_path_normalization(self) -> None:
        cases = [
            ("../../.env", "path_traversal_outside_root"),
            ("../contract.txt", "path_traversal_outside_root"),
            ("/etc/passwd", "path_absolute"),
            ("C:\\Windows\\file.txt", "path_windows_drive"),
            ("\\\\server\\share\\file.txt", "path_unc"),
            ("", "path_empty"),
            ("   ", "path_empty"),
            (" contracts/contract1.txt", "path_surrounding_whitespace"),
            ("contracts/contract1.txt ", "path_surrounding_whitespace"),
            ("contracts/\x00file.txt", "path_null_byte"),
            ("contracts/\nfile.txt", "path_control_character"),
            ("a" * (MAX_PATH_LENGTH + 1), "path_too_long"),
            ("a/" * (MAX_PATH_SEGMENTS + 1) + "file.txt", "path_too_many_segments"),
            ("contracts/file:ads.txt", "path_forbidden_character"),
            (".", "path_empty_after_normalization"),
        ]
        for raw_path, expected_code in cases:
            with self.subTest(raw_path=raw_path):
                result = prepare_tool_request(
                    tool_name="read_file",
                    raw_arguments={"path": raw_path},
                    input_schema=READ_FILE_SCHEMA_WITHOUT_MAX_LENGTH,
                )
                self.assert_invalid_code(result, expected_code)

    def test_list_files_rejects_extra_arguments(self) -> None:
        result = prepare_tool_request(
            tool_name="list_files",
            raw_arguments={"admin": True},
            input_schema=LIST_FILES_SCHEMA,
        )

        self.assert_invalid_code(result, "unexpected_argument:admin")

    def test_generic_tool_validates_schema_and_preserves_arguments(self) -> None:
        result = prepare_tool_request(
            tool_name="generic_tool",
            raw_arguments={"query": "status"},
            input_schema={
                "type": "object",
                "properties": {"query": {"type": "string"}},
                "required": ["query"],
            },
        )

        self.assertTrue(result.arguments_valid)
        self.assertEqual(result.operation, "unknown")
        self.assertEqual(result.resource_type, "unknown")
        self.assertEqual(result.resource_scope, "unknown")
        self.assertEqual(result.required_capability, "unclassified")
        self.assertIsNone(result.canonical_resource)
        self.assertEqual(result.arguments, {"query": "status"})

    def test_read_file_required_capability_is_filesystem_read(self) -> None:
        result = prepare_tool_request(
            tool_name="read_file",
            raw_arguments={"path": "contracts/contract1.txt"},
            input_schema=READ_FILE_SCHEMA,
        )

        self.assertEqual(result.required_capability, "filesystem.read")

    def test_invalid_read_file_keeps_filesystem_read_capability(self) -> None:
        result = prepare_tool_request(
            tool_name="read_file",
            raw_arguments={"path": 123},
            input_schema=READ_FILE_SCHEMA,
        )

        self.assertFalse(result.arguments_valid)
        self.assertEqual(result.required_capability, "filesystem.read")

    def test_list_files_required_capability_is_filesystem_list(self) -> None:
        result = prepare_tool_request(
            tool_name="list_files",
            raw_arguments={},
            input_schema=LIST_FILES_SCHEMA,
        )

        self.assertEqual(result.required_capability, "filesystem.list")

    def test_generic_tool_required_capability_is_unclassified(self) -> None:
        result = prepare_tool_request(
            tool_name="generic_tool",
            raw_arguments={},
            input_schema={},
        )

        self.assertEqual(result.required_capability, "unclassified")


if __name__ == "__main__":
    unittest.main()
