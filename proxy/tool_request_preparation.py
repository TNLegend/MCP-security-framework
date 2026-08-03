from dataclasses import dataclass
from functools import lru_cache
import json
import re
from typing import Any

from jsonschema import Draft7Validator, Draft202012Validator
from jsonschema.exceptions import SchemaError

from proxy.resource_adapters import (
    ResourceResolution,
    resolve_resource,
)
from proxy.resource_registry import ResourceRegistry
from proxy.tool_security_profiles import ResolvedToolSecurityProfile


MAX_SCHEMA_BYTES = 262_144
MAX_ARGUMENTS_BYTES = 262_144
MAX_VALIDATION_ERRORS = 20
MAX_ERROR_CODE_LENGTH = 128
MAX_PATH_LENGTH = 4096
MAX_PATH_SEGMENTS = 256
MAX_SCHEMA_DEPTH = 64
MAX_SCHEMA_NODES = 10_000

SAFE_CODE_PATTERN = re.compile(r"[^a-zA-Z0-9_\-.$:]")
WINDOWS_DRIVE_PATTERN = re.compile(r"^[a-zA-Z]:[\\/]")
SENSITIVE_PATH_PATTERNS = (
    ".env",
    ".aws/credentials",
    "/etc/passwd",
    "id_rsa",
    "secrets",
)
SENSITIVE_PATH_PATTERNS_LOWER = tuple(
    pattern.lower()
    for pattern in SENSITIVE_PATH_PATTERNS
)
SUPPORTED_JSON_SCHEMA_VALIDATORS = {
    "https://json-schema.org/draft/2020-12/schema": Draft202012Validator,
    "https://json-schema.org/draft/2020-12/schema#": Draft202012Validator,
    "http://json-schema.org/draft-07/schema": Draft7Validator,
    "http://json-schema.org/draft-07/schema#": Draft7Validator,
    "https://json-schema.org/draft-07/schema": Draft7Validator,
    "https://json-schema.org/draft-07/schema#": Draft7Validator,
}


@dataclass(frozen=True)
class PreparedToolRequest:
    arguments: dict[str, Any]
    arguments_valid: bool
    validation_error_codes: tuple[str, ...]
    operation: str
    required_capability: str
    resource_adapter: str
    resource_type: str
    resource_scope: str
    canonical_resource: str | None
    resource_sensitivity: str
    resource_resolution_status: str
    resource_flags: tuple[str, ...]
    resource_registry_revision: str
    tool_profile_revision: str
    operation_allowed_on_scope: bool
    execution_arguments: dict[str, Any]
    resource_resolution: ResourceResolution | None = None


def prepare_tool_request(
    *,
    tool_name: str,
    raw_arguments: Any,
    input_schema: Any,
    tool_profile: ResolvedToolSecurityProfile | None = None,
    resource_registry: ResourceRegistry | None = None,
) -> PreparedToolRequest:
    arguments = {} if raw_arguments is None else raw_arguments
    base_operation, base_resource_type = _resource_kind_for_tool(
        tool_name,
        tool_profile,
    )
    required_capability = _required_capability_for_tool(tool_name, tool_profile)

    if not isinstance(arguments, dict):
        return _invalid_result(
            ("arguments_not_object",),
            operation=base_operation,
            resource_type=base_resource_type,
            required_capability=required_capability,
            tool_profile=tool_profile,
            resource_registry=resource_registry,
        )

    try:
        canonical_arguments_json = _canonical_json(arguments)
    except (TypeError, ValueError, RecursionError):
        return _invalid_result(
            ("arguments_not_json_serializable",),
            operation=base_operation,
            resource_type=base_resource_type,
            required_capability=required_capability,
            tool_profile=tool_profile,
            resource_registry=resource_registry,
        )

    if len(canonical_arguments_json.encode("utf-8")) > MAX_ARGUMENTS_BYTES:
        return _invalid_result(
            ("arguments_too_large",),
            operation=base_operation,
            resource_type=base_resource_type,
            required_capability=required_capability,
            tool_profile=tool_profile,
            resource_registry=resource_registry,
        )

    schema_errors, canonical_schema_json = _validate_input_schema(input_schema)
    if schema_errors:
        return _invalid_result(
            schema_errors,
            operation=base_operation,
            resource_type=base_resource_type,
            required_capability=required_capability,
            tool_profile=tool_profile,
            resource_registry=resource_registry,
        )

    validator = _compile_validator(canonical_schema_json)
    validation_codes = _validation_error_codes(validator.iter_errors(arguments))
    if validation_codes:
        return _invalid_result(
            validation_codes,
            operation=base_operation,
            resource_type=base_resource_type,
            required_capability=required_capability,
            tool_profile=tool_profile,
            resource_registry=resource_registry,
        )

    if tool_profile is not None and resource_registry is not None:
        resolution = resolve_resource(
            profile=tool_profile,
            arguments=dict(arguments),
            registry=resource_registry,
        )
        return PreparedToolRequest(
            arguments=dict(arguments) if resolution.resource_resolution_status == "resolved" else {},
            arguments_valid=True,
            validation_error_codes=(),
            operation=resolution.operation,
            required_capability=resolution.required_capability,
            resource_adapter=resolution.resource_adapter,
            resource_type=resolution.resource_type,
            resource_scope=resolution.resource_scope,
            canonical_resource=resolution.canonical_resource,
            resource_sensitivity=resolution.resource_sensitivity,
            resource_resolution_status=resolution.resource_resolution_status,
            resource_flags=resolution.resource_flags,
            resource_registry_revision=resolution.resource_registry_revision,
            tool_profile_revision=resolution.tool_profile_revision,
            operation_allowed_on_scope=resolution.operation_allowed_on_scope,
            execution_arguments=resolution.execution_arguments,
            resource_resolution=resolution,
        )

    if tool_name == "list_files":
        return PreparedToolRequest(
            arguments={},
            arguments_valid=True,
            validation_error_codes=(),
            operation="list",
            required_capability=required_capability,
            resource_adapter="filesystem",
            resource_type="directory",
            resource_scope="lab_root",
            canonical_resource=".",
            resource_sensitivity="internal",
            resource_resolution_status="resolved",
            resource_flags=(),
            resource_registry_revision="lab-default",
            tool_profile_revision="lab-default",
            operation_allowed_on_scope=True,
            execution_arguments={},
        )

    if tool_name == "read_file":
        canonical_resource, path_errors = _normalize_lab_relative_path(
            arguments.get("path")
        )
        if path_errors:
            return _invalid_result(
                path_errors,
                operation="read",
                resource_type="file",
                required_capability=required_capability,
                tool_profile=tool_profile,
                resource_registry=resource_registry,
            )

        normalized_arguments = dict(arguments)
        normalized_arguments["path"] = canonical_resource
        return PreparedToolRequest(
            arguments=normalized_arguments,
            arguments_valid=True,
            validation_error_codes=(),
            operation="read",
            required_capability=required_capability,
            resource_adapter="filesystem",
            resource_type="file",
            resource_scope=_resource_scope_for_path(canonical_resource),
            canonical_resource=canonical_resource,
            resource_sensitivity=(
                "secret"
                if _resource_scope_for_path(canonical_resource) == "sensitive"
                else "internal"
            ),
            resource_resolution_status="resolved",
            resource_flags=(),
            resource_registry_revision="lab-default",
            tool_profile_revision="lab-default",
            operation_allowed_on_scope=True,
            execution_arguments=normalized_arguments,
        )

    return PreparedToolRequest(
        arguments=dict(arguments),
        arguments_valid=True,
        validation_error_codes=(),
        operation="unknown",
        required_capability=required_capability,
        resource_adapter="unknown",
        resource_type="unknown",
        resource_scope="unknown",
        canonical_resource=None,
        resource_sensitivity="unknown",
        resource_resolution_status="unresolved",
        resource_flags=(),
        resource_registry_revision="unknown",
        tool_profile_revision="unknown",
        operation_allowed_on_scope=False,
        execution_arguments=dict(arguments),
    )


def _resource_kind_for_tool(
    tool_name: str,
    tool_profile: ResolvedToolSecurityProfile | None = None,
) -> tuple[str, str]:
    if tool_profile is not None:
        return tool_profile.operation, f"{tool_profile.resource.adapter}.{tool_profile.resource.expected_type}"
    if tool_name == "read_file":
        return "read", "file"
    if tool_name == "list_files":
        return "list", "directory"
    return "unknown", "unknown"


def _required_capability_for_tool(
    tool_name: str,
    tool_profile: ResolvedToolSecurityProfile | None = None,
) -> str:
    if tool_profile is not None:
        return tool_profile.required_capability
    if tool_name == "read_file":
        return "filesystem.read"
    if tool_name == "list_files":
        return "filesystem.list"
    return "unclassified"


def _invalid_result(
    error_codes: tuple[str, ...] | list[str],
    *,
    operation: str,
    resource_type: str,
    required_capability: str,
    tool_profile: ResolvedToolSecurityProfile | None = None,
    resource_registry: ResourceRegistry | None = None,
) -> PreparedToolRequest:
    return PreparedToolRequest(
        arguments={},
        arguments_valid=False,
        validation_error_codes=_sanitize_error_codes(error_codes),
        operation=operation,
        required_capability=required_capability,
        resource_adapter=(
            tool_profile.resource.adapter if tool_profile is not None else "unknown"
        ),
        resource_type=resource_type,
        resource_scope="invalid",
        canonical_resource=None,
        resource_sensitivity="unknown",
        resource_resolution_status="invalid_arguments",
        resource_flags=(),
        resource_registry_revision=(
            resource_registry.revision if resource_registry is not None else "unknown"
        ),
        tool_profile_revision=(
            tool_profile.revision if tool_profile is not None else "unknown"
        ),
        operation_allowed_on_scope=False,
        execution_arguments={},
    )


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _validate_input_schema(input_schema: Any) -> tuple[tuple[str, ...], str]:
    if input_schema is None:
        return ("input_schema_missing",), ""

    if not isinstance(input_schema, dict):
        return ("input_schema_not_object",), ""

    try:
        canonical_schema_json = _canonical_json(input_schema)
    except (TypeError, ValueError, RecursionError):
        return ("input_schema_not_json_serializable",), ""

    if len(canonical_schema_json.encode("utf-8")) > MAX_SCHEMA_BYTES:
        return ("input_schema_too_large",), ""

    schema_ref_errors = _validate_schema_references_and_limits(input_schema)
    if schema_ref_errors:
        return schema_ref_errors, ""

    try:
        validator_class = _select_validator_class(input_schema)
        validator_class.check_schema(input_schema)
    except SchemaError:
        return ("input_schema_invalid",), ""
    except ValueError:
        return ("input_schema_unsupported_draft",), ""

    return (), canonical_schema_json


def _select_validator_class(schema: dict[str, Any]):
    if "$schema" not in schema:
        return Draft202012Validator

    schema_uri = schema["$schema"]
    if not isinstance(schema_uri, str):
        raise ValueError("Unsupported JSON Schema draft.")

    validator_class = SUPPORTED_JSON_SCHEMA_VALIDATORS.get(schema_uri)
    if validator_class is None:
        raise ValueError("Unsupported JSON Schema draft.")

    return validator_class


def _validate_schema_references_and_limits(schema: Any) -> tuple[str, ...]:
    stack = [(schema, 0)]
    nodes = 0

    while stack:
        value, depth = stack.pop()
        nodes += 1
        if nodes > MAX_SCHEMA_NODES:
            return ("input_schema_too_complex",)
        if depth > MAX_SCHEMA_DEPTH:
            return ("input_schema_too_deep",)

        if isinstance(value, dict):
            for key, child in value.items():
                if key in {"$ref", "$dynamicRef"} and isinstance(child, str):
                    if not _is_local_json_schema_ref(child):
                        return ("input_schema_external_ref",)
                stack.append((child, depth + 1))
        elif isinstance(value, list):
            for item in value:
                stack.append((item, depth + 1))

    return ()


def _is_local_json_schema_ref(ref: str) -> bool:
    return ref == "#" or ref.startswith("#/definitions/") or ref.startswith("#/$defs/")


@lru_cache(maxsize=128)
def _compile_validator(canonical_schema_json: str):
    schema = json.loads(canonical_schema_json)
    validator_class = _select_validator_class(schema)
    validator_class.check_schema(schema)
    return validator_class(schema)


def _validation_error_codes(errors: Any) -> tuple[str, ...]:
    sorted_errors = sorted(
        errors,
        key=lambda error: (
            ".".join(str(part) for part in error.path),
            str(error.validator),
        ),
    )
    codes = []
    for error in sorted_errors[:MAX_VALIDATION_ERRORS]:
        keyword = str(error.validator)
        path = _error_path(error)
        if keyword == "required":
            missing = _missing_required_property(error)
            codes.append(f"missing_required:{missing}")
        elif keyword == "additionalProperties":
            extra = _additional_property(error)
            codes.append(f"unexpected_argument:{extra}")
        elif keyword == "type":
            codes.append(f"invalid_type:{path}")
        elif keyword == "enum":
            codes.append(f"invalid_enum:{path}")
        elif keyword == "minimum":
            codes.append(f"below_minimum:{path}")
        elif keyword == "maximum":
            codes.append(f"above_maximum:{path}")
        elif keyword == "minLength":
            codes.append(f"too_short:{path}")
        elif keyword == "maxLength":
            codes.append(f"too_long:{path}")
        elif keyword == "pattern":
            codes.append(f"pattern_mismatch:{path}")
        elif keyword == "minItems":
            codes.append(f"too_few_items:{path}")
        elif keyword == "maxItems":
            codes.append(f"too_many_items:{path}")
        else:
            codes.append(f"schema_constraint_failed:{keyword}:{path}")

    return _sanitize_error_codes(codes)


def _error_path(error: Any) -> str:
    parts = [str(part) for part in error.path]
    if not parts:
        return "$"
    return ".".join(_sanitize_code_part(part) for part in parts)


def _missing_required_property(error: Any) -> str:
    validator_value = getattr(error, "validator_value", None)
    if isinstance(validator_value, list):
        instance = getattr(error, "instance", None)
        if isinstance(instance, dict):
            for required_property in validator_value:
                if required_property not in instance:
                    return _sanitize_code_part(str(required_property))
        if validator_value:
            return _sanitize_code_part(str(validator_value[0]))
    return _error_path(error)


def _additional_property(error: Any) -> str:
    message = str(getattr(error, "message", ""))
    match = re.search(r"'([^']+)'", message)
    if match:
        return _sanitize_code_part(match.group(1))
    return _error_path(error)


def _sanitize_error_codes(codes: tuple[str, ...] | list[str]) -> tuple[str, ...]:
    sanitized = []
    seen = set()
    for code in codes:
        safe_code = SAFE_CODE_PATTERN.sub("_", str(code))[:MAX_ERROR_CODE_LENGTH]
        if safe_code and safe_code not in seen:
            sanitized.append(safe_code)
            seen.add(safe_code)
        if len(sanitized) >= MAX_VALIDATION_ERRORS:
            break
    return tuple(sanitized)


def _sanitize_code_part(value: str) -> str:
    return SAFE_CODE_PATTERN.sub("_", value)[:MAX_ERROR_CODE_LENGTH] or "$"


def _normalize_lab_relative_path(
    raw_path: Any,
) -> tuple[str | None, tuple[str, ...]]:
    if not isinstance(raw_path, str):
        return None, ("invalid_type:path",)

    if raw_path == "":
        return None, ("path_empty",)

    if raw_path.strip() == "":
        return None, ("path_empty",)

    if raw_path != raw_path.strip():
        return None, ("path_surrounding_whitespace",)

    if "\x00" in raw_path:
        return None, ("path_null_byte",)

    if any(ord(character) < 32 for character in raw_path):
        return None, ("path_control_character",)

    if len(raw_path) > MAX_PATH_LENGTH:
        return None, ("path_too_long",)

    if WINDOWS_DRIVE_PATTERN.match(raw_path):
        return None, ("path_windows_drive",)

    if raw_path.startswith("\\\\") or raw_path.startswith("//"):
        return None, ("path_unc",)

    normalized = raw_path.replace("\\", "/")

    if normalized.startswith("/"):
        return None, ("path_absolute",)

    segments = []
    raw_segments = normalized.split("/")
    if len(raw_segments) > MAX_PATH_SEGMENTS:
        return None, ("path_too_many_segments",)

    for segment in raw_segments:
        if segment in {"", "."}:
            continue
        if ":" in segment:
            return None, ("path_forbidden_character",)
        if segment == "..":
            if not segments:
                return None, ("path_traversal_outside_root",)
            segments.pop()
            continue
        segments.append(segment)

    if len(segments) > MAX_PATH_SEGMENTS:
        return None, ("path_too_many_segments",)

    if not segments:
        return None, ("path_empty_after_normalization",)

    return "/".join(segments), ()


def _resource_scope_for_path(canonical_resource: str | None) -> str:
    if not canonical_resource:
        return "invalid"

    comparison_resource = canonical_resource.lower()
    if any(
        pattern in comparison_resource
        for pattern in SENSITIVE_PATH_PATTERNS_LOWER
    ):
        return "sensitive"

    if canonical_resource == "contracts" or canonical_resource.startswith("contracts/"):
        return "contracts"

    return "lab_root"
