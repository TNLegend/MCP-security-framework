from dataclasses import dataclass
from functools import lru_cache
import json
import re
from typing import Any

from jsonschema import Draft7Validator, Draft202012Validator
from jsonschema.exceptions import SchemaError

from common.canonical_json import canonical_json_bytes, sha256_canonical_json

from proxy.lab_tool_compat import (
    is_lab_directory_listing_tool,
    is_lab_file_read_tool,
    lab_tool_descriptor,
)
from proxy.resource_adapters import (
    ResourceResolution,
    resolve_resource,
)
from proxy.resource_registry import ResourceRegistry
from proxy.tool_security_profiles import ResolvedToolSecurityProfile
from proxy.resource_adapters_v2 import AdapterRegistry, resolve_effect_facts
from proxy.tool_security_v2 import (
    AdapterResolution,
    AuthorityResourceScope,
    NormalizedFacts,
    SecurityModelError,
    ToolObservationApproval,
    ToolSecurityContract,
    CapabilityCatalog,
    NormalizedEffectFacts,
    ReferencePrecision,
    validate_contract_for_schema,
)


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
    canonical_arguments_hash: str
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
    security_model_version: str = "1"
    normalized_facts: dict[str, Any] | None = None
    contract_hash: str | None = None
    tool_observation_approval: dict[str, Any] | None = None
    authority_resource_scopes: tuple[dict[str, Any], ...] = ()
    security_contract: dict[str, Any] | None = None
    capability_catalog: tuple[dict[str, Any], ...] = ()


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
    canonical_arguments_hash = sha256_canonical_json(arguments)

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
            canonical_arguments_hash=sha256_canonical_json(
                resolution.execution_arguments
            ),
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

    if is_lab_directory_listing_tool(tool_name):
        return PreparedToolRequest(
            arguments={},
            canonical_arguments_hash=EMPTY_ARGUMENTS_HASH,
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

    if is_lab_file_read_tool(tool_name):
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
            canonical_arguments_hash=sha256_canonical_json(normalized_arguments),
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
        canonical_arguments_hash=canonical_arguments_hash,
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


def prepare_tool_request_v2(
    *,
    raw_arguments: Any,
    input_schema: Any,
    contract: ToolSecurityContract,
    adapter_resolutions: tuple[AdapterResolution, ...],
    approval: ToolObservationApproval,
    authority_scopes: tuple[AuthorityResourceScope, ...],
    authority_context: dict[str, Any],
    client_protocol_profile_id: str,
    upstream_protocol_profile_id: str,
) -> PreparedToolRequest:
    arguments = {} if raw_arguments is None else raw_arguments
    if not isinstance(arguments, dict):
        return _invalid_v2(("arguments_not_object",), contract)
    try:
        canonical_arguments = canonical_json_bytes(arguments)
    except (TypeError, ValueError, RecursionError):
        return _invalid_v2(("arguments_not_json_serializable",), contract)
    if len(canonical_arguments) > MAX_ARGUMENTS_BYTES:
        return _invalid_v2(("arguments_too_large",), contract)
    if not isinstance(input_schema, dict):
        return _invalid_v2(("input_schema_not_object",), contract)

    try:
        derived_resolutions = validate_contract_for_schema(contract, input_schema)
    except (SecurityModelError, ValueError):
        return _invalid_v2(("contract_or_schema_invalid",), contract)
    if sorted(
        (value.effect_id, value.resource_type, value.adapter_id,
         value.adapter_api_version, value.implementation_version)
        for value in derived_resolutions
    ) != sorted(
        (value.effect_id, value.resource_type, value.adapter_id,
         value.adapter_api_version, value.implementation_version)
        for value in adapter_resolutions
    ):
        return _invalid_v2(("adapter_resolution_snapshot_mismatch",), contract)

    schema_errors, canonical_schema_json = _validate_input_schema(input_schema)
    if schema_errors:
        return _invalid_v2(schema_errors, contract)
    validator = _compile_validator(canonical_schema_json)
    validation_codes = _validation_error_codes(validator.iter_errors(arguments))
    if validation_codes:
        return _invalid_v2(validation_codes, contract)

    registry = AdapterRegistry()
    effect_facts = []
    errors: list[str] = []
    for effect in contract.effects:
        effect_resolutions = tuple(
            value for value in adapter_resolutions if value.effect_id == effect.effect_id
        )
        capability = CapabilityCatalog().get(effect.capability)
        if not capability.requires_resource and not effect.resource_bindings:
            effect_facts.append(
                NormalizedEffectFacts(
                    effect_id=effect.effect_id,
                    capability_id=effect.capability,
                    requires_resource=False,
                    adapter_id="none",
                    adapter_api_version="1",
                    declared_reference_precision=effect.declared_reference_precision,
                    runtime_reference_precision=ReferencePrecision.EXPLICIT,
                    effective_reference_precision=effect.declared_reference_precision,
                    max_resource_cardinality=effect.max_resource_cardinality,
                    bindings=(),
                )
            )
            continue
        if not effect_resolutions:
            errors.append("adapter_resolution_missing")
            continue
        adapter_keys = {
            (value.adapter_id, value.adapter_api_version, value.implementation_version)
            for value in effect_resolutions
        }
        if len(adapter_keys) != 1:
            errors.append("effect_adapter_resolution_ambiguous")
            continue
        resolution = effect_resolutions[0]
        try:
            facts = resolve_effect_facts(
                dict(arguments),
                effect,
                resolution,
                {
                    "authority": contract.server_ref,
                    "resource_type_config": authority_context,
                },
                registry=registry,
            )
            effect_facts.append(facts)
        except Exception as exc:
            errors.append(
                exc.code if isinstance(exc, SecurityModelError) else "adapter_resolution_failed"
            )

    canonical_hash = sha256_canonical_json(arguments)
    normalized = NormalizedFacts(
        request={
            "server_ref": contract.server_ref,
            "tool_name": contract.tool_name,
            "canonical_args_hash": canonical_hash,
            "client_protocol_profile_id": client_protocol_profile_id,
            "upstream_protocol_profile_id": upstream_protocol_profile_id,
        },
        effects=tuple(effect_facts),
        errors=tuple(errors),
    )
    first_effect = contract.effects[0]
    first_binding = first_effect.resource_bindings[0] if first_effect.resource_bindings else None
    first_facts = effect_facts[0] if effect_facts else None
    first_reference = (
        first_facts.bindings[0].references[0]
        if first_facts and first_facts.bindings and first_facts.bindings[0].references
        else None
    )
    return PreparedToolRequest(
        arguments=dict(arguments) if not errors else {},
        canonical_arguments_hash=canonical_hash if not errors else EMPTY_ARGUMENTS_HASH,
        arguments_valid=not errors,
        validation_error_codes=_sanitize_error_codes(errors),
        operation=first_effect.capability,
        required_capability=first_effect.capability,
        resource_adapter=first_facts.adapter_id if first_facts else "unknown",
        resource_type=first_binding.resource_type if first_binding else "none",
        resource_scope="v2_authority_scopes",
        canonical_resource=first_reference.canonical_value if first_reference else None,
        resource_sensitivity="governed",
        resource_resolution_status="resolved" if not errors else "invalid",
        resource_flags=(),
        resource_registry_revision="v2",
        tool_profile_revision=contract.contract_hash,
        operation_allowed_on_scope=False,
        execution_arguments=dict(arguments) if not errors else {},
        security_model_version="2",
        normalized_facts=normalized.model_dump(mode="json"),
        contract_hash=contract.contract_hash,
        tool_observation_approval=approval.model_dump(mode="json"),
        authority_resource_scopes=tuple(
            scope.model_dump(mode="json") for scope in authority_scopes
        ),
        security_contract=contract.model_dump(mode="json"),
        capability_catalog=tuple(CapabilityCatalog().as_policy_data()),
    )


def _invalid_v2(
    error_codes: tuple[str, ...] | list[str],
    contract: ToolSecurityContract,
) -> PreparedToolRequest:
    first = contract.effects[0]
    return PreparedToolRequest(
        arguments={},
        canonical_arguments_hash=EMPTY_ARGUMENTS_HASH,
        arguments_valid=False,
        validation_error_codes=_sanitize_error_codes(error_codes),
        operation=first.capability,
        required_capability=first.capability,
        resource_adapter="unknown",
        resource_type="unknown",
        resource_scope="invalid",
        canonical_resource=None,
        resource_sensitivity="unknown",
        resource_resolution_status="invalid_arguments",
        resource_flags=(),
        resource_registry_revision="v2",
        tool_profile_revision=contract.contract_hash,
        operation_allowed_on_scope=False,
        execution_arguments={},
        security_model_version="2",
        contract_hash=contract.contract_hash,
        security_contract=contract.model_dump(mode="json"),
        capability_catalog=tuple(CapabilityCatalog().as_policy_data()),
    )


def _resource_kind_for_tool(
    tool_name: str,
    tool_profile: ResolvedToolSecurityProfile | None = None,
) -> tuple[str, str]:
    if tool_profile is not None:
        return tool_profile.operation, f"{tool_profile.resource.adapter}.{tool_profile.resource.expected_type}"
    descriptor = lab_tool_descriptor(tool_name)
    if descriptor is not None:
        return descriptor.operation, descriptor.resource_type
    return "unknown", "unknown"


def _required_capability_for_tool(
    tool_name: str,
    tool_profile: ResolvedToolSecurityProfile | None = None,
) -> str:
    if tool_profile is not None:
        return tool_profile.required_capability
    descriptor = lab_tool_descriptor(tool_name)
    if descriptor is not None:
        return descriptor.required_capability
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
        canonical_arguments_hash=EMPTY_ARGUMENTS_HASH,
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
    return canonical_json_bytes(value).decode("utf-8")


EMPTY_ARGUMENTS_HASH = sha256_canonical_json({})


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
