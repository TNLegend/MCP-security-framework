from dataclasses import dataclass
from functools import lru_cache
import json
import re
from typing import Any

from jsonschema import Draft7Validator, Draft202012Validator
from jsonschema.exceptions import SchemaError

from common.canonical_json import canonical_json_bytes, sha256_canonical_json

from proxy.resource_adapters_v2 import (
    AdapterRegistry,
    extract_values_at_path,
    resolve_effect_facts,
)
from proxy.security_packs import SecurityPackManifest
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
    ResourceTypeRegistry,
    validate_contract_for_schema,
    compile_executable_contract_schema,
    security_schema_projection,
    constrain_effect_selectors,
)
from proxy.schema_bounds import SchemaBoundsError, apply_schema_bounds


MAX_SCHEMA_BYTES = 262_144
MAX_ARGUMENTS_BYTES = 262_144
MAX_VALIDATION_ERRORS = 20
MAX_ERROR_CODE_LENGTH = 128
MAX_SCHEMA_DEPTH = 64
MAX_SCHEMA_NODES = 10_000

SAFE_CODE_PATTERN = re.compile(r"[^a-zA-Z0-9_\-.$:]")
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
    security_model_version: str = "2"
    normalized_facts: dict[str, Any] | None = None
    contract_hash: str | None = None
    tool_observation_approval: dict[str, Any] | None = None
    authority_resource_scopes: tuple[dict[str, Any], ...] = ()
    security_contract: dict[str, Any] | None = None
    capability_catalog: tuple[dict[str, Any], ...] = ()
    adapter_resolutions: tuple[dict[str, Any], ...] = ()


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
    capability_catalog_version: str = "2",
    resource_type_registry_version: str = "2",
    security_packs: tuple[SecurityPackManifest, ...] = (),
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
    # Use the same restrictive security projection at contract creation and
    # execution. The upstream original remains unchanged for fingerprinting.
    try:
        input_schema = security_schema_projection(input_schema)
    except (SecurityModelError, SchemaBoundsError):
        return _invalid_v2(("input_schema_projection_invalid",), contract)

    capability_catalog = CapabilityCatalog(
        version=capability_catalog_version,
        security_packs=security_packs,
    )
    resource_type_registry = ResourceTypeRegistry(
        version=resource_type_registry_version,
        security_packs=security_packs,
    )
    registry = AdapterRegistry(
        capability_catalog_version=capability_catalog_version,
        resource_type_registry_version=resource_type_registry_version,
        security_packs=security_packs,
    )
    try:
        input_schema, derived_resolutions = compile_executable_contract_schema(
            contract,
            input_schema,
            capability_catalog=capability_catalog,
            resource_type_registry=resource_type_registry,
            adapter_resolver=registry,
        )
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

    constraint_errors = _argument_constraint_errors(
        arguments,
        contract.argument_constraints,
    )
    if constraint_errors:
        return _invalid_v2(constraint_errors, contract)

    effect_facts = []
    errors: list[str] = []
    for effect in contract.effects:
        effect_resolutions = tuple(
            value for value in adapter_resolutions if value.effect_id == effect.effect_id
        )
        capability = capability_catalog.get(effect.capability)
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
    request_flags, request_sensitivity = _v2_request_sensitivity(effect_facts)
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
        canonical_resource=(
            first_reference.canonical_value
            if first_reference is not None and not errors
            else None
        ),
        resource_sensitivity=request_sensitivity,
        resource_resolution_status="resolved" if not errors else "invalid",
        resource_flags=request_flags,
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
        capability_catalog=tuple(capability_catalog.as_policy_data()),
        adapter_resolutions=tuple(
            resolution.model_dump(mode="json") for resolution in adapter_resolutions
        ),
    )


def _constraint_values_equal(actual: Any, expected: Any) -> bool:
    if isinstance(expected, bool):
        return isinstance(actual, bool) and actual is expected
    if isinstance(expected, str):
        return isinstance(actual, str) and actual == expected
    if isinstance(expected, (int, float)) and not isinstance(expected, bool):
        return (
            isinstance(actual, (int, float))
            and not isinstance(actual, bool)
            and actual == expected
        )
    return False


def _argument_constraint_errors(arguments, constraints) -> tuple[str, ...]:
    errors: list[str] = []
    for constraint in constraints:
        values, status = extract_values_at_path(arguments, constraint.path)
        safe_id = SAFE_CODE_PATTERN.sub("_", constraint.constraint_id)[:80]
        if status == "missing":
            if constraint.required:
                errors.append(f"argument_constraint_missing:{safe_id}")
            continue
        if status != "resolved":
            errors.append(f"argument_constraint_invalid:{safe_id}")
            continue

        if constraint.operator == "MAX_OCCURRENCES":
            if len(values) > constraint.value:
                errors.append(f"argument_constraint_failed:{safe_id}")
            continue

        passed = True
        for actual in values:
            if constraint.operator == "EQ":
                current = _constraint_values_equal(actual, constraint.value)
            elif constraint.operator == "NE":
                current = not _constraint_values_equal(actual, constraint.value)
            elif constraint.operator in {"LT", "LE", "GT", "GE"}:
                if (
                    not isinstance(actual, (int, float))
                    or isinstance(actual, bool)
                ):
                    current = False
                elif constraint.operator == "LT":
                    current = actual < constraint.value
                elif constraint.operator == "LE":
                    current = actual <= constraint.value
                elif constraint.operator == "GT":
                    current = actual > constraint.value
                else:
                    current = actual >= constraint.value
            elif constraint.operator in {"IN", "NOT_IN"}:
                member = any(
                    _constraint_values_equal(actual, candidate)
                    for candidate in constraint.value
                )
                current = member if constraint.operator == "IN" else not member
            else:
                current = False
            if not current:
                passed = False
                break
        if not passed:
            errors.append(f"argument_constraint_failed:{safe_id}")
    return tuple(errors)


def _v2_request_sensitivity(
    effect_facts: list[NormalizedEffectFacts],
) -> tuple[tuple[str, ...], str]:
    flags: set[str] = set()
    sensitivity = "governed"
    for effect in effect_facts:
        for binding in effect.bindings:
            for reference in binding.references:
                flags.update(reference.resource_flags)
                if reference.resource_sensitivity == "secret":
                    sensitivity = "secret"
    return tuple(sorted(flags)), sensitivity


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


EMPTY_ARGUMENTS_HASH = sha256_canonical_json({})


def _validate_input_schema(input_schema: Any) -> tuple[tuple[str, ...], str]:
    if input_schema is None:
        return ("input_schema_missing",), ""

    if not isinstance(input_schema, dict):
        return ("input_schema_not_object",), ""

    try:
        canonical_schema_json = canonical_json_bytes(input_schema).decode("utf-8")
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
