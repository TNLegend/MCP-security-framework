from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import math
import re
import unicodedata
from typing import Any, Iterable, Literal
from urllib.parse import urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator, model_validator

from common.canonical_json import sha256_canonical_json
from proxy.security_packs import SecurityPackManifest, SecurityPackRegistry


SUPPORTED_SCHEMA_PROFILE_ID = "supported-json-schema-v1"
TOOL_SECURITY_CONTRACT_VERSION = "2"
CAPABILITY_CATALOG_VERSION = "2"
RESOURCE_TYPE_REGISTRY_VERSION = "2"
FACTS_SCHEMA_VERSION = "1"
MAX_SCHEMA_DEPTH = 8
MAX_SCHEMA_PROPERTIES = 256
MAX_ARRAY_ITEMS = 1_000
MAX_STRING_LENGTH = 65_536
MAX_BINDING_DEPTH = 16
MAX_RESOURCE_CARDINALITY = 1_000
PATH_TOKEN_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_.:-]{0,127}$")
IDENTIFIER_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")
ACTION_SELECTOR_NAMES = {
    "action",
    "command",
    "intent",
    "method",
    "mode",
    "op",
    "operation",
    "verb",
}
ACTION_SELECTOR_VALUES = {
    "create",
    "delete",
    "execute",
    "list",
    "modify",
    "read",
    "run",
    "send",
    "update",
    "write",
}
EMAIL_PATTERN = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$"
)
FORBIDDEN_UNICODE = {
    "\u200b",
    "\u200c",
    "\u200d",
    "\u2060",
    "\ufeff",
    "\u202a",
    "\u202b",
    "\u202c",
    "\u202d",
    "\u202e",
    "\u2066",
    "\u2067",
    "\u2068",
    "\u2069",
}


class SecurityModelError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class ReferencePrecision(str, Enum):
    EXPLICIT = "EXPLICIT"
    SELECTOR = "SELECTOR"
    OPAQUE = "OPAQUE"


class ScopeMatchMode(str, Enum):
    SELF = "SELF"
    SUBTREE = "SUBTREE"


PRECISION_RANK = {
    ReferencePrecision.EXPLICIT: 0,
    ReferencePrecision.SELECTOR: 1,
    ReferencePrecision.OPAQUE: 2,
}


def _constraint_number(value: Any) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
    )


def _constraint_scalar(value: Any) -> bool:
    return (
        isinstance(value, (str, bool))
        or _constraint_number(value)
    )


class ResourceBinding(BaseModel):
    path: tuple[str, ...]
    resource_type: str = Field(min_length=1, max_length=128)
    role: Literal["RESOURCE", "SOURCE", "DESTINATION"] = "RESOURCE"

    model_config = ConfigDict(extra="forbid", frozen=True)

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        validate_binding_tokens(value)
        return value

    @field_validator("resource_type")
    @classmethod
    def validate_resource_type(cls, value: str) -> str:
        if not IDENTIFIER_PATTERN.fullmatch(value):
            raise ValueError("invalid resource type identifier")
        return value


class FixedResourceReference(BaseModel):
    resource_type: str = Field(min_length=1, max_length=128)
    canonical_value: str = Field(min_length=1, max_length=4096)
    role: Literal["RESOURCE", "SOURCE", "DESTINATION"] = "RESOURCE"

    model_config = ConfigDict(extra="forbid", frozen=True)


class ArgumentConstraint(BaseModel):
    constraint_id: str = Field(min_length=1, max_length=128)
    path: tuple[str, ...]
    operator: Literal[
        "EQ",
        "NE",
        "LT",
        "LE",
        "GT",
        "GE",
        "IN",
        "NOT_IN",
        "MAX_OCCURRENCES",
    ]
    value: Any
    required: StrictBool = True

    model_config = ConfigDict(extra="forbid", frozen=True)

    @field_validator("constraint_id")
    @classmethod
    def validate_constraint_id(cls, value: str) -> str:
        if not IDENTIFIER_PATTERN.fullmatch(value):
            raise ValueError("invalid argument constraint id")
        return value

    @field_validator("path")
    @classmethod
    def validate_constraint_path(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        validate_binding_tokens(value)
        return value

    @model_validator(mode="after")
    def validate_constraint_value(self) -> "ArgumentConstraint":
        scalar = _constraint_scalar(self.value)
        if self.operator in {"EQ", "NE"}:
            if not scalar:
                raise ValueError("equality constraint requires a scalar value")
        elif self.operator in {"LT", "LE", "GT", "GE"}:
            if not _constraint_number(self.value):
                raise ValueError("ordered constraint requires a finite number")
        elif self.operator in {"IN", "NOT_IN"}:
            if (
                not isinstance(self.value, (list, tuple))
                or not self.value
                or len(self.value) > 100
                or not all(_constraint_scalar(item) for item in self.value)
            ):
                raise ValueError("membership constraint requires bounded scalar values")
        elif self.operator == "MAX_OCCURRENCES":
            if (
                not isinstance(self.value, int)
                or isinstance(self.value, bool)
                or self.value < 0
                or self.value > MAX_RESOURCE_CARDINALITY
            ):
                raise ValueError("max occurrences constraint requires a bounded integer")
        return self


class ResultControl(BaseModel):
    classification: Literal["UNSPECIFIED", "INTERNAL", "SENSITIVE", "SECRET"] = "UNSPECIFIED"
    track_for_exfiltration: StrictBool = False

    model_config = ConfigDict(extra="forbid", frozen=True)


class ToolEffect(BaseModel):
    effect_id: str = Field(min_length=1, max_length=128)
    capability: str = Field(min_length=1, max_length=128)
    resource_bindings: tuple[ResourceBinding, ...] = ()
    fixed_resource: FixedResourceReference | None = None
    max_resource_cardinality: int | None = Field(
        default=None,
        ge=1,
        le=MAX_RESOURCE_CARDINALITY,
        strict=True,
    )
    declared_reference_precision: ReferencePrecision = ReferencePrecision.EXPLICIT

    model_config = ConfigDict(extra="forbid", frozen=True)

    @field_validator("effect_id", "capability")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        if not IDENTIFIER_PATTERN.fullmatch(value):
            raise ValueError("invalid security identifier.")
        return value


class ToolSecurityContract(BaseModel):
    contract_version: Literal["2"] = TOOL_SECURITY_CONTRACT_VERSION
    server_ref: str = Field(min_length=1, max_length=512)
    tool_name: str = Field(min_length=1, max_length=255)
    effects: tuple[ToolEffect, ...] = Field(min_length=1)
    argument_constraints: tuple[ArgumentConstraint, ...] = ()
    result_control: ResultControl = ResultControl()
    unbound_arguments: tuple[tuple[str, ...], ...] = ()

    model_config = ConfigDict(extra="forbid", frozen=True)

    @field_validator("unbound_arguments")
    @classmethod
    def validate_unbound_paths(
        cls,
        value: tuple[tuple[str, ...], ...],
    ) -> tuple[tuple[str, ...], ...]:
        for path in value:
            validate_binding_tokens(path)
        if len(set(value)) != len(value):
            raise ValueError("unbound argument paths must be unique.")
        return value

    @model_validator(mode="after")
    def validate_unique_effects_and_bindings(self) -> "ToolSecurityContract":
        effect_ids = [effect.effect_id for effect in self.effects]
        if len(effect_ids) != len(set(effect_ids)):
            raise ValueError("effect ids must be unique.")
        constraint_ids = [value.constraint_id for value in self.argument_constraints]
        if len(constraint_ids) != len(set(constraint_ids)):
            raise ValueError("argument constraint ids must be unique.")
        resource_types_by_path: dict[tuple[str, ...], str] = {}
        for effect in self.effects:
            effect_paths = [binding.path for binding in effect.resource_bindings]
            if len(effect_paths) != len(set(effect_paths)):
                raise ValueError("resource binding paths must be unique within an effect.")
            for binding in effect.resource_bindings:
                existing_type = resource_types_by_path.get(binding.path)
                if existing_type is not None and existing_type != binding.resource_type:
                    raise ValueError(
                        "resource binding path cannot use different resource types across effects."
                    )
                resource_types_by_path[binding.path] = binding.resource_type
        return self

    def contract_hash_payload(self) -> dict[str, Any]:
        payload = self.model_dump(mode="json")
        if not payload.get("argument_constraints"):
            payload.pop("argument_constraints", None)
        result_control = payload.get("result_control")
        if result_control == {
            "classification": "UNSPECIFIED",
            "track_for_exfiltration": False,
        }:
            payload.pop("result_control", None)
        for effect in payload.get("effects", []):
            for binding in effect.get("resource_bindings", []):
                if binding.get("role") == "RESOURCE":
                    binding.pop("role", None)
            fixed_resource = effect.get("fixed_resource")
            if isinstance(fixed_resource, dict) and fixed_resource.get("role") == "RESOURCE":
                fixed_resource.pop("role", None)
        return payload

    @property
    def contract_hash(self) -> str:
        return sha256_canonical_json(self.contract_hash_payload())


class AuthorityResourceScope(BaseModel):
    scope_id: str = Field(min_length=1, max_length=128)
    authority: str = Field(min_length=1, max_length=255)
    resource_type: str = Field(min_length=1, max_length=128)
    canonical_value: str = Field(min_length=1, max_length=4096)
    match_mode: ScopeMatchMode
    broad_scope_acknowledged: StrictBool = False

    model_config = ConfigDict(extra="forbid", frozen=True)

    @field_validator("scope_id")
    @classmethod
    def validate_scope_id(cls, value: str) -> str:
        if not IDENTIFIER_PATTERN.fullmatch(value):
            raise ValueError("invalid scope id.")
        return value


class ToolObservationApproval(BaseModel):
    tool_observation_id: int = Field(gt=0, strict=True)
    server_ref: str = Field(min_length=1, max_length=512)
    upstream_protocol_profile_id: str = Field(min_length=1, max_length=100)
    tool_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    contract_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    evidence_bundle_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    admin_id: str = Field(min_length=1, max_length=255)
    approved_at: str = Field(min_length=1, max_length=64)
    revision_id: str = Field(min_length=1, max_length=64)

    model_config = ConfigDict(extra="forbid", frozen=True)


class AdapterResolution(BaseModel):
    effect_id: str
    resource_type: str
    adapter_id: str
    adapter_api_version: str
    implementation_version: str

    model_config = ConfigDict(extra="forbid", frozen=True)


class ClaimedResourceReference(BaseModel):
    authority: str = Field(min_length=1, max_length=255)
    resource_type: str = Field(min_length=1, max_length=64)
    canonical_value: str = Field(min_length=1, max_length=4096)
    ancestors: tuple[str, ...] = ()
    resource_sensitivity: Literal[
        "unknown",
        "public",
        "internal",
        "private",
        "confidential",
        "secret",
    ] = "unknown"
    resource_flags: tuple[str, ...] = ()

    model_config = ConfigDict(extra="forbid", frozen=True)


class NormalizedBindingFacts(BaseModel):
    path: tuple[str, ...]
    status: Literal["resolved", "missing", "invalid", "truncated", "error"]
    resource_type: str
    role: Literal["RESOURCE", "SOURCE", "DESTINATION"] = "RESOURCE"
    occurrence_count: int = Field(ge=0, strict=True)
    truncated: StrictBool = False
    references: tuple[ClaimedResourceReference, ...] = ()

    model_config = ConfigDict(extra="forbid", frozen=True)


class NormalizedEffectFacts(BaseModel):
    effect_id: str
    capability_id: str
    requires_resource: StrictBool
    adapter_id: str
    adapter_api_version: str
    declared_reference_precision: ReferencePrecision
    runtime_reference_precision: ReferencePrecision
    effective_reference_precision: ReferencePrecision
    max_resource_cardinality: int | None = None
    bindings: tuple[NormalizedBindingFacts, ...] = ()

    model_config = ConfigDict(extra="forbid", frozen=True)


class NormalizedFacts(BaseModel):
    facts_schema_version: Literal["1"] = FACTS_SCHEMA_VERSION
    request: dict[str, Any]
    effects: tuple[NormalizedEffectFacts, ...]
    errors: tuple[str, ...] = ()

    model_config = ConfigDict(extra="forbid", frozen=True)


@dataclass(frozen=True)
class CapabilityDefinition:
    id: str
    domain: str
    verb: str
    destructive: bool
    requires_resource: bool
    allowed_resource_types: tuple[str, ...]
    external_effect: bool = False
    lifecycle: str = "ACTIVE"


class CapabilityCatalog:
    version = CAPABILITY_CATALOG_VERSION

    def __init__(
        self,
        *,
        version: str = CAPABILITY_CATALOG_VERSION,
        security_packs: Iterable[SecurityPackManifest] = (),
    ) -> None:
        self.version = version
        if version == "1":
            definitions = self._v1_definitions()
        elif version == CAPABILITY_CATALOG_VERSION:
            registry = SecurityPackRegistry(security_packs)
            definitions = tuple(
                CapabilityDefinition(
                    id=value.id,
                    domain=value.domain,
                    verb=value.verb,
                    destructive=value.destructive,
                    requires_resource=value.requires_resource,
                    allowed_resource_types=value.allowed_resource_types,
                    external_effect=value.external_effect,
                    lifecycle=value.lifecycle,
                )
                for pack in registry.packs()
                for value in pack.capabilities
            )
        else:
            raise SecurityModelError("unsupported_capability_catalog_version")
        self._definitions = {definition.id: definition for definition in definitions}

    @staticmethod
    def _v1_definitions() -> tuple[CapabilityDefinition, ...]:
        return (
            CapabilityDefinition(
                id="filesystem.read",
                domain="filesystem",
                verb="read",
                destructive=False,
                requires_resource=True,
                allowed_resource_types=("filesystem_path",),
            ),
            CapabilityDefinition(
                id="filesystem.list",
                domain="filesystem",
                verb="list",
                destructive=False,
                requires_resource=True,
                allowed_resource_types=("filesystem_path",),
            ),
            CapabilityDefinition(
                id="message.send",
                domain="message",
                verb="send",
                destructive=False,
                requires_resource=True,
                allowed_resource_types=("email_address",),
            ),
            CapabilityDefinition(
                id="system.ping",
                domain="system",
                verb="ping",
                destructive=False,
                requires_resource=False,
                allowed_resource_types=(),
            ),
        )

    def get(self, capability_id: str) -> CapabilityDefinition:
        definition = self._definitions.get(capability_id)
        if definition is None or definition.lifecycle != "ACTIVE":
            raise SecurityModelError("unknown_capability")
        return definition

    def ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._definitions))

    def as_policy_data(self) -> list[dict[str, Any]]:
        return [
            {
                "id": definition.id,
                "domain": definition.domain,
                "verb": definition.verb,
                "destructive": definition.destructive,
                "external_effect": definition.external_effect,
                "requires_resource": definition.requires_resource,
                "allowed_resource_types": list(definition.allowed_resource_types),
                "lifecycle": definition.lifecycle,
            }
            for definition in sorted(self._definitions.values(), key=lambda item: item.id)
        ]


@dataclass(frozen=True)
class ResourceTypeDefinition:
    resource_type_id: str
    resource_type_version: str
    hierarchy_support: bool
    allowed_matching_modes: tuple[str, ...]
    requires_specialized_interpretation: bool
    case_semantics: str
    unicode_policy: str
    canonicalizer: str
    adapter_id: str


class ResourceTypeRegistry:
    version = RESOURCE_TYPE_REGISTRY_VERSION

    def __init__(
        self,
        *,
        version: str = RESOURCE_TYPE_REGISTRY_VERSION,
        security_packs: Iterable[SecurityPackManifest] = (),
    ) -> None:
        self.version = version
        if version == "1":
            self._definitions = self._v1_definitions()
        elif version == RESOURCE_TYPE_REGISTRY_VERSION:
            registry = SecurityPackRegistry(security_packs)
            self._definitions = {
                value.id: ResourceTypeDefinition(
                    resource_type_id=value.id,
                    resource_type_version=value.version,
                    hierarchy_support=value.hierarchy_support,
                    allowed_matching_modes=tuple(value.allowed_matching_modes),
                    requires_specialized_interpretation=value.requires_specialized_interpretation,
                    case_semantics=value.case_semantics,
                    unicode_policy=value.unicode_policy,
                    canonicalizer=value.canonicalizer,
                    adapter_id=value.adapter_id,
                )
                for pack in registry.packs()
                for value in pack.resource_types
            }
        else:
            raise SecurityModelError("unsupported_resource_type_registry_version")

    @staticmethod
    def _v1_definitions() -> dict[str, ResourceTypeDefinition]:
        return {
            "filesystem_path": ResourceTypeDefinition(
                "filesystem_path", "1", True, ("SELF", "SUBTREE"), True,
                "authority-defined", "NFC-strict", "filesystem_path", "filesystem"
            ),
            "hierarchical_name": ResourceTypeDefinition(
                "hierarchical_name", "1", True, ("SELF", "SUBTREE"), False,
                "authority-defined", "NFC-strict", "hierarchical_name", "generic-declarative"
            ),
            "email_address": ResourceTypeDefinition(
                "email_address", "1", False, ("SELF",), False,
                "local-preserved-domain-lower", "ASCII-MVP", "email_address", "generic-declarative"
            ),
        }

    def get(self, resource_type_id: str) -> ResourceTypeDefinition:
        try:
            return self._definitions[resource_type_id]
        except KeyError as exc:
            raise SecurityModelError("unknown_resource_type") from exc

    def canonicalize(
        self,
        resource_type_id: str,
        value: Any,
        authority_config: dict[str, Any] | None = None,
    ) -> tuple[str, tuple[str, ...]]:
        self.get(resource_type_id)
        if not isinstance(value, str):
            raise SecurityModelError("resource_value_not_string")
        normalized = _strict_nfc(value)
        definition = self.get(resource_type_id)
        if definition.canonicalizer == "filesystem_path":
            return _canonical_filesystem_path(normalized, authority_config or {})
        if definition.canonicalizer == "hierarchical_name":
            return _canonical_hierarchical_name(normalized, authority_config or {})
        if definition.canonicalizer == "email_address":
            return _canonical_email(normalized)
        if definition.canonicalizer == "url":
            return _canonical_url(normalized)
        raise SecurityModelError("unknown_resource_type")


def security_schema_projection(schema: Any) -> dict[str, Any]:
    """Return a closed, non-authority-broadening security view of an MCP input schema.

    The upstream schema remains the evidence/fingerprint source. This projection is
    used only for contracts and runtime validation. Explicit object properties are
    preserved, while arbitrary additional object properties are denied.
    """
    if not isinstance(schema, dict):
        raise SecurityModelError("schema_not_object")
    return _project_security_schema_node(schema)


def _project_security_schema_node(node: dict[str, Any]) -> dict[str, Any]:
    projected: dict[str, Any] = {}
    node_type = node.get("type")
    object_node = node_type == "object" or (
        isinstance(node_type, list) and "object" in node_type
    )
    for key, value in node.items():
        if key == "additionalProperties" and object_node:
            continue
        if key in {"properties", "$defs", "definitions"} and isinstance(value, dict):
            projected[key] = {
                name: (
                    _project_security_schema_node(child)
                    if isinstance(child, dict)
                    else _clone_json_value(child)
                )
                for name, child in value.items()
            }
        elif key == "items" and isinstance(value, dict):
            projected[key] = _project_security_schema_node(value)
        elif key in {"oneOf", "anyOf", "allOf"} and isinstance(value, list):
            projected[key] = [
                (
                    _project_security_schema_node(child)
                    if isinstance(child, dict)
                    else _clone_json_value(child)
                )
                for child in value
            ]
        else:
            projected[key] = _clone_json_value(value)
    if object_node:
        projected["additionalProperties"] = False
    return projected


def _clone_json_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _clone_json_value(child) for key, child in value.items()}
    if isinstance(value, list):
        return [_clone_json_value(child) for child in value]
    return value


class SupportedSchemaProfileV1:
    profile_id = SUPPORTED_SCHEMA_PROFILE_ID

    @classmethod
    def validate(cls, schema: Any) -> tuple[tuple[str, ...], ...]:
        if not isinstance(schema, dict):
            raise SecurityModelError("schema_not_object")
        definitions = schema.get("$defs", {})
        if not isinstance(definitions, dict) or any(
            not isinstance(name, str)
            or not PATH_TOKEN_PATTERN.fullmatch(name)
            or not isinstance(value, dict)
            for name, value in definitions.items()
        ):
            raise SecurityModelError("schema_definitions_invalid")
        counter = [0]
        paths = cls._visit(
            schema,
            (),
            0,
            counter,
            definitions=definitions,
            resolving_refs=(),
            root=True,
        )
        return tuple(sorted(set(paths)))

    @classmethod
    def _visit(
        cls,
        node: dict[str, Any],
        path: tuple[str, ...],
        depth: int,
        counter: list[int],
        *,
        definitions: dict[str, dict[str, Any]],
        resolving_refs: tuple[str, ...],
        root: bool = False,
    ) -> list[tuple[str, ...]]:
        if depth > MAX_SCHEMA_DEPTH:
            raise SecurityModelError("schema_depth_exceeded")
        counter[0] += 1
        if counter[0] > MAX_SCHEMA_PROPERTIES:
            raise SecurityModelError("schema_property_count_exceeded")
        if "x-mcp-header" in node:
            raise SecurityModelError("schema_x_mcp_header_unsupported")
        forbidden = {
            "$dynamicRef",
            "patternProperties",
            "unevaluatedProperties",
            "allOf",
            "if",
            "then",
            "else",
            "not",
            "dependentSchemas",
        }
        if forbidden.intersection(node):
            raise SecurityModelError("schema_construct_unsupported")
        if "$ref" in node:
            allowed_ref_keys = {"$ref", "title", "description", "default", "examples"}
            if set(node) - allowed_ref_keys:
                raise SecurityModelError("schema_ref_siblings_unsupported")
            reference = node.get("$ref")
            prefix = "#/$defs/"
            if not isinstance(reference, str) or not reference.startswith(prefix):
                raise SecurityModelError("schema_ref_external_unsupported")
            name = reference[len(prefix):]
            if not PATH_TOKEN_PATTERN.fullmatch(name) or name not in definitions:
                raise SecurityModelError("schema_ref_unknown")
            if reference in resolving_refs:
                raise SecurityModelError("schema_ref_cycle")
            return cls._visit(
                definitions[name],
                path,
                depth + 1,
                counter,
                definitions=definitions,
                resolving_refs=(*resolving_refs, reference),
                root=root,
            )
        union_key = "oneOf" if "oneOf" in node else "anyOf" if "anyOf" in node else None
        if union_key:
            allowed_union_keys = {union_key, "title", "description", "default", "examples"}
            variants = node.get(union_key)
            if set(node) - allowed_union_keys or not isinstance(variants, list) or not 2 <= len(variants) <= 8:
                raise SecurityModelError("schema_union_unsupported")
            variant_paths = []
            for variant in variants:
                if not isinstance(variant, dict):
                    raise SecurityModelError("schema_union_unsupported")
                variant_paths.append(
                    cls._visit(
                        variant,
                        path,
                        depth + 1,
                        counter,
                        definitions=definitions,
                        resolving_refs=resolving_refs,
                        root=root,
                    )
                )
            normalized = [set(paths) for paths in variant_paths]
            if any(paths != normalized[0] for paths in normalized[1:]):
                raise SecurityModelError("schema_union_paths_ambiguous")
            return variant_paths[0]
        node_type = node.get("type")
        if isinstance(node_type, list):
            non_null = [value for value in node_type if value != "null"]
            if len(node_type) != 2 or len(non_null) != 1 or "null" not in node_type:
                raise SecurityModelError("schema_type_union_unsupported")
            node_type = non_null[0]
        if root and node_type != "object":
            raise SecurityModelError("schema_root_must_be_object")
        if node_type not in {"object", "array", "string", "boolean", "integer", "number"}:
            raise SecurityModelError("schema_type_unsupported")
        _reject_unsupported_action_selector(path, node)

        if node_type == "object":
            if node.get("additionalProperties") is not False:
                raise SecurityModelError("schema_additional_properties_must_be_false")
            properties = node.get("properties", {})
            required = node.get("required", [])
            if not isinstance(properties, dict) or not isinstance(required, list):
                raise SecurityModelError("schema_object_shape_invalid")
            if any(not isinstance(name, str) for name in required) or not set(required) <= set(properties):
                raise SecurityModelError("schema_required_invalid")
            result: list[tuple[str, ...]] = []
            for name, child in properties.items():
                if not isinstance(name, str) or not PATH_TOKEN_PATTERN.fullmatch(name):
                    raise SecurityModelError("schema_property_name_unsupported")
                if not isinstance(child, dict):
                    raise SecurityModelError("schema_property_not_object")
                result.extend(
                    cls._visit(
                        child,
                        path + (name,),
                        depth + 1,
                        counter,
                        definitions=definitions,
                        resolving_refs=resolving_refs,
                    )
                )
            return result

        if node_type == "array":
            items = node.get("items")
            max_items = node.get("maxItems")
            if (
                not isinstance(items, dict)
                or not isinstance(max_items, int)
                or isinstance(max_items, bool)
                or max_items < 0
                or max_items > MAX_ARRAY_ITEMS
            ):
                raise SecurityModelError("schema_array_unbounded_or_invalid")
            return cls._visit(
                items,
                path + ("*",),
                depth + 1,
                counter,
                definitions=definitions,
                resolving_refs=resolving_refs,
            )

        cls._validate_scalar_constraints(node, node_type)
        return [path]

    @staticmethod
    def _validate_scalar_constraints(
        node: dict[str, Any],
        node_type: str,
    ) -> None:
        enum = node.get("enum")
        if enum is not None and (not isinstance(enum, list) or not enum):
            raise SecurityModelError("schema_enum_invalid")
        if node_type == "string":
            max_length = node.get("maxLength", MAX_STRING_LENGTH)
            if (
                not isinstance(max_length, int)
                or isinstance(max_length, bool)
                or max_length < 0
                or max_length > MAX_STRING_LENGTH
            ):
                raise SecurityModelError("schema_string_bound_invalid")
        if node_type in {"integer", "number"}:
            minimum = node.get("minimum")
            maximum = node.get("maximum")
            if minimum is None or maximum is None:
                raise SecurityModelError("schema_number_bounds_required")
            if not _safe_number(minimum) or not _safe_number(maximum) or minimum > maximum:
                raise SecurityModelError("schema_number_bounds_invalid")


def _reject_unsupported_action_selector(
    path: tuple[str, ...],
    node: dict[str, Any],
) -> None:
    if not path:
        return
    selector_name = path[-1].lower()
    if selector_name not in ACTION_SELECTOR_NAMES | ACTION_SELECTOR_VALUES:
        return
    enum = node.get("enum")
    if isinstance(enum, list) and len(enum) == 1:
        return
    raise SecurityModelError("conditional_selector_schema_unsupported")


def validate_contract_for_schema(
    contract: ToolSecurityContract,
    schema: dict[str, Any],
    *,
    capability_catalog: CapabilityCatalog | None = None,
    resource_type_registry: ResourceTypeRegistry | None = None,
    adapter_resolver=None,
) -> tuple[AdapterResolution, ...]:
    schema_paths = set(SupportedSchemaProfileV1.validate(schema))
    bound_paths = {
        binding.path
        for effect in contract.effects
        for binding in effect.resource_bindings
    }
    unbound_paths = set(contract.unbound_arguments)
    constraint_paths = {constraint.path for constraint in contract.argument_constraints}
    if bound_paths.intersection(unbound_paths):
        raise SecurityModelError("argument_bound_and_unbound")
    unknown = (bound_paths | unbound_paths) - schema_paths
    if unknown:
        raise SecurityModelError("contract_path_not_in_schema")
    if constraint_paths - schema_paths:
        raise SecurityModelError("constraint_path_not_in_schema")
    if schema_paths != bound_paths | unbound_paths:
        raise SecurityModelError("unaccounted_schema_argument")

    catalog = capability_catalog or CapabilityCatalog()
    type_registry = resource_type_registry or ResourceTypeRegistry()
    if adapter_resolver is None:
        from proxy.resource_adapters_v2 import AdapterRegistry

        adapter_resolver = AdapterRegistry()
    resolutions: list[AdapterResolution] = []
    for effect in contract.effects:
        capability = catalog.get(effect.capability)
        resource_source_count = len(effect.resource_bindings) + (
            1 if effect.fixed_resource is not None else 0
        )
        if capability.requires_resource and resource_source_count == 0:
            raise SecurityModelError("required_resource_binding_missing")
        if not capability.requires_resource and resource_source_count:
            raise SecurityModelError("resource_binding_not_allowed")
        if effect.resource_bindings and effect.fixed_resource is not None:
            raise SecurityModelError("resource_source_ambiguous")
        for binding in effect.resource_bindings:
            type_registry.get(binding.resource_type)
            if binding.resource_type not in capability.allowed_resource_types:
                raise SecurityModelError("capability_resource_type_incompatible")
            manifest = adapter_resolver.resolve(effect.capability, binding.resource_type)
            resolutions.append(
                AdapterResolution(
                    effect_id=effect.effect_id,
                    resource_type=binding.resource_type,
                    adapter_id=manifest.adapter_id,
                    adapter_api_version=manifest.adapter_api_version,
                    implementation_version=manifest.implementation_version,
                )
            )
        if effect.fixed_resource is not None:
            type_registry.get(effect.fixed_resource.resource_type)
            if effect.fixed_resource.resource_type not in capability.allowed_resource_types:
                raise SecurityModelError("capability_resource_type_incompatible")
            manifest = adapter_resolver.resolve(
                effect.capability,
                effect.fixed_resource.resource_type,
            )
            resolutions.append(
                AdapterResolution(
                    effect_id=effect.effect_id,
                    resource_type=effect.fixed_resource.resource_type,
                    adapter_id=manifest.adapter_id,
                    adapter_api_version=manifest.adapter_api_version,
                    implementation_version=manifest.implementation_version,
                )
            )
    return tuple(resolutions)


def validate_scope(
    scope: AuthorityResourceScope,
    *,
    registry: ResourceTypeRegistry | None = None,
    authority_config: dict[str, Any] | None = None,
) -> AuthorityResourceScope:
    type_registry = registry or ResourceTypeRegistry()
    definition = type_registry.get(scope.resource_type)
    if scope.match_mode.value not in definition.allowed_matching_modes:
        raise SecurityModelError("scope_match_mode_unsupported")
    canonical, _ = type_registry.canonicalize(
        scope.resource_type,
        scope.canonical_value,
        authority_config,
    )
    is_root = canonical in {"/", ""}
    if scope.match_mode == ScopeMatchMode.SUBTREE and is_root and not scope.broad_scope_acknowledged:
        raise SecurityModelError("root_subtree_requires_acknowledgement")
    return scope.model_copy(update={"canonical_value": canonical})


def effective_precision(
    declared: ReferencePrecision,
    runtime: ReferencePrecision,
) -> ReferencePrecision:
    return max((declared, runtime), key=lambda value: PRECISION_RANK[value])


def validate_binding_tokens(tokens: Iterable[str]) -> None:
    values = tuple(tokens)
    if not values or len(values) > MAX_BINDING_DEPTH:
        raise ValueError("binding path has invalid depth.")
    for token in values:
        if token == "*" or token.isdigit():
            continue
        if not PATH_TOKEN_PATTERN.fullmatch(token):
            raise ValueError("binding path token is invalid.")


def _strict_nfc(value: str) -> str:
    if not value or value != value.strip() or "\x00" in value:
        raise SecurityModelError("resource_value_invalid")
    if any(character in FORBIDDEN_UNICODE or ord(character) < 32 for character in value):
        raise SecurityModelError("resource_value_ambiguous_unicode")
    normalized = unicodedata.normalize("NFC", value)
    if normalized != value:
        raise SecurityModelError("resource_value_not_nfc")
    return value


def _canonical_filesystem_path(
    value: str,
    config: dict[str, Any],
) -> tuple[str, tuple[str, ...]]:
    mode = config.get("filesystem_path_mode", "RELATIVE_ROOTED")
    if mode not in {"RELATIVE_ROOTED", "ABSOLUTE"}:
        raise SecurityModelError("filesystem_path_mode_unsupported")
    if "\\" in value or "//" in value or "*" in value or "?" in value or ":" in value:
        raise SecurityModelError("filesystem_path_ambiguous")
    if mode == "RELATIVE_ROOTED" and value.startswith("/"):
        raise SecurityModelError("filesystem_path_absolute_unsupported")
    if mode == "ABSOLUTE" and not value.startswith("/"):
        raise SecurityModelError("filesystem_path_relative_unsupported")
    if mode == "ABSOLUTE" and value == "/":
        return "/", ("/",)

    raw_parts = value[1:].split("/") if mode == "ABSOLUTE" else value.split("/")
    parts: list[str] = []
    for part in raw_parts:
        if part == "":
            raise SecurityModelError("filesystem_path_empty_segment")
        if part == ".":
            raise SecurityModelError("filesystem_path_dot_segment")
        if part == "..":
            raise SecurityModelError("filesystem_path_traversal")
        if not PATH_TOKEN_PATTERN.fullmatch(part):
            raise SecurityModelError("filesystem_path_segment_unsupported")
        parts.append(part)
    if not parts:
        raise SecurityModelError("filesystem_path_empty")
    if mode == "ABSOLUTE":
        canonical = "/" + "/".join(parts)
        ancestors = ["/"]
        current = ""
        for part in parts:
            current += "/" + part
            ancestors.append(current)
        return canonical, tuple(ancestors)

    canonical = "/".join(parts)
    ancestors = []
    current = ""
    for part in parts:
        current = part if not current else f"{current}/{part}"
        ancestors.append(current)
    return canonical, tuple(ancestors)


def _canonical_hierarchical_name(
    value: str,
    config: dict[str, Any],
) -> tuple[str, tuple[str, ...]]:
    separator = config.get("separator", "/")
    if separator not in {"/", ".", ":"}:
        raise SecurityModelError("hierarchical_separator_unsupported")
    if value.startswith(separator) or value.endswith(separator) or separator * 2 in value:
        raise SecurityModelError("hierarchical_name_ambiguous")
    parts = value.split(separator)
    max_depth = config.get("max_depth", 32)
    if not isinstance(max_depth, int) or len(parts) > max_depth:
        raise SecurityModelError("hierarchical_name_depth_exceeded")
    if any(not PATH_TOKEN_PATTERN.fullmatch(part) for part in parts):
        raise SecurityModelError("hierarchical_name_invalid")
    case_sensitive = config.get("case_sensitive", True)
    canonical_parts = parts if case_sensitive else [part.lower() for part in parts]
    canonical = separator.join(canonical_parts)
    ancestors = tuple(separator.join(canonical_parts[:index]) for index in range(1, len(parts) + 1))
    return canonical, ancestors


def _canonical_email(value: str) -> tuple[str, tuple[str, ...]]:
    if len(value) > 254 or not value.isascii() or not EMAIL_PATTERN.fullmatch(value):
        raise SecurityModelError("email_address_unsupported")
    local_part, domain = value.rsplit("@", 1)
    return f"{local_part}@{domain.lower()}", ()


def _canonical_url(value: str) -> tuple[str, tuple[str, ...]]:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise SecurityModelError("resource_url_invalid") from exc
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()
    if scheme not in {"http", "https"} or not host:
        raise SecurityModelError("resource_url_invalid")
    if parsed.username or parsed.password or parsed.fragment:
        raise SecurityModelError("resource_url_authority_invalid")
    if any(character.isspace() or ord(character) < 32 for character in value):
        raise SecurityModelError("resource_url_invalid_character")
    default_port = 80 if scheme == "http" else 443
    authority = host if port in {None, default_port} else f"{host}:{port}"
    path = parsed.path or "/"
    canonical = urlunsplit((scheme, authority, path, parsed.query, ""))
    return canonical, (f"{scheme}://{authority}",)


def _safe_number(value: Any) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    if isinstance(value, float) and not math.isfinite(value):
        return False
    return abs(value) <= 9_007_199_254_740_991
