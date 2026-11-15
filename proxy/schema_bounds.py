"""Provider-neutral, explicit narrowing of MCP JSON Schema for governed contracts.

The original MCP tool definition is never mutated or fingerprinted differently.
No bounds are inferred from provider names, argument names, prose, or defaults.
Only a signed tool contract may carry these explicit constraints.
"""
from __future__ import annotations

from copy import deepcopy
import math
import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, StrictFloat, StrictInt, field_validator, model_validator

MAX_ARRAY_ITEMS = 1000
MAX_BOUNDS = 64
MAX_PATH_DEPTH = 8
SAFE_JSON_INTEGER = 9007199254740991
PATH_TOKEN = re.compile(r"^[A-Za-z_][A-Za-z0-9_.:-]{0,127}$")


class SchemaBoundsError(ValueError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class SchemaBound(BaseModel):
    """An explicit, narrower limit for one typed schema node.

    Path components are JSON Schema object property names, with '*' only
    for the items of an array; $refs/unions are intentionally unsupported.
    """
    kind: Literal["NUMBER_RANGE", "ARRAY_MAX_ITEMS"]
    path: tuple[str, ...]
    minimum: StrictInt | StrictFloat | None = None
    maximum: StrictInt | StrictFloat | None = None
    max_items: StrictInt | None = None

    # JSON array paths are accepted and normalized to immutable tuples at the API boundary.
    # Security-relevant scalar values remain strictly checked below.
    model_config = ConfigDict(extra="forbid", frozen=True)

    @field_validator("path")
    @classmethod
    def valid_path(cls, path: tuple[str, ...]) -> tuple[str, ...]:
        if not path or len(path) > MAX_PATH_DEPTH:
            raise ValueError("schema_bound_path_invalid")
        if any(t != "*" and not PATH_TOKEN.fullmatch(t) for t in path):
            raise ValueError("schema_bound_path_invalid")
        return path

    @model_validator(mode="after")
    def valid_limit(self) -> "SchemaBound":
        if self.kind == "ARRAY_MAX_ITEMS":
            if (
                self.minimum is not None or self.maximum is not None
                or self.max_items is None or not 0 <= self.max_items <= MAX_ARRAY_ITEMS
            ):
                raise ValueError("schema_bound_array_invalid")
        else:
            if self.max_items is not None or not _finite(self.minimum) or not _finite(self.maximum):
                raise ValueError("schema_bound_number_invalid")
            if self.minimum > self.maximum:
                raise ValueError("schema_bound_number_invalid")
            if abs(self.minimum) > SAFE_JSON_INTEGER or abs(self.maximum) > SAFE_JSON_INTEGER:
                raise ValueError("schema_bound_number_unsafe")
        return self


def _finite(value: Any) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        return math.isfinite(value)
    except (TypeError, ValueError, OverflowError):
        return False


def _find_node(root: dict[str, Any], path: tuple[str, ...]) -> dict[str, Any]:
    node: Any = root
    for part in path:
        if not isinstance(node, dict) or any(k in node for k in ("$ref", "oneOf", "anyOf", "allOf", "if", "then", "else")):
            raise SchemaBoundsError("schema_bound_unsupported_node")
        if part == "*":
            if node.get("type") != "array" or not isinstance(node.get("items"), dict):
                raise SchemaBoundsError("schema_bound_path_invalid")
            node = node["items"]
        else:
            if node.get("type") != "object" or not isinstance(node.get("properties"), dict) or part not in node["properties"]:
                raise SchemaBoundsError("schema_bound_path_invalid")
            node = node["properties"][part]
    if not isinstance(node, dict) or any(k in node for k in ("$ref", "oneOf", "anyOf", "allOf", "if", "then", "else")):
        raise SchemaBoundsError("schema_bound_unsupported_node")
    return node


def apply_schema_bounds(
    projected_schema: dict[str, Any], bounds: tuple[SchemaBound, ...] | list[SchemaBound]
) -> dict[str, Any]:
    """Produce an authorized schema subset, never mutate the upstream schema."""
    if not isinstance(projected_schema, dict):
        raise SchemaBoundsError("schema_not_object")
    if not bounds:
        return projected_schema
    if len(bounds) > MAX_BOUNDS:
        raise SchemaBoundsError("schema_bound_count_exceeded")
    projected = deepcopy(projected_schema)
    paths: set[tuple[str, ...]] = set()
    for bound in bounds:
        if bound.path in paths:
            raise SchemaBoundsError("schema_bound_path_duplicate")
        paths.add(bound.path)
        node = _find_node(projected, bound.path)
        if bound.kind == "NUMBER_RANGE":
            if node.get("type") not in ("integer", "number"):
                raise SchemaBoundsError("schema_bound_type_mismatch")
            if node["type"] == "integer" and (
                not isinstance(bound.minimum, int) or not isinstance(bound.maximum, int)
            ):
                raise SchemaBoundsError("schema_bound_integer_fraction")
            previous_min = node.get("minimum")
            previous_max = node.get("maximum")
            if previous_min is not None and (not _finite(previous_min) or bound.minimum < previous_min):
                raise SchemaBoundsError("schema_bound_would_widen")
            if previous_max is not None and (not _finite(previous_max) or bound.maximum > previous_max):
                raise SchemaBoundsError("schema_bound_would_widen")
            node["minimum"], node["maximum"] = bound.minimum, bound.maximum
        else:
            if node.get("type") != "array":
                raise SchemaBoundsError("schema_bound_type_mismatch")
            previous_max = node.get("maxItems")
            previous_min = node.get("minItems", 0)
            if (
                not isinstance(previous_min, int) or isinstance(previous_min, bool)
                or previous_min > bound.max_items
                or (previous_max is not None and (
                    not isinstance(previous_max, int) or isinstance(previous_max, bool)
                    or bound.max_items > previous_max
                ))
            ):
                raise SchemaBoundsError("schema_bound_would_widen")
            node["maxItems"] = bound.max_items
    return projected
