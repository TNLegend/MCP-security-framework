"""Operational M6 supplemental exact constraint drift. Historical shadow labels are preserved for serialized compatibility.
Reports exact differences inside the known signed JSON-schema fragment.
Does NOT infer authorization or arbitrary schema inclusion, and leaves V0
schema/contract validation, signatures and runtime permissions unchanged.
"""

from __future__ import annotations
import math
from decimal import Decimal
from typing import Any

REVISION = "m6-constraint-delta-shadow-v1"
SCALAR_KEYS = {
    "integer": ("minimum", "maximum", "enum", "const"),
    "number": ("minimum", "maximum", "enum", "const"),
    "string": ("minLength", "maxLength", "enum", "const"),
    "array": ("minItems", "maxItems", "uniqueItems", "enum", "const"),
    "object": ("minProperties", "maxProperties", "enum", "const"),
    "boolean": ("enum", "const"),
}
LOWER_KEYS = {"minimum", "minLength", "minItems", "minProperties"}
UPPER_KEYS = {"maximum", "maxLength", "maxItems", "maxProperties"}


def _nodes(node: Any, path: str = "", depth: int = 0):
    if not isinstance(node, dict) or depth > 32:
        return
    kind = node.get("type")
    if not isinstance(kind, str) or kind not in SCALAR_KEYS:
        return
    yield (path, node, kind)
    if kind == "object":
        for name, child in (node.get("properties") or {}).items():
            if isinstance(name, str):
                esc = name.replace("~", "~0").replace("/", "~1")
                yield from _nodes(child, path + "/properties/" + esc, depth + 1)
    if kind == "array":
        yield from _nodes(node.get("items"), path + "/items", depth + 1)


def _supported_number(value):
    if type(value) is int:
        return abs(value) <= 2**53 - 1
    return type(value) is float and math.isfinite(value)


def _value_token(x):
    """JSON-semantic equality: bool != number, 1 == 1.0; enum order irrelevant."""
    if x is None:
        return ("null",)
    if type(x) is bool:
        return ("boolean", x)
    if _supported_number(x):
        return ("number", str(Decimal(str(x)).normalize()))
    if type(x) is int:
        return ("unsupported_large_integer", x)
    if type(x) is float:
        return ("unsupported_nonfinite", repr(x))
    if isinstance(x, str):
        return ("string", x)
    if isinstance(x, list):
        return ("array", tuple((_value_token(v) for v in x)))
    if isinstance(x, dict):
        return (
            "object",
            tuple(sorted(((str(k), _value_token(v)) for k, v in x.items()))),
        )
    return ("unsupported", type(x).__name__, repr(x))


def _same_constraint(key, a, b):
    if key == "enum" and isinstance(a, list) and isinstance(b, list):
        return {_value_token(x) for x in a} == {_value_token(x) for x in b}
    return _value_token(a) == _value_token(b)


def _polarity(key, old, new):
    if _same_constraint(key, old, new):
        return "UNCHANGED"
    if old is None:
        return "BOUND_ADDED"
    if new is None:
        return "BOUND_REMOVED"
    if key in LOWER_KEYS | UPPER_KEYS and all(
        (_supported_number(x) for x in (old, new))
    ):
        try:
            if key in LOWER_KEYS:
                return "RELAXED" if new < old else "TIGHTENED"
            return "RELAXED" if new > old else "TIGHTENED"
        except TypeError:
            return "UNRESOLVED"
    if key == "uniqueItems" and all((isinstance(x, bool) for x in (old, new))):
        return "RELAXED" if old and (not new) else "TIGHTENED"
    if key == "const":
        return "VALUE_CHANGED_NOT_ORDERED"
    if key == "enum" and isinstance(old, list) and isinstance(new, list):
        left = {_value_token(v) for v in old}
        right = {_value_token(v) for v in new}
        if right > left:
            return "RELAXED"
        if right < left:
            return "TIGHTENED"
        return "VALUE_CHANGED_NOT_ORDERED"
    return "UNRESOLVED"


def _schema_profile_status(schema: dict[str, Any]) -> dict[str, str]:
    """Syntax/profile check only, not contract inclusion, authority, or completeness."""
    from proxy.tool_security_v2 import SupportedSchemaProfileV1, SecurityModelError

    try:
        SupportedSchemaProfileV1.validate(schema)
    except (
        SecurityModelError,
        ValueError,
        TypeError,
        OverflowError,
        RecursionError,
    ) as error:
        return {"status": "OUTSIDE_SUPPORTED_PROFILE", "reason": str(error)[:180]}
    return {"status": "SUPPORTED_PROFILE_SYNTAX", "reason": ""}


def supplemental_constraint_delta(
    previous: dict[str, Any], current: dict[str, Any]
) -> dict[str, Any]:
    old = {p: (n, t) for p, n, t in _nodes(previous)}
    new = {p: (n, t) for p, n, t in _nodes(current)}
    rows = []
    for path in sorted(old.keys() & new.keys()):
        a, ta = old[path]
        b, tb = new[path]
        if ta != tb:
            continue
        for key in SCALAR_KEYS[ta]:
            left = a.get(key)
            right = b.get(key)
            if _same_constraint(key, left, right):
                continue
            rows.append(
                {
                    "path": path or "/",
                    "keyword": key,
                    "old": left,
                    "new": right,
                    "comparison": _polarity(key, left, right),
                    "origin": "EXACT_JSON_SCHEMA",
                    "security_fragment_supported_keyword": True,
                    "disposition": "SHADOW_ONLY_NOT_AUTHORITY",
                }
            )
    profiles = {
        "previous": _schema_profile_status(previous),
        "current": _schema_profile_status(current),
    }
    return {
        "revision": REVISION,
        "changes": rows,
        "creates_permissions": False,
        "schema_profile_checks": profiles,
        "coverage": "PARTIAL_KEYWORDS_AND_RECURSION_ONLY",
        "interpretation": "Diagnostic delta only; profile checks do not certify contract inclusion, tool behavior or permissions",
    }
