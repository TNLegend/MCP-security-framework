from __future__ import annotations

import json
import math
from typing import Any


MAX_JSON_BYTES = 262_144
MAX_JSON_DEPTH = 64
MAX_JSON_PROPERTIES = 2_000
MAX_JSON_ARRAY_ITEMS = 2_000
MAX_JSON_STRING_LENGTH = 65_536
MAX_SAFE_INTEGER = 9_007_199_254_740_991


class StrictJSONError(ValueError):
    pass


def parse_strict_json(raw: bytes) -> dict[str, Any]:
    if not raw or len(raw) > MAX_JSON_BYTES:
        raise StrictJSONError("json_body_empty_or_too_large")
    if raw.startswith((b"\xef\xbb\xbf", b"\xff\xfe", b"\xfe\xff")):
        raise StrictJSONError("json_bom_or_encoding_unsupported")
    try:
        text = raw.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
            parse_int=_parse_int,
            parse_float=_parse_float,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise StrictJSONError("json_invalid") from exc
    if not isinstance(value, dict):
        raise StrictJSONError("jsonrpc_batch_or_non_object_unsupported")
    _validate_limits(value, depth=0)
    return value


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise StrictJSONError("json_duplicate_key")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise StrictJSONError(f"json_non_finite_number:{value}")


def _parse_int(value: str) -> int:
    parsed = int(value)
    if abs(parsed) > MAX_SAFE_INTEGER:
        raise StrictJSONError("json_integer_out_of_safe_range")
    return parsed


def _parse_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed) or abs(parsed) > MAX_SAFE_INTEGER:
        raise StrictJSONError("json_number_out_of_safe_range")
    if len(value.replace("-", "").replace("+", "")) > 32:
        raise StrictJSONError("json_number_precision_unsupported")
    return parsed


def _validate_limits(value: Any, *, depth: int) -> None:
    if depth > MAX_JSON_DEPTH:
        raise StrictJSONError("json_depth_exceeded")
    if isinstance(value, str):
        if len(value) > MAX_JSON_STRING_LENGTH:
            raise StrictJSONError("json_string_too_long")
        return
    if isinstance(value, dict):
        if len(value) > MAX_JSON_PROPERTIES:
            raise StrictJSONError("json_object_too_large")
        for key, child in value.items():
            if len(key) > 512:
                raise StrictJSONError("json_key_too_long")
            _validate_limits(child, depth=depth + 1)
        return
    if isinstance(value, list):
        if len(value) > MAX_JSON_ARRAY_ITEMS:
            raise StrictJSONError("json_array_too_large")
        for child in value:
            _validate_limits(child, depth=depth + 1)
