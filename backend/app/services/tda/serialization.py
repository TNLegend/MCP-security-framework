from __future__ import annotations
from typing import Any


def _safe_excerpt(value: str, limit: int = 160) -> str:
    import re

    text = re.sub("\\s+", " ", str(value)).strip()
    text = re.sub(
        "(?i)(token|password|secret|api[_ -]?key|credential)=?[A-Za-z0-9._~+/=-]+",
        "\\1=<redacted>",
        text,
    )
    if len(text) > limit:
        return f"{text[:limit]}..."
    return text


def _safe_json(value: Any) -> str:
    from common.canonical_json import canonical_json_bytes

    try:
        return canonical_json_bytes(value).decode("utf-8")
    except Exception:
        return str(value)


def _json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _json_safe(item) for key, item in value.items() if key != "findings"
        }
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    return value
