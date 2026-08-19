from __future__ import annotations

from hashlib import sha256
from typing import Any

import rfc8785


class CanonicalJSONError(ValueError):
    """Raised when a value is outside the supported RFC 8785 JSON domain."""


def canonical_json_bytes(value: Any) -> bytes:
    try:
        return rfc8785.dumps(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise CanonicalJSONError("value_not_rfc8785_canonicalizable") from exc


def sha256_canonical_json(value: Any) -> str:
    return sha256(canonical_json_bytes(value)).hexdigest()
