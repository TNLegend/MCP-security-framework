from hashlib import sha256
from typing import Any

import rfc8785

from app.schemas.policy_context import RuntimePolicyInput


def canonical_runtime_context_bytes(context: dict[str, Any]) -> bytes:
    validated_context = RuntimePolicyInput.model_validate(context).model_dump(
        mode="json"
    )
    return rfc8785.dumps(validated_context)


def runtime_context_hash(context: dict[str, Any]) -> str:
    return sha256(canonical_runtime_context_bytes(context)).hexdigest()
