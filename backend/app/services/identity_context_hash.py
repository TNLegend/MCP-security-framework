from typing import Any

from common.canonical_json import canonical_json_bytes, sha256_canonical_json

from app.schemas.policy_context import RuntimePolicyInput


def canonical_runtime_context_bytes(context: dict[str, Any]) -> bytes:
    validated_context = RuntimePolicyInput.model_validate(context).model_dump(
        mode="json"
    )
    return canonical_json_bytes(validated_context)


def runtime_context_hash(context: dict[str, Any]) -> str:
    validated_context = RuntimePolicyInput.model_validate(context).model_dump(mode="json")
    return sha256_canonical_json(validated_context)
