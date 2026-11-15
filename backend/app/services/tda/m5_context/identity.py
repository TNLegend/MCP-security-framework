from __future__ import annotations
from typing import Any
import re

INVALID_ANALYSIS_CONTEXT_PREFIX = "invalid:"
SHA256_HEX_RE = re.compile("^[0-9a-f]{64}$")


def normalize_description(description: str | None) -> str:
    import re

    if description is None:
        return ""
    return re.sub("\\s+", " ", description.strip())


def tool_fingerprint_payload(
    *,
    server_ref: str,
    tool_name: str,
    description: str | None,
    input_schema: dict[str, Any] | None,
    output_schema: dict[str, Any] | None,
    annotations: dict[str, Any] | None,
    execution: dict[str, Any] | None = None,
    profile: dict[str, Any] | None = None,
) -> dict[str, Any]:
    _ = (server_ref, profile)
    return {
        "tool_name": tool_name,
        "description": normalize_description(description),
        "input_schema": input_schema or {},
        "output_schema": output_schema or {},
        "annotations": annotations or {},
        "execution": execution or {},
    }


def compute_tool_fingerprint(payload: dict[str, Any]) -> str:
    from common.canonical_json import canonical_json_bytes
    from hashlib import sha256

    return sha256(canonical_json_bytes(payload)).hexdigest()


def analysis_context_payload(profile_snapshot: dict[str, Any] | None) -> dict[str, Any]:
    if profile_snapshot is None:
        return {"schema_version": 0, "profile": None}
    contract_hash = profile_snapshot.get("contract_hash")
    if isinstance(contract_hash, str) and SHA256_HEX_RE.fullmatch(contract_hash):
        return {"schema_version": 2, "contract_hash": contract_hash}
    return {"schema_version": 2, "invalid_context": "missing_or_invalid_contract_hash"}


def compute_analysis_context_hash(profile_snapshot: dict[str, Any] | None) -> str:
    from common.canonical_json import canonical_json_bytes
    from hashlib import sha256

    payload = analysis_context_payload(profile_snapshot)
    digest = sha256(canonical_json_bytes(payload)).hexdigest()
    if payload.get("invalid_context"):
        return f"{INVALID_ANALYSIS_CONTEXT_PREFIX}{digest[:56]}"
    return digest


def reusable_analysis_context_hash(value: str | None) -> bool:
    return isinstance(value, str) and SHA256_HEX_RE.fullmatch(value) is not None
