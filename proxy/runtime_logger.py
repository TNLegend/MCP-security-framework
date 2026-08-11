from typing import Any

from proxy.backend_client import BackendClient
from proxy.tool_request_preparation import (
    MAX_ERROR_CODE_LENGTH,
    MAX_VALIDATION_ERRORS,
    _sanitize_error_codes,
    _sanitize_code_part,
)


STATUS_BY_DECISION = {
    "ALLOW": "allowed",
    "WARN": "allowed",
    "LOG_ONLY": "allowed",
    "BLOCK": "blocked",
    "ASK_APPROVAL": "approval_required",
    "LIMIT": "limited",
}

EXECUTING_DECISIONS = {"ALLOW", "WARN", "LOG_ONLY"}
MAX_ARGUMENT_NAMES_IN_SUMMARY = 20
MAX_ARGUMENT_NAME_LENGTH = 64
SENSITIVE_SUMMARY_FIELDS = {
    "access_token",
    "session_token",
    "authorization",
    "identity_assertion",
    "signature",
    "private_key",
    "public_key",
    "jwks",
    "pem",
    "jti",
    "ctx_hash",
    "token_hash",
    "token_pepper",
    "physical_resource",
    "physical_path",
}


def summarize_arguments(tool_call: dict[str, Any]) -> dict[str, Any]:
    arguments = tool_call.get("arguments")
    if not isinstance(arguments, dict):
        arguments = {}

    safe_argument_keys = [
        name
        for name in sorted(arguments.keys(), key=str)
        if not _is_sensitive_summary_field(name)
    ][:MAX_ARGUMENT_NAMES_IN_SUMMARY]
    argument_names = [_safe_summary_name(name) for name in safe_argument_keys]
    argument_types = {
        _safe_summary_name(name): _safe_type_name(arguments[name])
        for name in safe_argument_keys
    }
    validation_error_codes = tool_call.get("validation_error_codes") or []
    safe_validation_error_codes = [
        code
        for code in validation_error_codes
        if not _contains_sensitive_summary_field(code)
    ]

    return {
        "argument_names": argument_names,
        "argument_types": argument_types,
        "arguments_valid": bool(tool_call.get("arguments_valid", False)),
        "validation_error_codes": list(
            _sanitize_error_codes(
                [
                    str(code)[:MAX_ERROR_CODE_LENGTH]
                    for code in safe_validation_error_codes[:MAX_VALIDATION_ERRORS]
                ]
            )
        ),
        "resource_type": _safe_summary_name(
            str(tool_call.get("resource_type") or "unknown")
        ),
        "resource_scope": _safe_summary_name(
            str(tool_call.get("resource_scope") or "unknown")
        ),
        "operation": _safe_summary_name(str(tool_call.get("operation") or "unknown")),
        "required_capability": _safe_summary_name(
            str(tool_call.get("required_capability") or "unknown")
        ),
        "resource_sensitivity": _safe_summary_name(
            str(tool_call.get("resource_sensitivity") or "unknown")
        ),
        "resource_resolution_status": _safe_summary_name(
            str(tool_call.get("resource_resolution_status") or "unknown")
        ),
    }


def summarize_tool_result(result: dict[str, Any] | None) -> str | None:
    if result is None:
        return None

    content = result.get("content") or []
    if not isinstance(content, list):
        content = []

    text_length = 0
    for item in content:
        if isinstance(item, dict) and isinstance(item.get("text"), str):
            text_length += len(item["text"])

    is_error = bool(result.get("isError", False))
    return (
        f"content_items={len(content)}, "
        f"text_length={text_length}, "
        f"is_error={str(is_error).lower()}"
    )


def build_runtime_log(
    tool_call: dict[str, Any],
    decision: dict[str, Any],
    *,
    server_id: int | None = None,
    executed: bool = False,
    execution_status: str | None = None,
    tool_result: dict[str, Any] | None = None,
    error_summary: str | None = None,
    status: str | None = None,
) -> dict[str, Any]:
    decision_value = decision.get("decision", "LOG_ONLY")
    return {
        "agent_id": tool_call.get("agent_id", "agent-demo"),
        "session_id": tool_call.get("session_id", "session-demo"),
        "server_id": server_id if server_id is not None else tool_call.get("server_id"),
        "tool_name": tool_call.get("tool_name", "unknown_tool"),
        "arguments_summary": summarize_arguments(tool_call),
        "status": status or STATUS_BY_DECISION.get(decision_value, "allowed"),
        "decision": decision_value,
        "rule_id": decision.get("rule_id"),
        "decision_reason": decision.get("reason"),
        "severity": decision.get("severity"),
        "control_plane_revision_id": tool_call.get("control_plane_revision_id"),
        "control_plane_revision_number": tool_call.get("control_plane_revision_number"),
        "control_plane_content_hash": tool_call.get("control_plane_content_hash"),
        "executed": executed,
        "execution_status": execution_status,
        "result_summary": summarize_tool_result(tool_result),
        "error_summary": shorten(error_summary, 500) if error_summary else None,
    }


def send_runtime_log(
    log_payload: dict[str, Any],
    backend_client: BackendClient | None = None,
) -> dict[str, Any]:
    client = backend_client or BackendClient()
    return client.create_runtime_log(log_payload)


def shorten(value: str, max_length: int) -> str:
    if len(value) <= max_length:
        return value
    return f"{value[: max_length - 3]}..."


def _safe_summary_name(value: Any) -> str:
    return _sanitize_code_part(str(value))[:MAX_ARGUMENT_NAME_LENGTH]


def _safe_type_name(value: Any) -> str:
    if isinstance(value, str):
        return "string"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int) or isinstance(value, float):
        return "number"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    if value is None:
        return "null"
    return "unknown"


def _is_sensitive_summary_field(value: Any) -> bool:
    normalized = str(value).strip().lower()
    return normalized in SENSITIVE_SUMMARY_FIELDS


def _contains_sensitive_summary_field(value: Any) -> bool:
    normalized = str(value).lower()
    return any(field in normalized for field in SENSITIVE_SUMMARY_FIELDS)
