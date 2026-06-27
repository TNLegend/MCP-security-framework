from typing import Any

from proxy.backend_client import BackendClient


STATUS_BY_DECISION = {
    "ALLOW": "allowed",
    "WARN": "allowed",
    "LOG_ONLY": "allowed",
    "BLOCK": "blocked",
    "ASK_APPROVAL": "approval_required",
    "LIMIT": "limited",
}

EXECUTING_DECISIONS = {"ALLOW", "WARN", "LOG_ONLY"}


def summarize_arguments(arguments: dict[str, Any]) -> str:
    if not arguments:
        return "no_arguments"

    parts = []
    for key, value in arguments.items():
        if key == "path":
            parts.append(f"path={shorten(str(value), 160)}")
            continue

        if isinstance(value, str):
            parts.append(f"{key}={shorten(value, 80)}")
        elif value is None:
            parts.append(f"{key}=null")
        else:
            parts.append(f"{key}=<{type(value).__name__}>")

    return ", ".join(parts)[:500]


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
    arguments = tool_call.get("arguments") or {}

    return {
        "agent_id": tool_call.get("agent_id", "agent-demo"),
        "session_id": tool_call.get("session_id", "session-demo"),
        "server_id": server_id if server_id is not None else tool_call.get("server_id"),
        "tool_name": tool_call.get("tool_name", "unknown_tool"),
        "arguments_summary": summarize_arguments(arguments),
        "status": status or STATUS_BY_DECISION.get(decision_value, "allowed"),
        "decision": decision_value,
        "rule_id": decision.get("rule_id"),
        "decision_reason": decision.get("reason"),
        "severity": decision.get("severity"),
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
