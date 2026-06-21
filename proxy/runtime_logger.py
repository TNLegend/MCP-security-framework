STATUS_BY_DECISION = {
    "ALLOW": "allowed",
    "WARN": "allowed",
    "LOG_ONLY": "allowed",
    "BLOCK": "blocked",
    "ASK_APPROVAL": "approval_required",
    "LIMIT": "limited",
}


def build_runtime_log(tool_call: dict, decision: dict) -> dict:
    decision_value = decision.get("decision", "LOG_ONLY")

    return {
        "agent_id": tool_call.get("agent_id"),
        "session_id": tool_call.get("session_id"),
        "server_id": tool_call.get("server_id"),
        "tool_name": tool_call.get("tool_name"),
        "arguments_summary": tool_call.get("arguments", {}),
        "decision": decision_value,
        "rule_id": decision.get("rule_id"),
        "status": STATUS_BY_DECISION.get(decision_value, "allowed"),
    }
