from proxy.policy_client import request_decision
from proxy.runtime_logger import build_runtime_log


class MCPProxy:
    def __init__(self, decision_client=request_decision) -> None:
        self.decision_client = decision_client

    def handle_tool_call(self, tool_call: dict) -> dict:
        context = self._build_policy_context(tool_call)
        decision = self.decision_client(context)
        runtime_log = build_runtime_log(tool_call, decision)

        if decision["decision"] == "BLOCK":
            return {
                "status": "blocked",
                "decision": decision,
                "runtime_log": runtime_log,
                "result": None,
                "message": "Tool call blocked by MCP Security Framework.",
            }

        if decision["decision"] == "ASK_APPROVAL":
            return {
                "status": "approval_required",
                "decision": decision,
                "runtime_log": runtime_log,
                "result": None,
                "message": "Tool call requires human approval.",
            }

        if decision["decision"] == "LIMIT":
            return {
                "status": "limited",
                "decision": decision,
                "runtime_log": runtime_log,
                "result": {
                    "simulated": True,
                    "limited": True,
                    "message": "Tool call would be executed with output limits.",
                },
            }

        return {
            "status": "allowed",
            "decision": decision,
            "runtime_log": runtime_log,
            "result": {
                "simulated": True,
                "message": "Tool call would be executed by the MCP server.",
            },
        }

    def _build_policy_context(self, tool_call: dict) -> dict:
        return {
            "agent_id": tool_call.get("agent_id"),
            "server_id": tool_call.get("server_id"),
            "server_status": tool_call.get("server_status", "unknown"),
            "tool_name": tool_call.get("tool_name"),
            "tool_risk_score": tool_call.get("tool_risk_score", 0),
            "tool_sensitivity": tool_call.get("tool_sensitivity", "medium"),
            "arguments": tool_call.get("arguments", {}),
            "estimated_output_size_mb": tool_call.get("estimated_output_size_mb", 0),
        }
