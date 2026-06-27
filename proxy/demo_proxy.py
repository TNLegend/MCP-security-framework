import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from proxy.mcp_proxy import MCPProxy


def main() -> None:
    print("MCP Security Framework - Proxy Runtime Demo")
    print("=" * 50)
    print("Preconditions:")
    print("1. Backend must be running at http://127.0.0.1:8000")
    print("2. MCP lab server must be running at http://127.0.0.1:9000/mcp")
    print("3. Discovery must have been run at least once")
    print("=" * 50)

    proxy = MCPProxy()

    demo_cases = [
        (
            "Case 1 - allowed contract read",
            {
                "agent_id": "agent-demo",
                "session_id": "session-runtime-allow",
                "tool_name": "read_file",
                "arguments": {
                    "path": "contracts/contract1.txt",
                },
            },
        ),
        (
            "Case 2 - blocked .env read",
            {
                "agent_id": "agent-demo",
                "session_id": "session-runtime-block",
                "tool_name": "read_file",
                "arguments": {
                    "path": ".env",
                },
            },
        ),
    ]

    for label, tool_call in demo_cases:
        print()
        print(f"=== {label} ===")
        result = proxy.handle_tool_call(tool_call)
        print_case_summary(tool_call, result)

    print()
    print("Check runtime logs:")
    print("Invoke-RestMethod http://127.0.0.1:8000/api/v1/runtime/logs")


def print_case_summary(tool_call: dict, result: dict) -> None:
    decision = result.get("decision") or {}
    summary = {
        "tool_name": tool_call.get("tool_name"),
        "arguments": tool_call.get("arguments"),
        "decision": decision.get("decision"),
        "rule_id": decision.get("rule_id"),
        "reason": decision.get("reason"),
        "executed": result.get("executed"),
        "mcp_called": result.get("mcp_called"),
        "execution_status": result.get("execution_status"),
        "runtime_log_created": result.get("runtime_log_created"),
        "runtime_log_id": result.get("runtime_log_id"),
        "result_summary": result.get("result_summary"),
        "message": result.get("message"),
    }
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
