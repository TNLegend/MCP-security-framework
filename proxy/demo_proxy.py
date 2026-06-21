import json

from proxy.mcp_proxy import MCPProxy


def main() -> None:
    proxy = MCPProxy()

    allowed_call = {
        "agent_id": "agent-demo",
        "session_id": "session-001",
        "server_id": "filesystem-mcp",
        "server_status": "trusted",
        "tool_name": "read_file",
        "tool_risk_score": 10,
        "tool_sensitivity": "medium",
        "arguments": {
            "path": "contracts/contract1.txt",
        },
    }

    blocked_call = {
        "agent_id": "agent-demo",
        "session_id": "session-002",
        "server_id": "filesystem-mcp",
        "server_status": "trusted",
        "tool_name": "read_file",
        "tool_risk_score": 10,
        "tool_sensitivity": "medium",
        "arguments": {
            "path": ".env",
        },
    }

    for label, tool_call in [
        ("Allowed call", allowed_call),
        ("Blocked call", blocked_call),
    ]:
        print(f"=== {label} ===")
        result = proxy.handle_tool_call(tool_call)
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
