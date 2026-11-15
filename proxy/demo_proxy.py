import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from proxy.mcp_proxy import MCPProxy
from scripts.local_identity_provider import issue_access_token, load_project_env


DEMO_IDENTITY_SUBJECT = "service-account-llm-agent-demo"
DEMO_MCP_ENDPOINT = "http://127.0.0.1:9000/mcp"


def _demo_server_id(proxy: MCPProxy) -> int:
    server = proxy.backend_client.find_server(endpoint=DEMO_MCP_ENDPOINT)
    if (
        not isinstance(server, dict)
        or isinstance(server.get("id"), bool)
        or not isinstance(server.get("id"), int)
    ):
        raise RuntimeError(
            "The MCP lab is not registered in Inventory. Run discovery first."
        )
    return server["id"]


def _demo_cases(*, server_id: int, session_token: str) -> list[tuple[str, dict]]:
    return [
        (
            "Case 1 - contract read (requires approval)",
            {
                "server_id": server_id,
                "session_token": session_token,
                "tool_name": "read_file",
                "arguments": {
                    "path": "contracts/contract1.txt",
                },
            },
        ),
        (
            "Case 2 - blocked .env read",
            {
                "server_id": server_id,
                "session_token": session_token,
                "tool_name": "read_file",
                "arguments": {
                    "path": ".env",
                },
            },
        ),
        (
            "Case 3 - directory listing (requires approval)",
            {
                "server_id": server_id,
                "session_token": session_token,
                "tool_name": "list_files",
                "arguments": {},
            },
        ),
    ]


def main() -> None:
    load_project_env()
    print("MCP Security Framework - Proxy Runtime Demo")
    print("=" * 50)
    print("Preconditions:")
    print("1. Backend must be running at http://127.0.0.1:8000")
    print("2. MCP lab server must be running at http://127.0.0.1:9000/mcp")
    print("3. Discovery must have been run at least once")
    print("4. Local identity provider must be running with the configured JWKS URL")
    print("5. The demo agent must have a published identity binding and capability grants")
    print("6. ALLOW cases also require approved observations and published tool contracts")
    print("=" * 50)

    proxy = MCPProxy()
    server_id = _demo_server_id(proxy)
    trusted_session = proxy.create_trusted_session(
        issue_access_token(subject=DEMO_IDENTITY_SUBJECT)
    )

    for label, tool_call in _demo_cases(
        server_id=server_id,
        session_token=trusted_session["session_token"],
    ):
        print()
        print(f"=== {label} ===")
        result = proxy.handle_tool_call(tool_call)
        print_case_summary(tool_call, result)

    print()
    print("Check runtime logs in the authenticated Control Center:")
    print("http://127.0.0.1:5173/ -> Runtime Calls")


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
