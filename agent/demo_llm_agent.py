import json
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agent.llm_adapter.adapter import LLMAdapter
from agent.llm_providers.base import load_project_env
from proxy.backend_client import BackendClient
from proxy.mcp_proxy import MCPProxy


PROMPTS = [
    "Lis le fichier contracts/contract1.txt",
    "Lis le fichier .env",
]


def main() -> None:
    load_project_env()
    print("MCP Security Framework - LLM Agent Demo")
    print("=" * 50)
    print("Preconditions:")
    print("1. Backend must be running at http://127.0.0.1:8000")
    print("2. MCP lab server must be running at http://127.0.0.1:9000/mcp")
    print("3. Discovery must have been run at least once")
    print("4. LLM_PROVIDER can be mock, gemini, or groq")
    print("=" * 50)

    backend_client = BackendClient()
    adapter = LLMAdapter()
    proxy = MCPProxy(backend_client=backend_client)

    for index, user_prompt in enumerate(PROMPTS, start=1):
        print()
        print(f"=== Prompt {index} ===")
        print(f"user_prompt: {user_prompt}")
        result = run_prompt(
            user_prompt=user_prompt,
            session_id=f"llm-agent-demo-{index}",
            backend_client=backend_client,
            adapter=adapter,
            proxy=proxy,
        )
        print(json.dumps(result, indent=2))

    print()
    print("Check runtime logs:")
    print("Invoke-RestMethod http://127.0.0.1:8000/api/v1/runtime/logs")


def run_prompt(
    *,
    user_prompt: str,
    session_id: str,
    backend_client: BackendClient,
    adapter: LLMAdapter,
    proxy: MCPProxy,
) -> dict[str, Any]:
    try:
        server = select_mcp_lab_server(backend_client)
        available_tools = build_available_tools(backend_client, server["id"])
    except Exception as exc:
        return {
            "error": f"Inventory lookup failed: {exc}",
            "proxy_called": False,
            "runtime_log_created": False,
        }

    proposal = adapter.generate_tool_proposal(user_prompt, available_tools)
    summary = {
        "provider": proposal.get("provider"),
        "fallback_used": proposal.get("fallback_used", False),
        "provider_error": proposal.get("provider_error"),
        "should_call_tool": proposal.get("should_call_tool"),
        "proposed_tool": proposal.get("tool_name"),
        "proposed_arguments": proposal.get("arguments"),
        "proposal_rationale": proposal.get("rationale"),
    }

    if not proposal.get("should_call_tool"):
        summary.update(
            {
                "proxy_called": False,
                "policy_decision": None,
                "runtime_log_created": False,
                "message": proposal.get("user_message"),
            }
        )
        return summary

    tool_call = {
        "agent_id": "llm-agent-demo",
        "session_id": session_id,
        "server_id": server["id"],
        "tool_name": proposal["tool_name"],
        "arguments": proposal["arguments"],
    }
    proxy_result = proxy.handle_tool_call(tool_call)
    decision = proxy_result.get("decision") or {}

    summary.update(
        {
            "proxy_called": True,
            "policy_decision": decision.get("decision"),
            "matched_rule_id": decision.get("rule_id"),
            "reason": decision.get("reason"),
            "executed": proxy_result.get("executed"),
            "mcp_called": proxy_result.get("mcp_called"),
            "execution_status": proxy_result.get("execution_status"),
            "runtime_log_created": proxy_result.get("runtime_log_created"),
            "runtime_log_id": proxy_result.get("runtime_log_id"),
            "result_summary": proxy_result.get("result_summary"),
        }
    )
    return summary


def select_mcp_lab_server(backend_client: BackendClient) -> dict[str, Any]:
    server = backend_client.find_server()
    if server is None:
        raise RuntimeError("No local Streamable HTTP MCP server found.")
    return server


def build_available_tools(
    backend_client: BackendClient,
    server_id: int,
) -> list[dict[str, Any]]:
    tools = [
        tool
        for tool in backend_client.list_tools()
        if tool.get("server_id") == server_id
    ]

    return [
        {
            "name": tool.get("name"),
            "title": tool.get("title"),
            "description": tool.get("description"),
            "input_schema": tool.get("input_schema"),
            "sensitivity": tool.get("sensitivity"),
            "risk_score": tool.get("risk_score"),
            "policy_status": tool.get("policy_status"),
        }
        for tool in tools
    ]


if __name__ == "__main__":
    main()
