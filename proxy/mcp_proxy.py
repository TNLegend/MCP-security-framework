from typing import Any

from proxy.backend_client import BackendClient, BackendClientError
from proxy.http_mcp_client import (
    MCPHttpClient,
    MCPHttpError,
    MCPProtocolError,
    SUPPORTED_PROTOCOL_VERSION,
)
from proxy.runtime_logger import (
    build_runtime_log,
    send_runtime_log,
    summarize_tool_result,
)


EXECUTING_DECISIONS = {"ALLOW", "WARN", "LOG_ONLY"}


class MCPProxy:
    def __init__(
        self,
        backend_client: BackendClient | None = None,
        mcp_client_class: type[MCPHttpClient] = MCPHttpClient,
    ) -> None:
        self.backend_client = backend_client or BackendClient()
        self.mcp_client_class = mcp_client_class

    def handle_tool_call(self, tool_call: dict[str, Any]) -> dict[str, Any]:
        tool_call = {
            "agent_id": tool_call.get("agent_id", "agent-demo"),
            "session_id": tool_call.get("session_id", "session-demo"),
            "tool_name": tool_call.get("tool_name"),
            "arguments": tool_call.get("arguments") or {},
            **tool_call,
        }

        try:
            server = self._resolve_server(tool_call)
            tool = self._resolve_tool(server, tool_call)
        except BackendClientError as exc:
            return self._inventory_error_response(tool_call, str(exc))

        context = self._build_policy_context(tool_call, server, tool)

        try:
            decision = self.backend_client.request_policy_decision(context)
        except BackendClientError as exc:
            decision = {
                "decision": "BLOCK",
                "rule_id": "policy_error",
                "reason": f"Policy decision failed: {exc}",
                "severity": "high",
            }
            return self._skip_response(
                tool_call=tool_call,
                server_id=server["id"],
                decision=decision,
                status="blocked",
                execution_status="policy_error",
                message="Tool call skipped because policy evaluation failed.",
            )

        decision_value = decision.get("decision", "LOG_ONLY")

        if decision_value == "BLOCK":
            return self._skip_response(
                tool_call=tool_call,
                server_id=server["id"],
                decision=decision,
                status="blocked",
                execution_status="skipped",
                message="Tool call blocked before MCP execution.",
            )

        if decision_value == "ASK_APPROVAL":
            return self._skip_response(
                tool_call=tool_call,
                server_id=server["id"],
                decision=decision,
                status="approval_required",
                execution_status="skipped",
                message="Tool call requires human approval and was not executed.",
            )

        if decision_value == "LIMIT":
            return self._skip_response(
                tool_call=tool_call,
                server_id=server["id"],
                decision=decision,
                status="limited",
                execution_status="skipped",
                message="Tool call limited and skipped in this Phase 2 runtime.",
            )

        if decision_value not in EXECUTING_DECISIONS:
            return self._skip_response(
                tool_call=tool_call,
                server_id=server["id"],
                decision=decision,
                status="blocked",
                execution_status="policy_error",
                message=f"Unsupported policy decision: {decision_value}",
            )

        return self._execute_tool_call(tool_call, server, decision)

    def _resolve_server(self, tool_call: dict[str, Any]) -> dict[str, Any]:
        raw_server_id = tool_call.get("server_id")
        server_id = None
        server_endpoint = tool_call.get("server_endpoint")

        if isinstance(raw_server_id, int):
            server_id = raw_server_id
        elif isinstance(raw_server_id, str) and raw_server_id.isdigit():
            server_id = int(raw_server_id)
        elif isinstance(raw_server_id, str) and raw_server_id.startswith("http"):
            server_endpoint = raw_server_id

        server = self.backend_client.find_server(
            server_id=server_id,
            endpoint=server_endpoint,
        )
        if server is None:
            raise BackendClientError("No matching Streamable HTTP MCP server found.")

        endpoint = str(server.get("endpoint") or "")
        if not endpoint.startswith("http://"):
            raise BackendClientError(
                f"Resolved server endpoint is not HTTP Streamable MCP: {endpoint}"
            )

        return server

    def _resolve_tool(
        self,
        server: dict[str, Any],
        tool_call: dict[str, Any],
    ) -> dict[str, Any]:
        tool_name = tool_call.get("tool_name")
        if not tool_name:
            raise BackendClientError("Tool call is missing tool_name.")

        tool = self.backend_client.find_tool(server["id"], str(tool_name))
        if tool is None:
            raise BackendClientError(
                f"Tool '{tool_name}' was not found for server id {server['id']}."
            )
        return tool

    def _build_policy_context(
        self,
        tool_call: dict[str, Any],
        server: dict[str, Any],
        tool: dict[str, Any],
    ) -> dict[str, Any]:
        trust_status = server.get("trust_status") or server.get("status") or "unknown"

        return {
            "agent_id": tool_call.get("agent_id"),
            "session_id": tool_call.get("session_id"),
            "server_id": server.get("id"),
            "server_endpoint": server.get("endpoint"),
            "server_status": trust_status,
            "trust_status": trust_status,
            "server_security_status": server.get("security_status"),
            "tool_name": tool.get("name") or tool_call.get("tool_name"),
            "tool_risk_score": tool.get("risk_score", 0),
            "tool_sensitivity": tool.get("sensitivity", "unknown"),
            "arguments": tool_call.get("arguments") or {},
            "estimated_output_size_mb": tool_call.get("estimated_output_size_mb", 0.001),
        }

    def _execute_tool_call(
        self,
        tool_call: dict[str, Any],
        server: dict[str, Any],
        decision: dict[str, Any],
    ) -> dict[str, Any]:
        protocol_version = server.get("protocol_version") or SUPPORTED_PROTOCOL_VERSION
        mcp_client = self.mcp_client_class(
            endpoint=server["endpoint"],
            protocol_version=protocol_version,
        )

        mcp_called = False
        try:
            mcp_called = True
            tool_result = mcp_client.call_tool(
                str(tool_call.get("tool_name")),
                tool_call.get("arguments") or {},
            )
            execution_status = (
                "tool_error" if bool(tool_result.get("isError", False)) else "success"
            )
            log_payload = build_runtime_log(
                tool_call,
                decision,
                server_id=server["id"],
                executed=True,
                execution_status=execution_status,
                tool_result=tool_result,
                status="allowed",
            )
            runtime_log = self._send_runtime_log(log_payload)

            return self._response(
                status="allowed",
                decision=decision,
                executed=True,
                mcp_called=mcp_called,
                execution_status=execution_status,
                tool_result=tool_result,
                runtime_log=runtime_log,
                message="Tool call executed through the MCP HTTP server.",
            )
        except MCPHttpError as exc:
            return self._execution_error_response(
                tool_call=tool_call,
                server_id=server["id"],
                decision=decision,
                mcp_called=mcp_called,
                execution_status="http_error",
                error_summary=str(exc),
            )
        except MCPProtocolError as exc:
            return self._execution_error_response(
                tool_call=tool_call,
                server_id=server["id"],
                decision=decision,
                mcp_called=mcp_called,
                execution_status="protocol_error",
                error_summary=str(exc),
            )

    def _skip_response(
        self,
        *,
        tool_call: dict[str, Any],
        server_id: int | None,
        decision: dict[str, Any],
        status: str,
        execution_status: str,
        message: str,
    ) -> dict[str, Any]:
        log_payload = build_runtime_log(
            tool_call,
            decision,
            server_id=server_id,
            executed=False,
            execution_status=execution_status,
            status=status,
        )
        runtime_log = self._send_runtime_log(log_payload)

        return self._response(
            status=status,
            decision=decision,
            executed=False,
            mcp_called=False,
            execution_status=execution_status,
            tool_result=None,
            runtime_log=runtime_log,
            message=message,
        )

    def _inventory_error_response(
        self,
        tool_call: dict[str, Any],
        error_summary: str,
    ) -> dict[str, Any]:
        decision = {
            "decision": "BLOCK",
            "rule_id": "inventory_error",
            "reason": error_summary,
            "severity": "high",
        }
        log_payload = build_runtime_log(
            tool_call,
            decision,
            server_id=None,
            executed=False,
            execution_status="inventory_error",
            error_summary=error_summary,
            status="blocked",
        )
        runtime_log = self._send_runtime_log(log_payload)

        return self._response(
            status="blocked",
            decision=decision,
            executed=False,
            mcp_called=False,
            execution_status="inventory_error",
            tool_result=None,
            runtime_log=runtime_log,
            message="Tool call skipped because inventory resolution failed.",
        )

    def _execution_error_response(
        self,
        *,
        tool_call: dict[str, Any],
        server_id: int,
        decision: dict[str, Any],
        mcp_called: bool,
        execution_status: str,
        error_summary: str,
    ) -> dict[str, Any]:
        log_payload = build_runtime_log(
            tool_call,
            decision,
            server_id=server_id,
            executed=mcp_called,
            execution_status=execution_status,
            error_summary=error_summary,
            status="allowed",
        )
        runtime_log = self._send_runtime_log(log_payload)

        return self._response(
            status="error",
            decision=decision,
            executed=mcp_called,
            mcp_called=mcp_called,
            execution_status=execution_status,
            tool_result=None,
            runtime_log=runtime_log,
            message=error_summary,
        )

    def _send_runtime_log(self, log_payload: dict[str, Any]) -> dict[str, Any]:
        try:
            created_log = send_runtime_log(log_payload, self.backend_client)
            return {
                "created": True,
                "id": created_log.get("id"),
                "payload": log_payload,
                "response": created_log,
            }
        except BackendClientError as exc:
            return {
                "created": False,
                "id": None,
                "payload": log_payload,
                "error": str(exc),
            }

    def _response(
        self,
        *,
        status: str,
        decision: dict[str, Any],
        executed: bool,
        mcp_called: bool,
        execution_status: str,
        tool_result: dict[str, Any] | None,
        runtime_log: dict[str, Any],
        message: str,
    ) -> dict[str, Any]:
        return {
            "status": status,
            "decision": decision,
            "rule_id": decision.get("rule_id"),
            "reason": decision.get("reason"),
            "executed": executed,
            "mcp_called": mcp_called,
            "execution_status": execution_status,
            "tool_result": tool_result,
            "result_summary": summarize_tool_result(tool_result),
            "runtime_log_created": runtime_log.get("created", False),
            "runtime_log_id": runtime_log.get("id"),
            "runtime_log": runtime_log.get("payload"),
            "message": message,
        }
