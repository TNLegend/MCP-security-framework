from pathlib import Path
import sys
from typing import Any

from pydantic import ValidationError

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
from proxy.tool_request_preparation import (
    PreparedToolRequest,
    prepare_tool_request,
)

try:
    from app.schemas.policy_decision import PolicyDecision, PolicyEffect
except ModuleNotFoundError:
    backend_path = Path(__file__).resolve().parents[1] / "backend"
    sys.path.insert(0, str(backend_path))
    from app.schemas.policy_decision import PolicyDecision, PolicyEffect


SUPPORTED_RUNTIME_OBLIGATIONS = {"LOG", "WARN"}
VALID_POLICY_EFFECTS = {"ALLOW", "DENY", "DEFER"}


def _can_execute_policy_decision(decision: PolicyDecision) -> tuple[bool, str | None]:
    if not isinstance(decision, PolicyDecision):
        raise TypeError("_can_execute_policy_decision requires a PolicyDecision.")

    if decision.effect == PolicyEffect.DENY:
        return False, "policy_denied"

    if decision.effect == PolicyEffect.DEFER:
        return False, "policy_deferred"

    if decision.effect != PolicyEffect.ALLOW:
        return False, "invalid_policy_effect"

    obligation_types = {obligation.type.value for obligation in decision.obligations}

    unsupported_obligations = obligation_types - SUPPORTED_RUNTIME_OBLIGATIONS
    if unsupported_obligations:
        return False, "unsupported_policy_obligation"

    return True, None


def _validate_policy_decision(
    raw_decision: Any,
) -> tuple[PolicyDecision | None, str | None]:
    if not isinstance(raw_decision, dict):
        return None, "invalid_policy_decision"

    if "effect" not in raw_decision:
        return None, "missing_policy_effect"

    effect = raw_decision.get("effect")
    if effect not in VALID_POLICY_EFFECTS:
        return None, "invalid_policy_effect"

    try:
        validated = PolicyDecision.model_validate(raw_decision)
    except ValidationError as exc:
        return None, _classify_policy_validation_error(exc)

    return validated, None


def _classify_policy_validation_error(exc: ValidationError) -> str:
    for error in exc.errors():
        location = tuple(str(part) for part in error.get("loc", ()))
        message = str(error.get("msg", ""))

        if any(part == "obligations" for part in location):
            return "invalid_policy_obligation"

        if "obligation" in message:
            return "invalid_policy_obligation"

        if "effect is not coherent" in message:
            return "inconsistent_policy_decision"

        if "rule_id must be present" in message:
            return "inconsistent_policy_decision"

    return "invalid_policy_decision"


class MCPProxy:
    def __init__(
        self,
        backend_client: BackendClient | None = None,
        mcp_client_class: type[MCPHttpClient] = MCPHttpClient,
    ) -> None:
        self.backend_client = backend_client or BackendClient()
        self.mcp_client_class = mcp_client_class

    def handle_tool_call(self, tool_call: dict[str, Any]) -> dict[str, Any]:
        raw_arguments = tool_call.get("arguments", {})
        if raw_arguments is None:
            raw_arguments = {}

        tool_call = {
            **tool_call,
            "tool_name": tool_call.get("tool_name"),
            "arguments": raw_arguments,
        }

        if not tool_call.get("agent_id") or not tool_call.get("session_id"):
            decision = _fail_closed_proxy_decision(
                rule_id="invalid_runtime_identity",
                reason="Tool call is missing required agent_id or session_id.",
            )
            return self._response(
                status="blocked",
                decision=decision.model_dump(mode="json"),
                executed=False,
                mcp_called=False,
                execution_status="blocked",
                tool_result=None,
                runtime_log={"created": False, "id": None, "payload": None},
                message="Tool call skipped because runtime identity is incomplete.",
                skip_reason="invalid_runtime_identity",
            )

        try:
            server = self._resolve_server(tool_call)
            tool = self._resolve_tool(server, tool_call)
        except BackendClientError as exc:
            return self._inventory_error_response(tool_call, str(exc))

        try:
            prepared_request = prepare_tool_request(
                tool_name=str(tool.get("name") or tool_call.get("tool_name") or ""),
                raw_arguments=raw_arguments,
                input_schema=tool.get("input_schema"),
            )
        except Exception:
            decision = _fail_closed_proxy_decision(
                rule_id="request_preparation_error",
                reason="Tool request could not be safely prepared.",
                severity="critical",
            )
            decision_data = decision.model_dump(mode="json")
            safe_tool_call = self._prepared_tool_call(
                tool_call,
                PreparedToolRequest(
                    arguments={},
                    arguments_valid=False,
                    validation_error_codes=("request_preparation_error",),
                    operation="unknown",
                    resource_type="unknown",
                    resource_scope="invalid",
                    canonical_resource=None,
                    required_capability="unclassified",
                ),
            )
            return self._skip_response(
                tool_call=safe_tool_call,
                server_id=server["id"],
                decision=decision_data,
                status="blocked",
                execution_status="blocked",
                message="Tool call skipped because request preparation failed.",
                error_summary="request_preparation_error",
                skip_reason="request_preparation_error",
            )

        prepared_tool_call = self._prepared_tool_call(tool_call, prepared_request)
        context = self._build_policy_context(
            prepared_tool_call,
            server,
            tool,
            prepared_request,
        )

        try:
            raw_decision = self.backend_client.request_policy_decision(context)
        except BackendClientError as exc:
            decision = _fail_closed_proxy_decision(
                rule_id="policy_error",
                reason=f"Policy decision failed: {exc}",
            )
            decision_data = decision.model_dump(mode="json")
            return self._skip_response(
                tool_call=prepared_tool_call,
                server_id=server["id"],
                decision=decision_data,
                status="blocked",
                execution_status="blocked",
                message="Tool call skipped because policy evaluation failed.",
                error_summary="policy_error",
                skip_reason="policy_error",
            )

        decision, validation_error = _validate_policy_decision(raw_decision)
        if validation_error is not None:
            decision = _fail_closed_proxy_decision(
                rule_id=validation_error,
                reason="Policy decision response is invalid.",
            )
            decision_data = decision.model_dump(mode="json")
            return self._skip_response(
                tool_call=prepared_tool_call,
                server_id=server["id"],
                decision=decision_data,
                status="blocked",
                execution_status="blocked",
                message=f"Tool call skipped because policy decision is invalid: {validation_error}.",
                error_summary=validation_error,
                skip_reason=validation_error,
            )

        if not prepared_request.arguments_valid and decision.effect != PolicyEffect.DENY:
            decision = _fail_closed_proxy_decision(
                rule_id="invalid_tool_arguments_guard",
                reason="Tool arguments are invalid or could not be safely prepared.",
                severity="high",
                evidence={
                    "arguments_valid": False,
                    "validation_error_codes": list(
                        prepared_request.validation_error_codes
                    ),
                },
                policy_revision="proxy-safety-guard-v1",
            )
            policy_decision_data = decision.model_dump(mode="json")
            return self._skip_response(
                tool_call=prepared_tool_call,
                server_id=server["id"],
                decision=policy_decision_data,
                status="blocked",
                execution_status="blocked",
                message="Tool call skipped because tool arguments are invalid.",
                error_summary="invalid_tool_arguments",
                skip_reason="invalid_tool_arguments",
            )

        can_execute, skip_reason = _can_execute_policy_decision(decision)
        policy_decision_data = decision.model_dump(mode="json")
        if not can_execute:
            return self._skip_response(
                tool_call=prepared_tool_call,
                server_id=server["id"],
                decision=policy_decision_data,
                status=self._status_for_skipped_policy_decision(decision),
                execution_status=self._execution_status_for_skip_reason(skip_reason),
                message=f"Tool call skipped by policy: {skip_reason}.",
                error_summary=skip_reason,
                skip_reason=skip_reason,
            )

        return self._execute_tool_call(prepared_tool_call, server, policy_decision_data)

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
        prepared_request: PreparedToolRequest,
    ) -> dict[str, Any]:
        trust_status = server.get("trust_status") or server.get("status") or "unknown"

        return {
            "subject": {
                "agent_id": tool_call["agent_id"],
                "role": "unknown",
                "authorization_status": "unknown",
                "authorization_revision": "unresolved",
                "grants": [],
                "allowed_capabilities": [],
                "allowed_scopes": [],
            },
            "server": {
                "id": server.get("id"),
                "endpoint": server.get("endpoint"),
                "trust_status": trust_status,
                "security_status": server.get("security_status"),
            },
            "tool": {
                "id": tool.get("id"),
                "name": tool.get("name") or tool_call.get("tool_name"),
                "risk_score": tool.get("risk_score", 0.0),
                "sensitivity": tool.get("sensitivity") or "unknown",
                "capabilities": tool.get("capabilities") or [],
                "admission_status": tool.get("admission_status", "unknown"),
                "description_risk_score": tool.get("description_risk_score", 0.0),
                "capability_mismatch": tool.get("capability_mismatch", False),
                "drift_status": tool.get("drift_status") or "unknown",
            },
            "request": {
                "operation": prepared_request.operation,
                "resource_type": prepared_request.resource_type,
                "resource_scope": prepared_request.resource_scope,
                "required_capability": prepared_request.required_capability,
                "canonical_resource": prepared_request.canonical_resource,
                "arguments": prepared_request.arguments,
                "arguments_valid": prepared_request.arguments_valid,
                "validation_error_codes": list(
                    prepared_request.validation_error_codes
                ),
                "estimated_output_size_mb": tool_call.get("estimated_output_size_mb", 0.001),
            },
            "runtime": {
                "environment": tool_call.get("environment", "local"),
                "session_id": tool_call["session_id"],
            },
        }

    def _status_for_skipped_policy_decision(self, decision: PolicyDecision) -> str:
        if decision.effect == PolicyEffect.DEFER:
            return "approval_required"
        return "blocked"

    def _execution_status_for_skip_reason(self, skip_reason: str | None) -> str:
        if skip_reason == "policy_deferred":
            return "approval_required"
        return "blocked"

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
        error_summary: str | None = None,
        skip_reason: str | None = None,
    ) -> dict[str, Any]:
        log_payload = build_runtime_log(
            tool_call,
            decision,
            server_id=server_id,
            executed=False,
            execution_status=execution_status,
            error_summary=error_summary,
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
            skip_reason=skip_reason,
        )

    def _inventory_error_response(
        self,
        tool_call: dict[str, Any],
        error_summary: str,
    ) -> dict[str, Any]:
        decision = _fail_closed_proxy_decision(
            rule_id="inventory_error",
            reason=error_summary,
        )
        decision_data = decision.model_dump(mode="json")
        log_payload = build_runtime_log(
            tool_call,
            decision_data,
            server_id=None,
            executed=False,
            execution_status="blocked",
            error_summary=error_summary,
            status="blocked",
        )
        runtime_log = self._send_runtime_log(log_payload)

        return self._response(
            status="blocked",
            decision=decision_data,
            executed=False,
            mcp_called=False,
            execution_status="blocked",
            tool_result=None,
            runtime_log=runtime_log,
            message="Tool call skipped because inventory resolution failed.",
            skip_reason="inventory_error",
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
            skip_reason=None,
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
        skip_reason: str | None = None,
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
            "skip_reason": skip_reason,
        }

    def _prepared_tool_call(
        self,
        tool_call: dict[str, Any],
        prepared_request: PreparedToolRequest,
    ) -> dict[str, Any]:
        prepared_tool_call = dict(tool_call)
        prepared_tool_call["arguments"] = prepared_request.arguments
        prepared_tool_call["arguments_valid"] = prepared_request.arguments_valid
        prepared_tool_call["validation_error_codes"] = list(
            prepared_request.validation_error_codes
        )
        prepared_tool_call["operation"] = prepared_request.operation
        prepared_tool_call["resource_type"] = prepared_request.resource_type
        prepared_tool_call["resource_scope"] = prepared_request.resource_scope
        prepared_tool_call["required_capability"] = prepared_request.required_capability
        prepared_tool_call["canonical_resource"] = prepared_request.canonical_resource
        return prepared_tool_call


def _fail_closed_proxy_decision(
    *,
    rule_id: str,
    reason: str,
    severity: str = "critical",
    evidence: dict[str, Any] | None = None,
    recommended_action: str | None = None,
    policy_revision: str = "proxy-fail-closed-v1",
) -> PolicyDecision:
    raw_decision = {
        "effect": "DENY",
        "obligations": [
            {"type": "LOG", "parameters": {}},
            {"type": "ALERT", "parameters": {}},
        ],
        "rule_ids": [rule_id],
        "reason": reason,
        "severity": severity,
        "evidence": evidence or {},
        "recommended_action": recommended_action,
        "policy_revision": policy_revision,
        "decision": "BLOCK",
        "rule_id": rule_id,
    }
    return PolicyDecision.model_validate(raw_decision)
