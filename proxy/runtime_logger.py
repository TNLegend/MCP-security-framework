import math
import time
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

# Only framework-authored, fixed diagnostic codes may reach persistent
# audit error fields. Data originating from remote MCP messages, HTTP errors,
# provider diagnostics or exception strings is never a safe audit payload.
from shared.explanation_catalog import (
    SAFE_RUNTIME_ERROR_CODES,
    RUNTIME_EXPLANATION_CHECKS,
    RUNTIME_EFFECT_CHECKS,
    RUNTIME_GUARDS,
)



def safe_runtime_error_code(error: object) -> str:
    return error if isinstance(error, str) and error in SAFE_RUNTIME_ERROR_CODES else "untrusted_error_redacted"


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
        **(
            {"effects": effects_summary}
            if (effects_summary := _safe_effect_summary(tool_call.get("effect_summary")))
            else {}
        ),
    }


_SUMMARY_LIMIT_CODES = frozenset({
    "REFERENCE_VALUES_NOT_RECORDED",
    "SCOPE_AUTHORIZATION_DECIDED_BY_OPA",
    "EFFECTS_TRUNCATED",
    "NON_EXPLICIT_REFERENCE_PRESENT",
    "UNRESOLVED_BINDING_PRESENT",
})


def _safe_effect_summary(value: Any) -> dict[str, Any] | None:
    """RT-12: re-validate the Proxy-built multi-effect summary before audit.

    Only identifiers, enumerated statuses and counts survive; anything
    unexpected drops the whole summary rather than persisting raw data.
    """
    if not isinstance(value, dict) or value.get("summary_version") != 1:
        return None
    effects = value.get("effects")
    count = value.get("effect_count")
    if not isinstance(effects, list) or len(effects) > 16:
        return None
    if not isinstance(count, int) or isinstance(count, bool) or not 0 <= count <= 10_000:
        return None
    limits = value.get("limits")
    if not isinstance(limits, list) or not all(
        isinstance(item, str) and item in _SUMMARY_LIMIT_CODES for item in limits
    ):
        return None

    def names(items: Any) -> list[str] | None:
        if not isinstance(items, list) or len(items) > 16:
            return None
        if not all(isinstance(item, str) and 0 < len(item) <= 128 for item in items):
            return None
        return [_safe_summary_name(item) for item in items]

    safe_effects = []
    for item in effects:
        if not isinstance(item, dict):
            return None
        resource_types = names(item.get("resource_types"))
        statuses = names(item.get("binding_statuses"))
        scopes = names(item.get("candidate_scope_ids"))
        references = item.get("reference_count")
        if None in (resource_types, statuses, scopes):
            return None
        if not isinstance(references, int) or isinstance(references, bool) or references < 0:
            return None
        safe_effects.append({
            "effect_id": _safe_summary_name(item.get("effect_id")),
            "capability": _safe_summary_name(item.get("capability")),
            "resource_types": resource_types,
            "reference_precision": _safe_summary_name(item.get("reference_precision")),
            "binding_statuses": statuses,
            "reference_count": min(references, 10_000),
            "candidate_scope_ids": scopes,
        })
    capabilities = names(value.get("capabilities"))
    if capabilities is None:
        return None
    return {
        "summary_version": 1,
        "effect_count": count,
        "capabilities": capabilities,
        "effects": safe_effects,
        "limits": sorted(set(limits)),
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


# Only store bounded, enumerated OPA diagnostics. The complete policy
# evidence may contain resource names and must not be copied into audit logs.



def summarize_policy_evidence(decision: dict[str, Any]) -> dict[str, Any] | None:
    """Preserve verifiable, low-sensitivity failure codes, never raw MCP data."""
    evidence = decision.get("evidence")
    if not isinstance(evidence, dict) or evidence.get("explanation_version") != 1:
        return None
    if evidence.get("scope") != "runtime_security_model_v2":
        return None
    checks = evidence.get("failed_checks")
    effects = evidence.get("failed_effects")
    if not isinstance(checks, list) or len(checks) > 32:
        return None
    if not isinstance(effects, list) or len(effects) > 32:
        return None
    if not all(isinstance(item, str) and item in RUNTIME_EXPLANATION_CHECKS
               for item in checks):
        return None
    safe_effects = []
    for item in effects:
        if not isinstance(item, dict):
            return None
        code = item.get("check")
        identifier = item.get("effect_id")
        capability = item.get("capability")
        if code not in RUNTIME_EFFECT_CHECKS:
            return None
        if not all(isinstance(value, str) and 0 < len(value) <= 128
                   and all(char in "abcdefghijklmnopqrstuvwxyz0123456789._-"
                           for char in value)
                   for value in (identifier, capability)):
            return None
        safe_effects.append({
            "check": code, "effect_id": identifier, "capability": capability,
        })
    return {
        "explanation_version": 1,
        "scope": "runtime_security_model_v2",
        "failed_checks": sorted(set(checks)),
        "failed_effects": safe_effects,
    }


def safe_runtime_decision_reason(decision: dict[str, Any]) -> str:
    # Error strings can contain external URLs, headers and token fragments.
    # For these two paths the reason is known from the trusted rule ID.
    if decision.get("rule_id") == "policy_error":
        return "Runtime policy evaluation failed; call blocked as a precaution."
    if decision.get("rule_id") == "inventory_error":
        return "Tool inventory verification failed; call blocked as a precaution."
    value = decision.get("reason")
    if not isinstance(value, str) or not value or len(value) > 512:
        return "Runtime decision details unavailable."
    lower = value.lower()
    if any(token in lower for token in (
        "authorization:", "access_token", "secret_key", "password=",
        "bearer ", "http://", "https://", "traceback", "\n", "\r",
    )):
        return "Runtime decision details withheld for security."
    return value


def _safe_runtime_identifier(value: object, *, max_length: int) -> str | None:
    if not (isinstance(value, str) and 0 < len(value) <= max_length):
        return None
    return value if all(
        char in "abcdefghijklmnopqrstuvwxyz0123456789._-" for char in value
    ) else None


def _verified_opa_provenance(tool_call: dict[str, Any]) -> dict[str, Any] | None:
    # This field is generated by the Proxy only AFTER PolicyDecision validation
    # and immutable-revision binding verification; caller _runtime_* fields
    # are removed at MCP ingress. Still bound/validate before persistence.
    snapshot = tool_call.get("_runtime_verified_opa_decision")
    if not isinstance(snapshot, dict):
        return None
    value = snapshot.get("decision")
    if value not in EXECUTING_DECISIONS | {"BLOCK", "ASK_APPROVAL", "LIMIT"}:
        return None
    rule_id = _safe_runtime_identifier(snapshot.get("rule_id"), max_length=128)
    revision = _safe_runtime_identifier(snapshot.get("policy_revision"), max_length=96)
    if rule_id is None or revision is None:
        return None
    return {
        "opa_decision": value,
        "opa_rule_id": rule_id,
        "opa_policy_revision": revision,
        "opa_explanation": summarize_policy_evidence(snapshot),
    }


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
    # RT-07: a missing or unrecognised decision is never recorded as an
    # authorisation. It maps to status "unknown_decision" below.
    raw_decision_value = decision.get("decision")
    decision_value = (
        raw_decision_value
        if isinstance(raw_decision_value, str) and raw_decision_value in STATUS_BY_DECISION
        else "UNKNOWN"
    )
    argument_summary = summarize_arguments(tool_call)
    explanation = summarize_policy_evidence(decision)
    original_opa = _verified_opa_provenance(tool_call)
    if execution_status == "upstream_outcome_unknown":
        dispatch_state = "SENT_OUTCOME_UNKNOWN"
    elif execution_status == "authorized_pending_execution":
        dispatch_state = "PENDING"
    elif executed:
        dispatch_state = "SENT_CONFIRMED"
    else:
        dispatch_state = "NOT_SENT"
    revision = _safe_runtime_identifier(
        decision.get("policy_revision"), max_length=96,
    )
    rule_id = decision.get("rule_id")
    same_as_opa = (
        original_opa is not None
        and original_opa["opa_decision"] == decision_value
        and original_opa["opa_rule_id"] == rule_id
    )
    if same_as_opa or (
        original_opa is None
        and explanation is not None
        and rule_id in {"allow_generic_security_model_v2", "deny_generic_security_model_v2",
                        "deny_sensitive_resource"}
    ):
        # Compat: a pre-provenance trusted V2 event still carries a
        # validated explanation and an unambiguous policy rule ID.
        basis = "POLICY"
    elif rule_id in {"emergency_deny_active", "blocked_by_emergency_deny"}:
        basis = "EMERGENCY"
    elif revision == "opa-authoritative-fail-closed-v1" or rule_id in {
        "opa_unavailable", "opa_timeout", "subject_authorization_unavailable",
        "dispatch_admission_unavailable", "trusted_identity_unavailable",
        "policy_error", "inventory_error", "invalid_policy_decision",
        "runtime_audit_unavailable",
        "emergency_deny_store_unavailable", "emergency_deny_store_invalid_response",
    }:
        basis = "FAIL_CLOSED_TECHNICAL"
    elif original_opa is not None:
        # This final refusal was imposed AFTER OPA and must not be labeled as
        # a rejection by OPA itself.
        basis = "GUARD"
    elif rule_id in {
        "trusted_identity_required", "untrusted_server",
        "tool_not_approved", "unsupported_mcp_protocol_profile",
        "unsafe_resource_guard",
    }:
        basis = "PRE_POLICY_GATE"
    elif isinstance(rule_id, str) and rule_id in RUNTIME_GUARDS:
        phase = RUNTIME_GUARDS[rule_id]["phase"]
        basis = (
            "PRE_POLICY_GATE" if phase == "PRE_POLICY"
            else "FAIL_CLOSED_TECHNICAL" if phase == "FAIL_CLOSED"
            else "GUARD"
        )
    else:
        basis = "UNKNOWN"
    # A closed-schema guard record is produced exclusively from a known,
    # framework-authored final rule, never from the remote MCP response.
    guard_spec = RUNTIME_GUARDS.get(rule_id) if isinstance(rule_id, str) else None
    guard_record = (
        {"explanation_version": 1, "source": "proxy_internal_guard",
         "rule_id": rule_id, "phase": guard_spec["phase"]}
        if decision_value == "BLOCK" and guard_spec is not None
        and basis in {"GUARD", "PRE_POLICY_GATE", "FAIL_CLOSED_TECHNICAL"}
        else None
    )
    return {
        # Generated by the trusted Proxy for every logical tools/call. Reuse
        # the identifier for intent and outcome, not individual log writes.
        "operation_id": tool_call.get("_runtime_operation_id"),
        "event_phase": (
            "intent" if execution_status == "authorized_pending_execution"
            else "outcome"
        ) if tool_call.get("_runtime_operation_id") else None,
        "agent_id": tool_call.get("agent_id", "agent-demo"),
        "session_id": tool_call.get("session_id", "session-demo"),
        "server_id": server_id if server_id is not None else tool_call.get("server_id"),
        "tool_name": tool_call.get("tool_name", "unknown_tool"),
        "tool_fingerprint": tool_call.get("_runtime_authorized_tool_fingerprint"),
        "arguments_summary": argument_summary,
        "status": status or STATUS_BY_DECISION.get(decision_value, "unknown_decision"),
        "decision": decision_value,
        "rule_id": decision.get("rule_id"),
        "decision_reason": safe_runtime_decision_reason(decision),
        "explanation": explanation,
        "opa_decision": original_opa["opa_decision"] if original_opa else None,
        "opa_rule_id": original_opa["opa_rule_id"] if original_opa else None,
        "opa_policy_revision": original_opa["opa_policy_revision"] if original_opa else None,
        "opa_explanation": original_opa["opa_explanation"] if original_opa else None,
        "guard_explanation": guard_record,
        "policy_revision": revision,
        "decision_basis": basis,
        "dispatch_state": dispatch_state,
        "severity": decision.get("severity"),
        "control_plane_revision_id": tool_call.get("control_plane_revision_id"),
        "control_plane_revision_number": tool_call.get("control_plane_revision_number"),
        "control_plane_content_hash": tool_call.get("control_plane_content_hash"),
        "client_protocol_profile_id": tool_call.get("client_protocol_profile_id"),
        "client_protocol_era": tool_call.get("client_protocol_era"),
        "client_protocol_version": tool_call.get("client_protocol_version"),
        "client_transport_kind": tool_call.get("client_transport_kind"),
        "upstream_protocol_profile_id": tool_call.get("upstream_protocol_profile_id"),
        "upstream_protocol_era": tool_call.get("upstream_protocol_era"),
        "upstream_protocol_version": tool_call.get("upstream_protocol_version"),
        "upstream_transport_kind": tool_call.get("upstream_transport_kind"),
        "executed": executed,
        "execution_status": execution_status,
        "result_summary": summarize_tool_result(tool_result),
         "error_summary": safe_runtime_error_code(error_summary) if error_summary else None,
        "total_duration_ms": _runtime_total_duration_ms(tool_call),
        "policy_duration_ms": _safe_duration_ms(tool_call.get("_runtime_policy_duration_ms")),
        "upstream_duration_ms": _safe_duration_ms(tool_call.get("_runtime_upstream_duration_ms")),
        "result_guard_duration_ms": _safe_duration_ms(
            tool_call.get("_runtime_result_guard_duration_ms")
        ),
    }


def send_runtime_log(
    log_payload: dict[str, Any],
    backend_client: BackendClient | None = None,
) -> dict[str, Any]:
    client = backend_client or BackendClient()
    return client.create_runtime_log(log_payload)




def _runtime_total_duration_ms(tool_call: dict[str, Any]) -> float | None:
    started = tool_call.get("_runtime_started_monotonic")
    if isinstance(started, bool) or not isinstance(started, (int, float)):
        return None
    return _safe_duration_ms((time.perf_counter() - float(started)) * 1000)


def _safe_duration_ms(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    numeric = float(value)
    if not math.isfinite(numeric) or numeric < 0:
        return None
    return round(min(numeric, 3_600_000.0), 3)


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
