from pathlib import Path
from typing import Any

from pydantic import ValidationError
import yaml

from app.schemas.policy_decision import PolicyDecision

DEFAULT_RULES_PATH = Path(__file__).resolve().parents[3] / "policies" / "default_rules.yaml"

DECISION_PRIORITY = {
    "BLOCK": 60,
    "ASK_APPROVAL": 50,
    "LIMIT": 40,
    "WARN": 30,
    "ALLOW": 20,
    "LOG_ONLY": 10,
}

DEFAULT_REASONS = {
    "block_unknown_server": "MCP server is unknown or blocked.",
    "deny_invalid_arguments": "Tool arguments failed schema validation.",
    "deny_unknown_subject": "Subject authorization is unknown.",
    "deny_sensitive_paths": "Access to sensitive path is forbidden.",
    "deny_unclassified_capability": "The request capability is not classified.",
    "deny_capability_not_granted": (
        "The required capability is not granted "
        "to the subject."
    ),
    "deny_scope_not_granted": (
        "The requested resource scope is not granted "
        "for the required capability."
    ),
    "allow_contracts_read": "The requested path is allowed.",
    "warn_high_risk_tool": "High-risk MCP tool call detected.",
    "require_approval_for_sensitive_tool": "Sensitive tool requires human approval.",
    "limit_large_outputs": "Estimated output exceeds the configured limit.",
    "log_normal_runtime_call": "Runtime call logged for audit purposes.",
}

LEGACY_DECISION_MAPPING = {
    "ALLOW": {
        "effect": "ALLOW",
        "obligations": [
            {"type": "LOG", "parameters": {}},
        ],
    },
    "BLOCK": {
        "effect": "DENY",
        "obligations": [
            {"type": "LOG", "parameters": {}},
            {"type": "ALERT", "parameters": {}},
        ],
    },
    "WARN": {
        "effect": "ALLOW",
        "obligations": [
            {"type": "WARN", "parameters": {}},
            {"type": "LOG", "parameters": {}},
        ],
    },
    "ASK_APPROVAL": {
        "effect": "DEFER",
        "obligations": [
            {"type": "REQUIRE_APPROVAL", "parameters": {}},
            {"type": "LOG", "parameters": {}},
        ],
    },
    "LIMIT": {
        "effect": "ALLOW",
        "obligations": [
            {"type": "LIMIT_OUTPUT", "parameters": {}},
            {"type": "LOG", "parameters": {}},
        ],
    },
    "LOG_ONLY": {
        "effect": "ALLOW",
        "obligations": [
            {"type": "LOG", "parameters": {}},
        ],
    },
}


def _to_legacy_policy_context(context: dict[str, Any]) -> dict[str, Any]:
    if all(
        key in context
        for key in ("subject", "server", "tool", "request", "runtime")
    ):
        request = context["request"]
        canonical_resource = request.get("canonical_resource")
        policy_arguments = dict(request.get("arguments") or {})
        if isinstance(canonical_resource, str):
            policy_arguments["path"] = canonical_resource

        return {
            "agent_id": context["subject"]["agent_id"],
            "session_id": context["runtime"]["session_id"],
            "server_id": context["server"]["id"],
            "server_endpoint": context["server"]["endpoint"],
            "server_status": context["server"]["trust_status"],
            "trust_status": context["server"]["trust_status"],
            "server_security_status": context["server"].get("security_status"),
            "tool_name": context["tool"]["name"],
            "tool_risk_score": context["tool"]["risk_score"],
            "tool_sensitivity": context["tool"]["sensitivity"],
            "authorization_status": context["subject"].get(
                "authorization_status",
                "unknown",
            ),
            "authorization_revision": context["subject"].get(
                "authorization_revision",
                "unknown",
            ),
            "grants": context["subject"].get("grants", []),
            "allowed_capabilities": context["subject"].get("allowed_capabilities", []),
            "allowed_scopes": context["subject"].get("allowed_scopes", []),
            "arguments": policy_arguments,
            "arguments_valid": request["arguments_valid"],
            "validation_error_codes": request.get("validation_error_codes", []),
            "canonical_resource": canonical_resource,
            "operation": request.get("operation", "unknown"),
            "resource_type": request.get("resource_type", "unknown"),
            "resource_scope": request.get("resource_scope", "unknown"),
            "required_capability": request.get(
                "required_capability",
                "unclassified",
            ),
            "estimated_output_size_mb": request["estimated_output_size_mb"],
        }

    return context


def _to_policy_decision(legacy_decision: dict[str, Any]) -> dict[str, Any]:
    try:
        decision_value = legacy_decision["decision"]
        mapping = LEGACY_DECISION_MAPPING[decision_value]
        result = {
            "effect": mapping["effect"],
            "obligations": mapping["obligations"],
            "rule_ids": [legacy_decision["rule_id"]],
            "reason": legacy_decision["reason"],
            "severity": legacy_decision["severity"],
            "evidence": legacy_decision.get("evidence", {}),
            "recommended_action": legacy_decision.get("recommended_action"),
            "policy_revision": "legacy-yaml-v1",
            "decision": decision_value,
            "rule_id": legacy_decision["rule_id"],
        }
        validated = PolicyDecision.model_validate(result)
    except (KeyError, TypeError, ValidationError):
        result = {
            "effect": "DENY",
            "obligations": [
                {"type": "LOG", "parameters": {}},
                {"type": "ALERT", "parameters": {}},
            ],
            "rule_ids": ["invalid_legacy_policy_decision"],
            "reason": "The legacy policy engine returned an invalid decision.",
            "severity": "critical",
            "evidence": {},
            "recommended_action": None,
            "policy_revision": "legacy-yaml-v1",
            "decision": "BLOCK",
            "rule_id": "invalid_legacy_policy_decision",
        }
        validated = PolicyDecision.model_validate(result)

    return validated.model_dump(mode="json")


class PolicyEngine:
    def __init__(self, rules_path: Path = DEFAULT_RULES_PATH) -> None:
        self.rules_path = rules_path
        self.rules = self._load_rules()

    def evaluate(self, context: dict[str, Any]) -> dict[str, Any]:
        legacy_context = _to_legacy_policy_context(context)
        matching_rules = [
            rule
            for rule in self.rules
            if rule.get("enabled", True) and self._matches_rule(rule, legacy_context)
        ]

        if not matching_rules:
            fallback = self._find_rule("log_normal_runtime_call")
            return _to_policy_decision(self._build_decision(fallback))

        selected_rule = max(
            matching_rules,
            key=lambda rule: DECISION_PRIORITY.get(rule.get("decision", "LOG_ONLY"), 0),
        )
        return _to_policy_decision(self._build_decision(selected_rule))

    def _load_rules(self) -> list[dict[str, Any]]:
        with self.rules_path.open("r", encoding="utf-8") as file:
            data = yaml.safe_load(file) or {}
        return data.get("rules", [])

    def _find_rule(self, rule_id: str) -> dict[str, Any]:
        for rule in self.rules:
            if rule.get("id") == rule_id:
                return rule

        return {
            "id": rule_id,
            "decision": "LOG_ONLY",
            "severity": "low",
            "description": "Default runtime logging rule.",
        }

    def _matches_rule(self, rule: dict[str, Any], context: dict[str, Any]) -> bool:
        match = rule.get("match")
        if not match:
            return False

        if "server_status" in match:
            return context.get("server_status") in match["server_status"]

        if "arguments_valid" in match:
            return context.get("arguments_valid") is match["arguments_valid"]

        if "authorization_status" in match:
            return context.get("authorization_status") in match["authorization_status"]

        if "contains" in match:
            argument_value = self._get_argument_value(context, match.get("argument"))
            comparison_value = argument_value.lower()
            return any(
                str(pattern).lower() in comparison_value
                for pattern in match["contains"]
            )

        if "allowed_prefixes" in match:
            argument_value = self._get_argument_value(context, match.get("argument"))
            tool_name = match.get("tool_name")
            tool_matches = tool_name is None or context.get("tool_name") == tool_name
            return tool_matches and any(
                argument_value.startswith(prefix) for prefix in match["allowed_prefixes"]
            )

        if "min_tool_risk_score" in match:
            return context.get("tool_risk_score", 0) >= match["min_tool_risk_score"]

        if "tool_sensitivity" in match:
            return context.get("tool_sensitivity") in match["tool_sensitivity"]

        if "required_capability" in match:
            return context.get("required_capability") in match["required_capability"]

        if "capability_not_granted" in match:
            return not _subject_has_capability(context)

        if "scope_not_granted" in match:
            return (
                _subject_has_capability(context)
                and not _subject_has_capability_scope_grant(context)
            )

        if "max_output_size_mb" in match:
            estimated_size = context.get("estimated_output_size_mb", 0)
            return estimated_size > match["max_output_size_mb"]

        return False

    def _get_argument_value(self, context: dict[str, Any], argument_name: str | None) -> str:
        if not argument_name:
            return ""

        arguments = context.get("arguments") or {}
        value = arguments.get(argument_name, "")
        if isinstance(value, str):
            return value
        return ""

    def _build_decision(self, rule: dict[str, Any]) -> dict[str, str]:
        rule_id = rule.get("id", "log_normal_runtime_call")
        return {
            "decision": rule.get("decision", "LOG_ONLY"),
            "rule_id": rule_id,
            "reason": DEFAULT_REASONS.get(rule_id, rule.get("description", "Policy evaluated.")),
            "severity": rule.get("severity", "low"),
        }


def evaluate_policy(context: dict[str, Any]) -> dict[str, Any]:
    return PolicyEngine().evaluate(context)


def _subject_has_capability(context: dict[str, Any]) -> bool:
    required_capability = context.get("required_capability")
    if not isinstance(required_capability, str) or not required_capability:
        return False

    for grant in context.get("grants") or []:
        if not isinstance(grant, dict):
            continue
        if grant.get("capability") == required_capability:
            return True

    return False


def _subject_has_capability_scope_grant(context: dict[str, Any]) -> bool:
    required_capability = context.get("required_capability")
    resource_scope = context.get("resource_scope")
    if (
        not isinstance(required_capability, str)
        or not required_capability
        or not isinstance(resource_scope, str)
        or not resource_scope
    ):
        return False

    for grant in context.get("grants") or []:
        if not isinstance(grant, dict):
            continue
        if grant.get("capability") != required_capability:
            continue
        scopes = grant.get("scopes")
        if isinstance(scopes, list) and resource_scope in scopes:
            return True

    return False
