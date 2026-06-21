from pathlib import Path
from typing import Any

import yaml

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
    "deny_sensitive_paths": "Access to sensitive path is forbidden.",
    "allow_contracts_read": "The requested path is allowed.",
    "warn_high_risk_tool": "High-risk MCP tool call detected.",
    "require_approval_for_sensitive_tool": "Sensitive tool requires human approval.",
    "limit_large_outputs": "Estimated output exceeds the configured limit.",
    "log_normal_runtime_call": "Runtime call logged for audit purposes.",
}


class PolicyEngine:
    def __init__(self, rules_path: Path = DEFAULT_RULES_PATH) -> None:
        self.rules_path = rules_path
        self.rules = self._load_rules()

    def evaluate(self, context: dict[str, Any]) -> dict[str, str]:
        matching_rules = [
            rule
            for rule in self.rules
            if rule.get("enabled", True) and self._matches_rule(rule, context)
        ]

        if not matching_rules:
            fallback = self._find_rule("log_normal_runtime_call")
            return self._build_decision(fallback)

        selected_rule = max(
            matching_rules,
            key=lambda rule: DECISION_PRIORITY.get(rule.get("decision", "LOG_ONLY"), 0),
        )
        return self._build_decision(selected_rule)

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

        if "contains" in match:
            argument_value = self._get_argument_value(context, match.get("argument"))
            return any(pattern in argument_value for pattern in match["contains"])

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

        if "max_output_size_mb" in match:
            estimated_size = context.get("estimated_output_size_mb", 0)
            return estimated_size > match["max_output_size_mb"]

        return False

    def _get_argument_value(self, context: dict[str, Any], argument_name: str | None) -> str:
        if not argument_name:
            return ""

        arguments = context.get("arguments") or {}
        return str(arguments.get(argument_name, ""))

    def _build_decision(self, rule: dict[str, Any]) -> dict[str, str]:
        rule_id = rule.get("id", "log_normal_runtime_call")
        return {
            "decision": rule.get("decision", "LOG_ONLY"),
            "rule_id": rule_id,
            "reason": DEFAULT_REASONS.get(rule_id, rule.get("description", "Policy evaluated.")),
            "severity": rule.get("severity", "low"),
        }


def evaluate_policy(context: dict[str, Any]) -> dict[str, str]:
    return PolicyEngine().evaluate(context)
