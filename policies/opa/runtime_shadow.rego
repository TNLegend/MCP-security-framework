package mcp.security.runtime

import rego.v1

sensitive_path_patterns := {
	".env",
	".aws/credentials",
	"/etc/passwd",
	"id_rsa",
	"secrets",
}

policy_revision := "opa-runtime-v2"

default input_object := {}

input_object := value if {
	value := input
	is_object(value)
}

default subject_object := {}

subject_object := value if {
	value := object.get(input_object, "subject", {})
	is_object(value)
}

default authorization_status := "unknown"

authorization_status := value if {
	value := object.get(subject_object, "authorization_status", "unknown")
	is_string(value)
}

default identity_status := "unverified"

identity_status := value if {
	value := object.get(subject_object, "identity_status", "unverified")
	is_string(value)
}

default session_status := "unknown"

session_status := value if {
	value := object.get(subject_object, "session_status", "unknown")
	is_string(value)
}

raw_subject_grants := object.get(subject_object, "grants", [])

default subject_grants := []

subject_grants := grants if {
	is_array(raw_subject_grants)
	grants := [grant |
		some candidate in raw_subject_grants
		is_object(candidate)
		capability := object.get(candidate, "capability", null)
		is_string(capability)
		scopes := object.get(candidate, "scopes", null)
		is_array(scopes)
		valid_scopes := [scope |
			some scope in scopes
			is_string(scope)
		]
		count(valid_scopes) == count(scopes)
		grant := {"capability": capability, "scopes": valid_scopes}
	]
}

default server_object := {}

server_object := value if {
	value := object.get(input_object, "server", {})
	is_object(value)
}

default trust_status := "unknown"

trust_status := value if {
	value := object.get(server_object, "trust_status", "unknown")
	is_string(value)
}

default request_object := {}

request_object := value if {
	value := object.get(input_object, "request", {})
	is_object(value)
}

default arguments_valid := false

arguments_valid := value if {
	value := object.get(request_object, "arguments_valid", false)
	is_boolean(value)
}

default canonical_resource := ""

canonical_resource := value if {
	value := object.get(request_object, "canonical_resource", "")
	is_string(value)
}

canonical_resource_lower := lower(canonical_resource)

default resource_resolution_status := "unknown"

resource_resolution_status := value if {
	value := object.get(request_object, "resource_resolution_status", "unknown")
	is_string(value)
}

default resource_sensitivity := "unknown"

resource_sensitivity := value if {
	value := object.get(request_object, "resource_sensitivity", "unknown")
	is_string(value)
}

default operation_allowed_on_scope := false

operation_allowed_on_scope := value if {
	value := object.get(request_object, "operation_allowed_on_scope", false)
	is_boolean(value)
}

default estimated_output_size_mb := 0

estimated_output_size_mb := value if {
	value := object.get(request_object, "estimated_output_size_mb", 0)
	is_number(value)
}

default required_capability := "unclassified"

required_capability := value if {
	value := object.get(request_object, "required_capability", "unclassified")
	is_string(value)
}

default resource_scope := "unknown"

resource_scope := value if {
	value := object.get(request_object, "resource_scope", "unknown")
	is_string(value)
}

default tool_object := {}

tool_object := value if {
	value := object.get(input_object, "tool", {})
	is_object(value)
}

default tool_name := ""

tool_name := value if {
	value := object.get(tool_object, "name", "")
	is_string(value)
}

default risk_score := 0

risk_score := value if {
	value := object.get(tool_object, "risk_score", 0)
	is_number(value)
}

default sensitivity := "unknown"

sensitivity := value if {
	value := object.get(tool_object, "sensitivity", "unknown")
	is_string(value)
}

default tool_profile_status := "unknown"

tool_profile_status := value if {
	value := object.get(tool_object, "profile_status", "unknown")
	is_string(value)
}

default decision := {
	"effect": "ALLOW",
	"obligations": [{"type": "LOG", "parameters": {}}],
	"rule_ids": ["log_normal_runtime_call"],
	"reason": "Runtime call logged for audit purposes.",
	"severity": "low",
	"evidence": {},
	"recommended_action": null,
	"policy_revision": "opa-runtime-v2",
	"decision": "LOG_ONLY",
	"rule_id": "log_normal_runtime_call",
}

decision := candidate.decision if {
	some candidate in rule_candidates
	candidate.precedence == winning_precedence
}

winning_precedence := max({candidate.precedence | some candidate in rule_candidates})

rule_candidates contains {
	"precedence": 900,
	"decision": block_unknown_server_decision,
} if {
	is_unknown_or_blocked_server
}

rule_candidates contains {
	"precedence": 899,
	"decision": deny_unverified_identity_decision,
} if {
	identity_status == "unverified"
}

rule_candidates contains {
	"precedence": 898,
	"decision": deny_invalid_or_expired_session_decision,
} if {
	session_status != "active"
}

rule_candidates contains {
	"precedence": 897,
	"decision": deny_invalid_arguments_decision,
} if {
	not arguments_valid
}

rule_candidates contains {
	"precedence": 896,
	"decision": deny_unknown_subject_decision,
} if {
	authorization_status == "unknown"
}

rule_candidates contains {
	"precedence": 895,
	"decision": deny_unknown_tool_security_profile_decision,
} if {
	tool_profile_status in {"unknown", "unavailable", "missing"}
}

rule_candidates contains {
	"precedence": 894,
	"decision": deny_tool_security_profile_drift_decision,
} if {
	tool_profile_status == "drift"
}

rule_candidates contains {
	"precedence": 893,
	"decision": deny_resource_resolution_failed_decision,
} if {
	resource_resolution_status in {
		"invalid_arguments",
		"resource_not_found",
		"resource_type_mismatch",
		"resource_resolution_failed",
		"path_null_byte",
		"path_control_character",
		"path_too_long",
		"path_too_many_segments",
		"path_unc",
		"path_device",
		"path_ntfs_ads",
		"path_reserved_name",
		"path_traversal_outside_root",
	}
}

rule_candidates contains {
	"precedence": 892,
	"decision": deny_resource_outside_registered_scope_decision,
} if {
	resource_resolution_status == "resource_outside_registered_scope"
}

rule_candidates contains {
	"precedence": 891,
	"decision": deny_ambiguous_resource_scope_decision,
} if {
	resource_resolution_status == "ambiguous_resource_scope"
}

rule_candidates contains {
	"precedence": 890,
	"decision": deny_sensitive_resource_decision,
} if {
	resource_sensitivity == "secret"
}

rule_candidates contains {
	"precedence": 889,
	"decision": deny_sensitive_paths_decision,
} if {
	is_sensitive_path
}

rule_candidates contains {
	"precedence": 888,
	"decision": deny_unclassified_capability_decision,
} if {
	required_capability == "unclassified"
}

rule_candidates contains {
	"precedence": 887,
	"decision": deny_capability_not_granted_decision,
} if {
	not subject_has_required_capability
}

rule_candidates contains {
	"precedence": 886,
	"decision": deny_scope_not_granted_decision,
} if {
	subject_has_required_capability
	not subject_has_required_capability_scope
}

rule_candidates contains {
	"precedence": 885,
	"decision": deny_operation_not_allowed_on_scope_decision,
} if {
	not operation_allowed_on_scope
}

rule_candidates contains {
	"precedence": 600,
	"decision": require_approval_for_sensitive_tool_decision,
} if {
	requires_approval_for_sensitive_tool
}

rule_candidates contains {
	"precedence": 500,
	"decision": limit_large_outputs_decision,
} if {
	requires_output_limit
}

rule_candidates contains {
	"precedence": 400,
	"decision": warn_high_risk_tool_decision,
} if {
	is_high_risk_tool
}

rule_candidates contains {
	"precedence": 300,
	"decision": allow_contracts_read_decision,
} if {
	is_contract_read
}

is_unknown_or_blocked_server if {
	trust_status in {"unknown", "blocked"}
}

is_sensitive_path if {
	some pattern in sensitive_path_patterns
	contains(canonical_resource_lower, lower(pattern))
}

is_contract_read if {
	tool_name == "read_file"
	startswith(canonical_resource, "contracts/")
}

is_contract_read if {
	tool_name == "read_file"
	startswith(canonical_resource, "fs.project_workspace:/contracts/")
}

is_contract_read if {
	tool_name == "read_file"
	startswith(canonical_resource, "fs.legal_contracts:/")
}

is_high_risk_tool if {
	risk_score >= 70
}

requires_approval_for_sensitive_tool if {
	sensitivity in {"high", "critical"}
}

requires_output_limit if {
	estimated_output_size_mb > 10
}

subject_has_required_capability if {
	some grant in subject_grants
	grant.capability == required_capability
}

subject_has_required_capability_scope if {
	some grant in subject_grants
	grant.capability == required_capability
	resource_scope in grant.scopes
}

block_unknown_server_decision := deny_decision(
	"block_unknown_server",
	"MCP server is unknown or blocked.",
)

deny_invalid_arguments_decision := deny_decision(
	"deny_invalid_arguments",
	"Tool arguments failed schema validation.",
)

deny_unverified_identity_decision := {
	"effect": "DENY",
	"obligations": [
		{"type": "LOG", "parameters": {}},
		{"type": "ALERT", "parameters": {}},
	],
	"rule_ids": ["deny_unverified_identity"],
	"reason": "Trusted agent identity is required.",
	"severity": "critical",
	"evidence": {},
	"recommended_action": null,
	"policy_revision": policy_revision,
	"decision": "BLOCK",
	"rule_id": "deny_unverified_identity",
}

deny_invalid_or_expired_session_decision := {
	"effect": "DENY",
	"obligations": [
		{"type": "LOG", "parameters": {}},
		{"type": "ALERT", "parameters": {}},
	],
	"rule_ids": ["deny_invalid_or_expired_session"],
	"reason": "Trusted runtime session is invalid or expired.",
	"severity": "critical",
	"evidence": {},
	"recommended_action": null,
	"policy_revision": policy_revision,
	"decision": "BLOCK",
	"rule_id": "deny_invalid_or_expired_session",
}

deny_unknown_subject_decision := deny_decision(
	"deny_unknown_subject",
	"Subject authorization is unknown.",
)

deny_unknown_tool_security_profile_decision := deny_decision(
	"deny_unknown_tool_security_profile",
	"Tool security profile is unknown.",
)

deny_tool_security_profile_drift_decision := deny_decision(
	"deny_tool_security_profile_drift",
	"Tool security profile drift was detected.",
)

deny_resource_resolution_failed_decision := deny_decision(
	"deny_resource_resolution_failed",
	"Resource could not be resolved safely.",
)

deny_resource_outside_registered_scope_decision := deny_decision(
	"deny_resource_outside_registered_scope",
	"Resource is outside registered scopes.",
)

deny_ambiguous_resource_scope_decision := deny_decision(
	"deny_ambiguous_resource_scope",
	"Resource scope is ambiguous.",
)

deny_sensitive_resource_decision := {
	"effect": "DENY",
	"obligations": [
		{"type": "LOG", "parameters": {}},
		{"type": "ALERT", "parameters": {}},
	],
	"rule_ids": ["deny_sensitive_resource"],
	"reason": "Sensitive resource access is forbidden.",
	"severity": "critical",
	"evidence": {},
	"recommended_action": null,
	"policy_revision": policy_revision,
	"decision": "BLOCK",
	"rule_id": "deny_sensitive_resource",
}

deny_sensitive_paths_decision := deny_decision(
	"deny_sensitive_paths",
	"Access to sensitive path is forbidden.",
)

deny_unclassified_capability_decision := deny_decision(
	"deny_unclassified_capability",
	"The request capability is not classified.",
)

deny_capability_not_granted_decision := deny_decision(
	"deny_capability_not_granted",
	"The required capability is not granted to the subject.",
)

deny_scope_not_granted_decision := deny_decision(
	"deny_scope_not_granted",
	"The requested resource scope is not granted for the required capability.",
)

deny_operation_not_allowed_on_scope_decision := deny_decision(
	"deny_operation_not_allowed_on_scope",
	"The requested operation is not allowed on the resource scope.",
)

allow_contracts_read_decision := {
	"effect": "ALLOW",
	"obligations": [{"type": "LOG", "parameters": {}}],
	"rule_ids": ["allow_contracts_read"],
	"reason": "The requested path is allowed.",
	"severity": "low",
	"evidence": {},
	"recommended_action": null,
	"policy_revision": policy_revision,
	"decision": "ALLOW",
	"rule_id": "allow_contracts_read",
}

warn_high_risk_tool_decision := {
	"effect": "ALLOW",
	"obligations": [
		{"type": "WARN", "parameters": {}},
		{"type": "LOG", "parameters": {}},
	],
	"rule_ids": ["warn_high_risk_tool"],
	"reason": "High-risk MCP tool call detected.",
	"severity": "medium",
	"evidence": {},
	"recommended_action": null,
	"policy_revision": policy_revision,
	"decision": "WARN",
	"rule_id": "warn_high_risk_tool",
}

require_approval_for_sensitive_tool_decision := {
	"effect": "DEFER",
	"obligations": [
		{"type": "REQUIRE_APPROVAL", "parameters": {}},
		{"type": "LOG", "parameters": {}},
	],
	"rule_ids": ["require_approval_for_sensitive_tool"],
	"reason": "Sensitive tool requires human approval.",
	"severity": "high",
	"evidence": {},
	"recommended_action": null,
	"policy_revision": policy_revision,
	"decision": "ASK_APPROVAL",
	"rule_id": "require_approval_for_sensitive_tool",
}

limit_large_outputs_decision := {
	"effect": "ALLOW",
	"obligations": [
		{"type": "LIMIT_OUTPUT", "parameters": {}},
		{"type": "LOG", "parameters": {}},
	],
	"rule_ids": ["limit_large_outputs"],
	"reason": "Estimated output exceeds the configured limit.",
	"severity": "medium",
	"evidence": {},
	"recommended_action": null,
	"policy_revision": policy_revision,
	"decision": "LIMIT",
	"rule_id": "limit_large_outputs",
}

log_normal_runtime_call_decision := {
	"effect": "ALLOW",
	"obligations": [{"type": "LOG", "parameters": {}}],
	"rule_ids": ["log_normal_runtime_call"],
	"reason": "Runtime call logged for audit purposes.",
	"severity": "low",
	"evidence": {},
	"recommended_action": null,
	"policy_revision": policy_revision,
	"decision": "LOG_ONLY",
	"rule_id": "log_normal_runtime_call",
}

deny_decision(rule_id, reason) := {
	"effect": "DENY",
	"obligations": [
		{"type": "LOG", "parameters": {}},
		{"type": "ALERT", "parameters": {}},
	],
	"rule_ids": [rule_id],
	"reason": reason,
	"severity": "high",
	"evidence": {},
	"recommended_action": null,
	"policy_revision": policy_revision,
	"decision": "BLOCK",
	"rule_id": rule_id,
}
