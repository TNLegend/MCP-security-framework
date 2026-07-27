package mcp.security.runtime_test

import data.mcp.security.runtime
import rego.v1

default_grants := [
	{"capability": "filesystem.read", "scopes": ["contracts", "sensitive"]},
	{"capability": "filesystem.list", "scopes": ["lab_root", "contracts"]},
]

resolved_subject := {
	"agent_id": "agent-test",
	"role": "legal_agent",
	"authorization_status": "resolved",
	"authorization_revision": "test-authorization-v1",
	"grants": default_grants,
	"allowed_capabilities": ["filesystem.read", "filesystem.list"],
	"allowed_scopes": ["contracts", "sensitive", "lab_root"],
}

unknown_subject := {
	"agent_id": "unknown-agent",
	"role": "unknown",
	"authorization_status": "unknown",
	"authorization_revision": "test-authorization-v1",
	"grants": [],
	"allowed_capabilities": [],
	"allowed_scopes": [],
}

runtime_input(tool_name, path) := runtime_input_full(
	"lab_trusted",
	tool_name,
	40,
	"medium",
	path,
	0.001,
)

runtime_input_full(trust_status, tool_name, risk_score, sensitivity, path, estimated_output_size_mb) := {
	"subject": resolved_subject,
	"server": {
		"id": 1,
		"endpoint": "http://127.0.0.1:9000/mcp",
		"trust_status": trust_status,
		"security_status": "pending_analysis",
	},
	"tool": {
		"id": 1,
		"name": tool_name,
		"risk_score": risk_score,
		"sensitivity": sensitivity,
		"capabilities": [],
		"admission_status": "unknown",
		"description_risk_score": 0,
		"capability_mismatch": false,
		"drift_status": "unknown",
	},
	"request": {
		"operation": "unknown",
		"resource_type": "unknown",
		"resource_scope": resource_scope_for(path),
		"required_capability": required_capability_for(tool_name),
		"canonical_resource": path,
		"arguments": {"path": path},
		"arguments_valid": true,
		"validation_error_codes": [],
		"estimated_output_size_mb": estimated_output_size_mb,
	},
	"runtime": {
		"environment": "local",
		"session_id": "session-test",
	},
}

runtime_input_with_arguments(tool_name, arguments) := {
	"subject": resolved_subject,
	"server": {
		"id": 1,
		"endpoint": "http://127.0.0.1:9000/mcp",
		"trust_status": "lab_trusted",
		"security_status": "pending_analysis",
	},
	"tool": {
		"id": 1,
		"name": tool_name,
		"risk_score": 40,
		"sensitivity": "medium",
		"capabilities": [],
		"admission_status": "unknown",
		"description_risk_score": 0,
		"capability_mismatch": false,
		"drift_status": "unknown",
	},
	"request": {
		"operation": "unknown",
		"resource_type": "unknown",
		"resource_scope": resource_scope_for(object.get(arguments, "path", null)),
		"required_capability": required_capability_for(tool_name),
		"canonical_resource": object.get(arguments, "path", null),
		"arguments": arguments,
		"arguments_valid": true,
		"validation_error_codes": [],
		"estimated_output_size_mb": 0.001,
	},
	"runtime": {
		"environment": "local",
		"session_id": "session-test",
	},
}

runtime_input_with_request(tool_name, request) := {
	"subject": resolved_subject,
	"server": {
		"id": 1,
		"endpoint": "http://127.0.0.1:9000/mcp",
		"trust_status": "lab_trusted",
		"security_status": "pending_analysis",
	},
	"tool": {
		"id": 1,
		"name": tool_name,
		"risk_score": 40,
		"sensitivity": "medium",
		"capabilities": [],
		"admission_status": "unknown",
		"description_risk_score": 0,
		"capability_mismatch": false,
		"drift_status": "unknown",
	},
	"request": request,
	"runtime": {
		"environment": "local",
		"session_id": "session-test",
	},
}

runtime_input_invalid_arguments(tool_name, arguments) := runtime_input_with_request(tool_name, {
	"operation": "read",
	"resource_type": "file",
	"resource_scope": "invalid",
	"required_capability": required_capability_for(tool_name),
	"canonical_resource": null,
	"arguments": arguments,
	"arguments_valid": false,
	"validation_error_codes": ["invalid_type:path"],
	"estimated_output_size_mb": 0.001,
})

runtime_input_with_tool(tool, path) := {
	"subject": resolved_subject,
	"server": {
		"id": 1,
		"endpoint": "http://127.0.0.1:9000/mcp",
		"trust_status": "lab_trusted",
		"security_status": "pending_analysis",
	},
	"tool": tool,
	"request": {
		"operation": "unknown",
		"resource_type": "unknown",
		"resource_scope": resource_scope_for(path),
		"required_capability": required_capability_for(object.get(tool, "name", "")),
		"canonical_resource": path,
		"arguments": {"path": path},
		"arguments_valid": true,
		"validation_error_codes": [],
		"estimated_output_size_mb": 0.001,
	},
	"runtime": {
		"environment": "local",
		"session_id": "session-test",
	},
}

required_capability_for(tool_name) := "filesystem.read" if {
	tool_name == "read_file"
} else := "filesystem.list" if {
	tool_name == "list_files"
} else := "unclassified"

resource_scope_for(path) := "sensitive" if {
	is_test_sensitive_path(path)
} else := "contracts" if {
	is_string(path)
	startswith(path, "contracts/")
} else := "lab_root" if {
	is_string(path)
	not startswith(path, "contracts/")
} else := "unknown"

is_test_sensitive_path(path) if {
	is_string(path)
	some pattern in {".env", ".aws/credentials", "/etc/passwd", "id_rsa", "secrets"}
	contains(lower(path), lower(pattern))
}

has_obligation(decision, obligation_type) if {
	some obligation in decision.obligations
	obligation.type == obligation_type
}

test_fallback_normal if {
	d := runtime.decision with input as runtime_input_full("lab_trusted", "list_files", 0, "medium", "documents/", 0.001)
	d.rule_id == "log_normal_runtime_call"
	d.decision == "LOG_ONLY"
	d.effect == "ALLOW"
	has_obligation(d, "LOG")
	d.policy_revision == "opa-runtime-v2"
}

test_unknown_server_blocks if {
	d := runtime.decision with input as runtime_input_full("unknown", "list_files", 0, "medium", "documents/", 0.001)
	d.rule_id == "block_unknown_server"
	d.decision == "BLOCK"
	d.effect == "DENY"
	has_obligation(d, "LOG")
	has_obligation(d, "ALERT")
}

test_blocked_server_blocks if {
	d := runtime.decision with input as runtime_input_full("blocked", "list_files", 0, "medium", "documents/", 0.001)
	d.rule_id == "block_unknown_server"
	d.decision == "BLOCK"
}

test_env_denied if {
	d := runtime.decision with input as runtime_input("read_file", ".env")
	d.rule_id == "deny_sensitive_paths"
	d.decision == "BLOCK"
	d.effect == "DENY"
}

test_uppercase_env_denied if {
	d := runtime.decision with input as runtime_input("read_file", ".ENV")
	d.rule_id == "deny_sensitive_paths"
	d.decision == "BLOCK"
	d.effect == "DENY"
}

test_uppercase_secrets_denied if {
	d := runtime.decision with input as runtime_input("read_file", "SECRETS/api.txt")
	d.rule_id == "deny_sensitive_paths"
}

test_uppercase_id_rsa_denied if {
	d := runtime.decision with input as runtime_input("read_file", "folder/ID_RSA")
	d.rule_id == "deny_sensitive_paths"
}

test_uppercase_aws_credentials_denied if {
	d := runtime.decision with input as runtime_input("read_file", ".AWS/CREDENTIALS")
	d.rule_id == "deny_sensitive_paths"
}

test_aws_credentials_denied if {
	d := runtime.decision with input as runtime_input("read_file", ".aws/credentials")
	d.rule_id == "deny_sensitive_paths"
}

test_etc_passwd_denied if {
	d := runtime.decision with input as runtime_input("read_file", "/etc/passwd")
	d.rule_id == "deny_sensitive_paths"
}

test_id_rsa_denied if {
	d := runtime.decision with input as runtime_input("read_file", "keys/id_rsa.backup")
	d.rule_id == "deny_sensitive_paths"
}

test_secrets_denied if {
	d := runtime.decision with input as runtime_input("read_file", "data/secrets/config.json")
	d.rule_id == "deny_sensitive_paths"
}

test_contract_read_allowed if {
	d := runtime.decision with input as runtime_input("read_file", "contracts/contract1.txt")
	d.rule_id == "allow_contracts_read"
	d.decision == "ALLOW"
	d.effect == "ALLOW"
	has_obligation(d, "LOG")
}

test_uppercase_contract_prefix_is_not_allowed_by_contract_rule if {
	subject := object.union(resolved_subject, {"grants": [{"capability": "filesystem.read", "scopes": ["lab_root"]}]})
	input_value := object.union(runtime_input("read_file", "CONTRACTS/contract1.txt"), {"subject": subject})
	d := runtime.decision with input as input_value
	d.rule_id == "log_normal_runtime_call"
	d.decision == "LOG_ONLY"
}

test_wrong_tool_in_contracts_falls_back if {
	d := runtime.decision with input as runtime_input("list_files", "contracts/")
	d.rule_id == "log_normal_runtime_call"
	d.decision == "LOG_ONLY"
}

test_risk_below_threshold_falls_back if {
	d := runtime.decision with input as runtime_input_full("lab_trusted", "list_files", 69.999, "medium", "documents/", 0.001)
	d.rule_id == "log_normal_runtime_call"
}

test_risk_at_threshold_warns if {
	d := runtime.decision with input as runtime_input_full("lab_trusted", "list_files", 70, "medium", "documents/", 0.001)
	d.rule_id == "warn_high_risk_tool"
	d.decision == "WARN"
	d.effect == "ALLOW"
	has_obligation(d, "WARN")
	has_obligation(d, "LOG")
}

test_risk_above_threshold_warns if {
	d := runtime.decision with input as runtime_input_full("lab_trusted", "list_files", 90, "medium", "documents/", 0.001)
	d.rule_id == "warn_high_risk_tool"
}

test_medium_sensitivity_falls_back if {
	d := runtime.decision with input as runtime_input_full("lab_trusted", "list_files", 0, "medium", "documents/", 0.001)
	d.rule_id == "log_normal_runtime_call"
}

test_high_sensitivity_defers if {
	d := runtime.decision with input as runtime_input_full("lab_trusted", "list_files", 0, "high", "documents/", 0.001)
	d.rule_id == "require_approval_for_sensitive_tool"
	d.decision == "ASK_APPROVAL"
	d.effect == "DEFER"
	has_obligation(d, "REQUIRE_APPROVAL")
	has_obligation(d, "LOG")
}

test_critical_sensitivity_defers if {
	d := runtime.decision with input as runtime_input_full("lab_trusted", "list_files", 0, "critical", "documents/", 0.001)
	d.rule_id == "require_approval_for_sensitive_tool"
}

test_size_equal_threshold_falls_back if {
	d := runtime.decision with input as runtime_input_full("lab_trusted", "list_files", 0, "medium", "documents/", 10)
	d.rule_id == "log_normal_runtime_call"
}

test_size_above_threshold_limits if {
	d := runtime.decision with input as runtime_input_full("lab_trusted", "list_files", 0, "medium", "documents/", 10.0001)
	d.rule_id == "limit_large_outputs"
	d.decision == "LIMIT"
	d.effect == "ALLOW"
	has_obligation(d, "LIMIT_OUTPUT")
	has_obligation(d, "LOG")
}

test_size_large_limits if {
	d := runtime.decision with input as runtime_input_full("lab_trusted", "list_files", 0, "medium", "documents/", 100)
	d.rule_id == "limit_large_outputs"
}

test_priority_unknown_server_beats_env if {
	d := runtime.decision with input as runtime_input_full("unknown", "read_file", 0, "medium", ".env", 0.001)
	d.rule_id == "block_unknown_server"
}

test_priority_blocked_server_beats_env if {
	d := runtime.decision with input as runtime_input_full("blocked", "read_file", 0, "medium", ".env", 0.001)
	d.rule_id == "block_unknown_server"
}

test_priority_unknown_server_beats_contract if {
	d := runtime.decision with input as runtime_input_full("unknown", "read_file", 0, "medium", "contracts/contract1.txt", 0.001)
	d.rule_id == "block_unknown_server"
}

test_priority_unknown_server_beats_all_lower_rules if {
	d := runtime.decision with input as runtime_input_full("unknown", "read_file", 90, "high", "contracts/contract1.txt", 100)
	d.rule_id == "block_unknown_server"
}

test_priority_sensitive_path_beats_high_sensitivity if {
	d := runtime.decision with input as runtime_input_full("lab_trusted", "read_file", 0, "high", ".env", 0.001)
	d.rule_id == "deny_sensitive_paths"
}

test_priority_sensitive_path_beats_large_output if {
	d := runtime.decision with input as runtime_input_full("lab_trusted", "read_file", 0, "medium", ".env", 100)
	d.rule_id == "deny_sensitive_paths"
}

test_priority_sensitive_path_beats_high_risk if {
	d := runtime.decision with input as runtime_input_full("lab_trusted", "read_file", 90, "medium", ".env", 0.001)
	d.rule_id == "deny_sensitive_paths"
}

test_priority_contract_env_denied if {
	d := runtime.decision with input as runtime_input("read_file", "contracts/.env")
	d.rule_id == "deny_sensitive_paths"
}

test_priority_high_sensitivity_beats_limit_warn_and_contract if {
	d := runtime.decision with input as runtime_input_full("lab_trusted", "read_file", 90, "high", "contracts/contract1.txt", 100)
	d.rule_id == "require_approval_for_sensitive_tool"
}

test_priority_large_output_beats_warn_and_contract if {
	d := runtime.decision with input as runtime_input_full("lab_trusted", "read_file", 90, "medium", "contracts/contract1.txt", 100)
	d.rule_id == "limit_large_outputs"
}

test_priority_high_risk_beats_contract if {
	d := runtime.decision with input as runtime_input_full("lab_trusted", "read_file", 90, "medium", "contracts/contract1.txt", 0.001)
	d.rule_id == "warn_high_risk_tool"
}

test_priority_contract_only_allows if {
	d := runtime.decision with input as runtime_input_full("lab_trusted", "read_file", 0, "medium", "contracts/contract1.txt", 0.001)
	d.rule_id == "allow_contracts_read"
}

test_priority_high_sensitivity_beats_high_risk if {
	d := runtime.decision with input as runtime_input_full("lab_trusted", "list_files", 90, "high", "documents/", 0.001)
	d.rule_id == "require_approval_for_sensitive_tool"
}

test_priority_large_output_beats_high_risk if {
	d := runtime.decision with input as runtime_input_full("lab_trusted", "list_files", 90, "medium", "documents/", 100)
	d.rule_id == "limit_large_outputs"
}

test_missing_path_falls_back_to_log_only if {
	d := runtime.decision with input as runtime_input_invalid_arguments("read_file", {})
	d.rule_id == "deny_invalid_arguments"
}

test_null_path_denies_invalid_arguments if {
	d := runtime.decision with input as runtime_input_invalid_arguments("read_file", {"path": null})
	d.rule_id == "deny_invalid_arguments"
}

test_numeric_path_denies_invalid_arguments if {
	d := runtime.decision with input as runtime_input_invalid_arguments("read_file", {"path": 123})
	d.rule_id == "deny_invalid_arguments"
}

test_array_path_denies_invalid_arguments if {
	d := runtime.decision with input as runtime_input_invalid_arguments("read_file", {"path": [".env"]})
	d.rule_id == "deny_invalid_arguments"
}

test_object_path_denies_invalid_arguments if {
	d := runtime.decision with input as runtime_input_invalid_arguments("read_file", {"path": {"value": ".env"}})
	d.rule_id == "deny_invalid_arguments"
}

test_null_arguments_denies_invalid_arguments if {
	d := runtime.decision with input as runtime_input_with_request("read_file", {"arguments": null})
	d.rule_id == "deny_invalid_arguments"
}

test_null_request_denies_invalid_arguments if {
	d := runtime.decision with input as runtime_input_with_request("read_file", null)
	d.rule_id == "deny_invalid_arguments"
}

test_null_tool_name_falls_back_to_log_only if {
	d := runtime.decision with input as runtime_input_with_tool({"name": null}, "contracts/contract1.txt")
	d.rule_id == "deny_unclassified_capability"
}

test_invalid_arguments_only_denied if {
	request := {
		"operation": "read",
		"resource_type": "file",
		"resource_scope": "invalid",
		"canonical_resource": null,
		"arguments": {},
		"arguments_valid": false,
		"validation_error_codes": ["invalid_type:path"],
		"estimated_output_size_mb": 0.001,
	}
	d := runtime.decision with input as runtime_input_with_request("read_file", request)
	d.rule_id == "deny_invalid_arguments"
	d.effect == "DENY"
}

test_unknown_server_beats_invalid_arguments if {
	input_value := runtime_input_full("unknown", "read_file", 0, "medium", "contracts/contract1.txt", 0.001)
	request := input_value.request
	invalid_request := object.union(request, {"arguments_valid": false, "canonical_resource": null, "validation_error_codes": ["invalid_type:path"]})
	d := runtime.decision with input as object.union(input_value, {"request": invalid_request})
	d.rule_id == "block_unknown_server"
}

test_invalid_arguments_beat_sensitive_path if {
	input_value := runtime_input("read_file", ".env")
	request := object.union(input_value.request, {"arguments_valid": false, "canonical_resource": null, "validation_error_codes": ["invalid_type:path"]})
	d := runtime.decision with input as object.union(input_value, {"request": request})
	d.rule_id == "deny_invalid_arguments"
}

test_invalid_arguments_beat_approval if {
	input_value := runtime_input_full("lab_trusted", "list_files", 0, "high", "documents/", 0.001)
	request := object.union(input_value.request, {"arguments_valid": false, "canonical_resource": null, "validation_error_codes": ["invalid_type:path"]})
	d := runtime.decision with input as object.union(input_value, {"request": request})
	d.rule_id == "deny_invalid_arguments"
}

test_invalid_arguments_beat_limit if {
	input_value := runtime_input_full("lab_trusted", "list_files", 0, "medium", "documents/", 100)
	request := object.union(input_value.request, {"arguments_valid": false, "canonical_resource": null, "validation_error_codes": ["invalid_type:path"]})
	d := runtime.decision with input as object.union(input_value, {"request": request})
	d.rule_id == "deny_invalid_arguments"
}

test_invalid_arguments_beat_warn if {
	input_value := runtime_input_full("lab_trusted", "list_files", 90, "medium", "documents/", 0.001)
	request := object.union(input_value.request, {"arguments_valid": false, "canonical_resource": null, "validation_error_codes": ["invalid_type:path"]})
	d := runtime.decision with input as object.union(input_value, {"request": request})
	d.rule_id == "deny_invalid_arguments"
}

test_invalid_arguments_beat_contract if {
	input_value := runtime_input("read_file", "contracts/contract1.txt")
	request := object.union(input_value.request, {"arguments_valid": false, "canonical_resource": null, "validation_error_codes": ["invalid_type:path"]})
	d := runtime.decision with input as object.union(input_value, {"request": request})
	d.rule_id == "deny_invalid_arguments"
}

test_raw_contract_canonical_env_denied if {
	input_value := runtime_input("read_file", "contracts/contract1.txt")
	request := object.union(input_value.request, {"canonical_resource": ".env"})
	d := runtime.decision with input as object.union(input_value, {"request": request})
	d.rule_id == "deny_sensitive_paths"
}

test_raw_env_canonical_contract_allowed if {
	input_value := runtime_input("read_file", ".env")
	request := object.union(input_value.request, {"canonical_resource": "contracts/contract1.txt"})
	d := runtime.decision with input as object.union(input_value, {"request": request})
	d.rule_id == "allow_contracts_read"
}

test_arguments_valid_absent_denies_invalid_arguments if {
	d := runtime.decision with input as runtime_input_with_request("read_file", {"arguments": {"path": "contracts/contract1.txt"}, "canonical_resource": "contracts/contract1.txt"})
	d.rule_id == "deny_invalid_arguments"
}

test_arguments_valid_string_denies_invalid_arguments if {
	request := {
		"arguments": {"path": "contracts/contract1.txt"},
		"arguments_valid": "true",
		"canonical_resource": "contracts/contract1.txt",
		"validation_error_codes": [],
		"estimated_output_size_mb": 0.001,
	}
	d := runtime.decision with input as runtime_input_with_request("read_file", request)
	d.rule_id == "deny_invalid_arguments"
}

test_non_string_canonical_resource_does_not_error if {
	request := {
		"arguments": {"path": "contracts/contract1.txt"},
		"arguments_valid": true,
		"canonical_resource": {"path": "contracts/contract1.txt"},
		"validation_error_codes": [],
		"estimated_output_size_mb": 0.001,
		"required_capability": "filesystem.read",
		"resource_scope": "contracts",
	}
	d := runtime.decision with input as runtime_input_with_request("read_file", request)
	d.rule_id == "log_normal_runtime_call"
}

test_unknown_subject_denied if {
	input_value := object.union(runtime_input("read_file", "contracts/contract1.txt"), {"subject": unknown_subject})
	d := runtime.decision with input as input_value
	d.rule_id == "deny_unknown_subject"
	d.effect == "DENY"
}

test_unclassified_capability_denied if {
	input_value := runtime_input("generic_tool", "documents/file.txt")
	d := runtime.decision with input as input_value
	d.rule_id == "deny_unclassified_capability"
}

test_capability_absent_denied if {
	subject := object.union(resolved_subject, {"grants": [{"capability": "filesystem.list", "scopes": ["lab_root"]}]})
	input_value := object.union(runtime_input("read_file", "contracts/contract1.txt"), {"subject": subject})
	d := runtime.decision with input as input_value
	d.rule_id == "deny_capability_not_granted"
}

test_scope_absent_from_grant_denied if {
	subject := object.union(resolved_subject, {"grants": [{"capability": "filesystem.read", "scopes": ["contracts"]}]})
	input_value := object.union(runtime_input("read_file", "public/readme.txt"), {"subject": subject})
	d := runtime.decision with input as input_value
	d.rule_id == "deny_scope_not_granted"
}

test_exact_contract_grant_allows if {
	subject := object.union(resolved_subject, {"grants": [{"capability": "filesystem.read", "scopes": ["contracts"]}]})
	input_value := object.union(runtime_input("read_file", "contracts/contract1.txt"), {"subject": subject})
	d := runtime.decision with input as input_value
	d.rule_id == "allow_contracts_read"
}

test_cross_product_scope_attack_denied if {
	subject := object.union(resolved_subject, {"grants": [
		{"capability": "filesystem.read", "scopes": ["contracts"]},
		{"capability": "filesystem.list", "scopes": ["lab_root"]},
	]})
	input_value := object.union(runtime_input("read_file", "public/readme.txt"), {"subject": subject})
	d := runtime.decision with input as input_value
	d.rule_id == "deny_scope_not_granted"
}

test_two_grants_selects_matching_grant if {
	subject := object.union(resolved_subject, {"grants": [
		{"capability": "filesystem.read", "scopes": ["contracts"]},
		{"capability": "filesystem.list", "scopes": ["lab_root"]},
	]})
	input_value := object.union(runtime_input("list_files", "."), {"subject": subject})
	d := runtime.decision with input as input_value
	d.rule_id == "log_normal_runtime_call"
}

test_empty_grants_denied if {
	subject := object.union(resolved_subject, {"grants": []})
	input_value := object.union(runtime_input("read_file", "contracts/contract1.txt"), {"subject": subject})
	d := runtime.decision with input as input_value
	d.rule_id == "deny_capability_not_granted"
}

test_null_grants_denied if {
	subject := object.union(resolved_subject, {"grants": null})
	input_value := object.union(runtime_input("read_file", "contracts/contract1.txt"), {"subject": subject})
	d := runtime.decision with input as input_value
	d.rule_id == "deny_capability_not_granted"
}

test_string_grants_denied if {
	subject := object.union(resolved_subject, {"grants": "not-grants"})
	input_value := object.union(runtime_input("read_file", "contracts/contract1.txt"), {"subject": subject})
	d := runtime.decision with input as input_value
	d.rule_id == "deny_capability_not_granted"
}

test_non_object_grant_ignored if {
	subject := object.union(resolved_subject, {"grants": ["not-object"]})
	input_value := object.union(runtime_input("read_file", "contracts/contract1.txt"), {"subject": subject})
	d := runtime.decision with input as input_value
	d.rule_id == "deny_capability_not_granted"
}

test_non_string_capability_grant_ignored if {
	subject := object.union(resolved_subject, {"grants": [{"capability": 123, "scopes": ["contracts"]}]})
	input_value := object.union(runtime_input("read_file", "contracts/contract1.txt"), {"subject": subject})
	d := runtime.decision with input as input_value
	d.rule_id == "deny_capability_not_granted"
}

test_non_array_scopes_grant_ignored if {
	subject := object.union(resolved_subject, {"grants": [{"capability": "filesystem.read", "scopes": "contracts"}]})
	input_value := object.union(runtime_input("read_file", "contracts/contract1.txt"), {"subject": subject})
	d := runtime.decision with input as input_value
	d.rule_id == "deny_capability_not_granted"
}

test_non_string_scope_grant_ignored if {
	subject := object.union(resolved_subject, {"grants": [{"capability": "filesystem.read", "scopes": [123]}]})
	input_value := object.union(runtime_input("read_file", "contracts/contract1.txt"), {"subject": subject})
	d := runtime.decision with input as input_value
	d.rule_id == "deny_capability_not_granted"
}

test_unknown_server_beats_unknown_subject if {
	input_value := object.union(runtime_input_full("unknown", "read_file", 0, "medium", "contracts/contract1.txt", 0.001), {"subject": unknown_subject})
	d := runtime.decision with input as input_value
	d.rule_id == "block_unknown_server"
}

test_invalid_args_beat_unknown_subject if {
	input_value := object.union(runtime_input_invalid_arguments("read_file", {}), {"subject": unknown_subject})
	d := runtime.decision with input as input_value
	d.rule_id == "deny_invalid_arguments"
}

test_unknown_subject_beats_sensitive if {
	input_value := object.union(runtime_input("read_file", ".env"), {"subject": unknown_subject})
	d := runtime.decision with input as input_value
	d.rule_id == "deny_unknown_subject"
}

test_known_subject_without_grant_sensitive_denied_sensitive if {
	subject := object.union(resolved_subject, {"grants": []})
	input_value := object.union(runtime_input("read_file", ".env"), {"subject": subject})
	d := runtime.decision with input as input_value
	d.rule_id == "deny_sensitive_paths"
}

test_capability_denied_beats_approval if {
	subject := object.union(resolved_subject, {"grants": [{"capability": "filesystem.list", "scopes": ["lab_root"]}]})
	input_value := object.union(runtime_input_full("lab_trusted", "read_file", 0, "high", "contracts/contract1.txt", 0.001), {"subject": subject})
	d := runtime.decision with input as input_value
	d.rule_id == "deny_capability_not_granted"
}

test_scope_denied_beats_large_output if {
	subject := object.union(resolved_subject, {"grants": [{"capability": "filesystem.read", "scopes": ["contracts"]}]})
	input_value := object.union(runtime_input_full("lab_trusted", "read_file", 0, "medium", "public/readme.txt", 100), {"subject": subject})
	d := runtime.decision with input as input_value
	d.rule_id == "deny_scope_not_granted"
}

test_contract_authorized_with_exact_grant if {
	subject := object.union(resolved_subject, {"grants": [{"capability": "filesystem.read", "scopes": ["contracts"]}]})
	input_value := object.union(runtime_input("read_file", "contracts/contract1.txt"), {"subject": subject})
	d := runtime.decision with input as input_value
	d.decision == "ALLOW"
}

test_list_files_authorized_with_exact_grant if {
	subject := object.union(resolved_subject, {"grants": [{"capability": "filesystem.list", "scopes": ["lab_root"]}]})
	input_value := object.union(runtime_input("list_files", "."), {"subject": subject})
	d := runtime.decision with input as input_value
	d.rule_id == "log_normal_runtime_call"
}
