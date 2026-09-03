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

default request_operation := "unknown"

request_operation := value if {
	value := object.get(request_object, "operation", "unknown")
	is_string(value)
}

default resource_adapter := "unknown"

resource_adapter := value if {
	value := object.get(request_object, "resource_adapter", "unknown")
	is_string(value)
}

default resource_type := "unknown"

resource_type := value if {
	value := object.get(request_object, "resource_type", "unknown")
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

default analysis_status := "missing"

analysis_status := value if {
	value := object.get(tool_object, "analysis_status", "missing")
	is_string(value)
}

default approved_fingerprint_match := false

approved_fingerprint_match := value if {
	value := object.get(tool_object, "approved_fingerprint_match", false)
	is_boolean(value)
}

default policy_settings := {"rules": {}}

policy_settings := value if {
	value := object.get(input, "policy_settings", {"rules": {}})
	is_object(value)
}

default policy_rules := {}

policy_rules := value if {
	value := object.get(policy_settings, "rules", {})
	is_object(value)
}

default tool_analysis_required_rule := {}

tool_analysis_required_rule := value if {
	value := object.get(policy_rules, "tool_analysis_required", {})
	is_object(value)
}

default tool_analysis_required_severity := "critical"

tool_analysis_required_severity := lower(value) if {
	value := object.get(tool_analysis_required_rule, "severity", "CRITICAL")
	value in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
}

default build_security_object := {
	"mode": "DISABLED",
	"max_evidence_age_hours": 168,
	"evidence_present": false,
	"required_scanners_complete": false,
}

build_security_object := value if {
	value := object.get(input_object, "build_security", {})
	is_object(value)
}

default build_security_mode := "DISABLED"

build_security_mode := value if {
	value := object.get(build_security_object, "mode", "DISABLED")
	value in {"DISABLED", "ALLOW_WARN", "REQUIRE_PASS"}
}

default build_evidence_present := false

build_evidence_present := value if {
	value := object.get(build_security_object, "evidence_present", false)
	is_boolean(value)
}

default build_required_scanners_complete := false

build_required_scanners_complete := value if {
	value := object.get(build_security_object, "required_scanners_complete", false)
	is_boolean(value)
}

default build_assessment_status := ""

build_assessment_status := value if {
	value := object.get(build_security_object, "assessment_status", "")
	is_string(value)
}

default build_max_evidence_age_hours := 168

build_max_evidence_age_hours := value if {
	value := object.get(build_security_object, "max_evidence_age_hours", 168)
	is_number(value)
	value >= 1
	value <= 8760
}

build_security_gate_enabled if {
	build_security_mode != "DISABLED"
}

build_evidence_timestamp_valid if {
	build_evidence_present
	completed_at := object.get(build_security_object, "completed_at", null)
	is_string(completed_at)
	_ := time.parse_rfc3339_ns(completed_at)
}

build_evidence_stale if {
	build_security_gate_enabled
	build_evidence_present
	build_evidence_timestamp_valid
	completed_at := object.get(build_security_object, "completed_at", "")
	completed_ns := time.parse_rfc3339_ns(completed_at)
	now_ns := time.now_ns()
	completed_ns > now_ns
}

build_evidence_stale if {
	build_security_gate_enabled
	build_evidence_present
	build_evidence_timestamp_valid
	completed_at := object.get(build_security_object, "completed_at", "")
	completed_ns := time.parse_rfc3339_ns(completed_at)
	now_ns := time.now_ns()
	max_age_ns := build_max_evidence_age_hours * 60 * 60 * 1000000000
	now_ns - completed_ns > max_age_ns
}

build_evidence_missing if {
	build_security_gate_enabled
	not build_evidence_present
}

build_evidence_invalid if {
	build_security_gate_enabled
	build_evidence_present
	not build_evidence_timestamp_valid
}

build_evidence_scanner_incomplete if {
	build_security_gate_enabled
	build_evidence_present
	not build_required_scanners_complete
}

build_evidence_assessment_blocked if {
	build_security_gate_enabled
	build_evidence_present
	build_assessment_status in {"BLOCK", "ERROR"}
}

build_evidence_assessment_blocked if {
	build_security_mode == "REQUIRE_PASS"
	build_evidence_present
	build_assessment_status == "WARN"
}

default semantic_flagged := false

semantic_flagged := value if {
	value := object.get(tool_object, "semantic_flagged", false)
	is_boolean(value)
}

default deterministic_critical_finding := false

deterministic_critical_finding := value if {
	value := object.get(tool_object, "deterministic_critical_finding", false)
	is_boolean(value)
}

default consistency_status := "unknown"

consistency_status := value if {
	value := object.get(tool_object, "consistency_status", "unknown")
	is_string(value)
}

default drift_status := "unknown"

drift_status := value if {
	value := object.get(tool_object, "drift_status", "unknown")
	is_string(value)
}

default review_status := "missing"

review_status := value if {
	value := object.get(tool_object, "review_status", "missing")
	is_string(value)
}

default analyzer_revision := "unknown"

analyzer_revision := value if {
	value := object.get(tool_object, "analyzer_revision", "unknown")
	is_string(value)
}

decision_binding := {
	"decision_id": sprintf("%s:%s", [object.get(runtime_object, "control_plane_revision_id", "unknown"), object.get(request_object, "canonical_arguments_hash", "unknown")]),
	"control_plane_revision_id": object.get(runtime_object, "control_plane_revision_id", "unknown"),
	"control_plane_content_hash": object.get(runtime_object, "control_plane_content_hash", "unknown"),
	"canonical_arguments_hash": object.get(request_object, "canonical_arguments_hash", "unknown"),
}

default decision := {
	"effect": "DENY",
	"obligations": [
		{"type": "LOG", "parameters": {}},
		{"type": "ALERT", "parameters": {}},
	],
	"rule_ids": ["deny_no_policy_decision"],
	"reason": "No runtime policy decision matched.",
	"severity": "critical",
	"evidence": {},
	"recommended_action": null,
	"policy_revision": "opa-runtime-v2",
	"decision": "BLOCK",
	"rule_id": "deny_no_policy_decision",
}

security_model_v2 if {
	object.get(request_object, "security_model_version", "1") == "2"
}

decision := candidate.decision if {
	security_model_v2
	some candidate in v2_precondition_candidates
	candidate.precedence == winning_v2_precondition_precedence
}

decision := generic_v2_allow_decision if {
	security_model_v2
	count(v2_precondition_candidates) == 0
	generic_v2_allow
}

decision := generic_v2_sensitive_resource_block_decision if {
	security_model_v2
	count(v2_precondition_candidates) == 0
	v2_sensitive_reference_exists
}

decision := generic_v2_block_decision if {
	security_model_v2
	count(v2_precondition_candidates) == 0
	not generic_v2_allow
	not v2_sensitive_reference_exists
}

decision := candidate.decision if {
	not security_model_v2
	some candidate in rule_candidates
	candidate.precedence == winning_precedence
}

decision := log_normal_runtime_call_decision if {
	not security_model_v2
	count(rule_candidates) == 0
}

generic_v2_allow if {
	identity_status == "verified"
	session_status == "active"
	authorization_status == "resolved"
	not is_unknown_or_blocked_server
	arguments_valid
	analysis_status in {"APPROVED", "ADMIN_ALLOWED"}
	not deterministic_critical_finding
	review_status in {"APPROVED", "ADMIN_ALLOWED"}
	not v2_sensitive_reference_exists
	v2_snapshot_binding_valid
	v2_approval_valid
	v2_normalized_request_valid
	v2_effect_sets_match
	every effect in v2_contract_effects {
		v2_effect_authorized(effect)
	}
}

default v2_contract := {}

v2_contract := value if {
	value := object.get(request_object, "tool_security_contract", {})
	is_object(value)
}

default v2_contract_effects := []

v2_contract_effects := value if {
	value := object.get(v2_contract, "effects", [])
	is_array(value)
}

default v2_facts := {}

v2_facts := value if {
	value := object.get(request_object, "normalized_facts", {})
	is_object(value)
}

default v2_fact_effects := []

v2_fact_effects := value if {
	value := object.get(v2_facts, "effects", [])
	is_array(value)
}

default v2_approval := {}

v2_approval := value if {
	value := object.get(request_object, "tool_observation_approval", {})
	is_object(value)
}

default v2_scopes := []

v2_scopes := value if {
	value := object.get(request_object, "authority_resource_scopes", [])
	is_array(value)
}

default v2_capability_catalog := []

v2_capability_catalog := value if {
	value := object.get(request_object, "capability_catalog", [])
	is_array(value)
}

default runtime_object := {}

runtime_object := value if {
	value := object.get(input_object, "runtime", {})
	is_object(value)
}

v2_snapshot_binding_valid if {
	revision_id := object.get(runtime_object, "control_plane_revision_id", "")
	revision_hash := object.get(runtime_object, "control_plane_content_hash", "")
	is_string(revision_id)
	revision_id != ""
	revision_id != "unknown"
	is_string(revision_hash)
	regex.match("^[0-9a-f]{64}$", revision_hash)
	object.get(v2_contract, "contract_version", "") == "2"
	object.get(v2_contract, "server_ref", "") == object.get(server_object, "server_ref", "")
	object.get(v2_contract, "tool_name", "") == tool_name
	count(v2_contract_effects) > 0
}

v2_approval_valid if {
	object.get(v2_approval, "server_ref", "") == object.get(server_object, "server_ref", "")
	object.get(v2_approval, "upstream_protocol_profile_id", "") == object.get(runtime_object, "upstream_protocol_profile_id", "")
	object.get(v2_approval, "tool_fingerprint", "") == object.get(tool_object, "current_fingerprint", "")
	object.get(v2_approval, "contract_hash", "") == object.get(request_object, "contract_hash", "")
	object.get(v2_approval, "revision_id", "") == object.get(runtime_object, "control_plane_revision_id", "")
	regex.match("^[0-9a-f]{64}$", object.get(v2_approval, "evidence_bundle_hash", ""))
}

v2_normalized_request_valid if {
	object.get(v2_facts, "facts_schema_version", "") == "1"
	count(object.get(v2_facts, "errors", ["missing"])) == 0
	fact_request := object.get(v2_facts, "request", {})
	is_object(fact_request)
	object.get(fact_request, "server_ref", "") == object.get(server_object, "server_ref", "")
	object.get(fact_request, "tool_name", "") == tool_name
	object.get(fact_request, "canonical_args_hash", "") == object.get(request_object, "canonical_arguments_hash", "")
	object.get(fact_request, "client_protocol_profile_id", "") == object.get(runtime_object, "client_protocol_profile_id", "")
	object.get(fact_request, "upstream_protocol_profile_id", "") == object.get(runtime_object, "upstream_protocol_profile_id", "")
}

v2_effect_sets_match if {
	count(v2_contract_effects) > 0
	count(v2_contract_effects) == count(v2_fact_effects)
	contract_ids := {object.get(effect, "effect_id", "") | some effect in v2_contract_effects}
	fact_ids := {object.get(effect, "effect_id", "") | some effect in v2_fact_effects}
	count(contract_ids) == count(v2_contract_effects)
	count(fact_ids) == count(v2_fact_effects)
	contract_ids == fact_ids
}

v2_effect_authorized(effect) if {
	is_object(effect)
	effect_id := object.get(effect, "effect_id", "")
	capability_id := object.get(effect, "capability", "")
	effect_id != ""
	capability := v2_catalog_capability(capability_id)
	object.get(capability, "lifecycle", "") == "ACTIVE"
	fact := v2_fact_for_effect(effect_id)
	object.get(fact, "capability_id", "") == capability_id
	object.get(fact, "effective_reference_precision", "OPAQUE") == "EXPLICIT"
	object.get(fact, "requires_resource", null) == object.get(capability, "requires_resource", null)
	v2_subject_has_capability(capability_id)
	v2_cardinality_valid(effect, fact)
	v2_resource_semantics_valid(effect, fact, capability)
}

v2_catalog_capability(capability_id) := capability if {
	matches := [item |
		some item in v2_capability_catalog
		is_object(item)
		object.get(item, "id", "") == capability_id
	]
	count(matches) == 1
	capability := matches[0]
}

v2_fact_for_effect(effect_id) := fact if {
	matches := [item |
		some item in v2_fact_effects
		is_object(item)
		object.get(item, "effect_id", "") == effect_id
	]
	count(matches) == 1
	fact := matches[0]
}

v2_subject_has_capability(capability_id) if {
	some grant in subject_grants
	grant.capability == capability_id
}

v2_cardinality_valid(effect, fact) if {
	maximum := object.get(effect, "max_resource_cardinality", null)
	maximum == null
	count(object.get(fact, "bindings", [])) >= 0
}

v2_cardinality_valid(effect, fact) if {
	maximum := object.get(effect, "max_resource_cardinality", null)
	is_number(maximum)
	maximum >= 1
	total := sum([object.get(binding, "occurrence_count", 0) |
		some binding in object.get(fact, "bindings", [])
		is_object(binding)
	])
	total <= maximum
}

v2_resource_semantics_valid(effect, fact, capability) if {
	object.get(capability, "requires_resource", true) == false
	count(object.get(effect, "resource_bindings", [])) == 0
	object.get(effect, "fixed_resource", null) == null
	count(object.get(fact, "bindings", [])) == 0
}

v2_resource_semantics_valid(effect, fact, capability) if {
	object.get(capability, "requires_resource", false) == true
	expected := object.get(effect, "resource_bindings", [])
	actual := object.get(fact, "bindings", [])
	is_array(expected)
	is_array(actual)
	count(expected) > 0
	count(expected) == count(actual)
	every binding in expected {
		v2_binding_authorized(binding, actual, object.get(effect, "capability", ""))
	}
}

v2_resource_semantics_valid(effect, fact, capability) if {
	object.get(capability, "requires_resource", false) == true
	count(object.get(effect, "resource_bindings", [])) == 0
	fixed := object.get(effect, "fixed_resource", null)
	is_object(fixed)
	actual := object.get(fact, "bindings", [])
	is_array(actual)
	count(actual) == 1
	expected := {
		"path": [],
		"resource_type": object.get(fixed, "resource_type", ""),
	}
	v2_binding_authorized(expected, actual, object.get(effect, "capability", ""))
}

v2_binding_authorized(expected, actual_bindings, capability_id) if {
	path := object.get(expected, "path", [])
	resource_type_id := object.get(expected, "resource_type", "")
	matches := [binding |
		some binding in actual_bindings
		object.get(binding, "path", []) == path
		object.get(binding, "resource_type", "") == resource_type_id
	]
	count(matches) == 1
	binding := matches[0]
	object.get(binding, "status", "") == "resolved"
	object.get(binding, "truncated", true) == false
	occurrences := object.get(binding, "occurrence_count", 0)
	references := object.get(binding, "references", [])
	occurrences > 0
	count(references) == occurrences
	every reference in references {
		v2_reference_authorized(reference, capability_id)
	}
}

v2_reference_authorized(reference, capability_id) if {
	is_object(reference)
	authority := object.get(reference, "authority", "")
	resource_type_id := object.get(reference, "resource_type", "")
	canonical_value := object.get(reference, "canonical_value", "")
	authority != ""
	resource_type_id != ""
	canonical_value != ""
	some grant in subject_grants
	grant.capability == capability_id
	some scope_id in grant.scopes
	some scope in v2_scopes
	object.get(scope, "scope_id", "") == scope_id
	object.get(scope, "authority", "") == authority
	object.get(scope, "resource_type", "") == resource_type_id
	v2_scope_matches(scope, reference)
}

v2_sensitive_reference_exists if {
	some effect in v2_fact_effects
	some binding in object.get(effect, "bindings", [])
	some reference in object.get(binding, "references", [])
	object.get(reference, "resource_sensitivity", "unknown") == "secret"
}

v2_sensitive_reference_exists if {
	some effect in v2_fact_effects
	some binding in object.get(effect, "bindings", [])
	some reference in object.get(binding, "references", [])
	flags := object.get(reference, "resource_flags", [])
	is_array(flags)
	some flag in flags
	flag in {"sensitive_name", "sensitive_directory", "denied_pattern"}
}

v2_sensitive_reference_exists if {
	some effect in v2_fact_effects
	some binding in object.get(effect, "bindings", [])
	some reference in object.get(binding, "references", [])
	object.get(reference, "resource_type", "") == "filesystem_path"
	canonical := object.get(reference, "canonical_value", "")
	is_string(canonical)
	some pattern in sensitive_path_patterns
	contains(lower(canonical), lower(pattern))
}

v2_scope_matches(scope, reference) if {
	object.get(scope, "match_mode", "") == "SELF"
	object.get(scope, "canonical_value", "") == object.get(reference, "canonical_value", "")
}

v2_scope_matches(scope, reference) if {
	object.get(scope, "match_mode", "") == "SUBTREE"
	ancestors := object.get(reference, "ancestors", [])
	is_array(ancestors)
	object.get(scope, "canonical_value", "") in ancestors
}

generic_v2_allow_decision := v2_decision(
	"ALLOW",
	"ALLOW",
	"allow_generic_security_model_v2",
	"All generic security model effects are authorized.",
	"low",
)

generic_v2_block_decision := v2_decision(
	"DENY",
	"BLOCK",
	"deny_generic_security_model_v2",
	"Generic security model authorization requirements were not satisfied.",
	"high",
)

generic_v2_sensitive_resource_block_decision := v2_decision(
	"DENY",
	"BLOCK",
	"deny_sensitive_resource",
	"Sensitive resource access is forbidden.",
	"critical",
)

v2_decision(effect, runtime_decision, rule_id, reason, severity) := {
	"effect": effect,
	"obligations": obligations,
	"rule_ids": [rule_id],
	"reason": reason,
	"severity": severity,
	"evidence": {},
	"recommended_action": null,
	"policy_revision": policy_revision,
	"decision": runtime_decision,
	"rule_id": rule_id,
	"decision_id": sprintf("%s:%s", [object.get(runtime_object, "control_plane_revision_id", "unknown"), object.get(request_object, "canonical_arguments_hash", "unknown")]),
	"control_plane_revision_id": object.get(runtime_object, "control_plane_revision_id", "unknown"),
	"control_plane_content_hash": object.get(runtime_object, "control_plane_content_hash", "unknown"),
	"canonical_arguments_hash": object.get(request_object, "canonical_arguments_hash", "unknown"),
} if {
	obligations := [{"type": "LOG", "parameters": {}}]
	effect == "ALLOW"
}

v2_decision(effect, runtime_decision, rule_id, reason, severity) := {
	"effect": effect,
	"obligations": obligations,
	"rule_ids": [rule_id],
	"reason": reason,
	"severity": severity,
	"evidence": {},
	"recommended_action": null,
	"policy_revision": policy_revision,
	"decision": runtime_decision,
	"rule_id": rule_id,
	"decision_id": sprintf("%s:%s", [object.get(runtime_object, "control_plane_revision_id", "unknown"), object.get(request_object, "canonical_arguments_hash", "unknown")]),
	"control_plane_revision_id": object.get(runtime_object, "control_plane_revision_id", "unknown"),
	"control_plane_content_hash": object.get(runtime_object, "control_plane_content_hash", "unknown"),
	"canonical_arguments_hash": object.get(request_object, "canonical_arguments_hash", "unknown"),
} if {
	obligations := [
		{"type": "LOG", "parameters": {}},
		{"type": "ALERT", "parameters": {}},
	]
	effect == "DENY"
}

winning_precedence := max({candidate.precedence | some candidate in rule_candidates})

winning_v2_precondition_precedence := max({
	candidate.precedence |
	some candidate in v2_precondition_candidates
})

v2_precondition_candidates contains {
	"precedence": 1000,
	"decision": deny_missing_or_unapproved_analysis_decision,
} if {
	analysis_blocks_runtime
}

v2_precondition_candidates contains {
	"precedence": 999,
	"decision": deny_tool_fingerprint_mismatch_decision,
} if {
	analysis_status in {"APPROVED", "ADMIN_ALLOWED"}
	not approved_fingerprint_match
}

v2_precondition_candidates contains {
	"precedence": 998,
	"decision": deny_drift_not_approved_decision,
} if {
	drift_status in {"HIGH", "CRITICAL"}
	not approved_fingerprint_match
}

v2_precondition_candidates contains {
	"precedence": 997,
	"decision": deny_deterministic_critical_finding_decision,
} if {
	deterministic_critical_finding
}

v2_precondition_candidates contains {
	"precedence": 996,
	"decision": deny_semantic_review_required_decision,
} if {
	semantic_flagged
	not review_status == "APPROVED"
	not review_status == "ADMIN_ALLOWED"
}

v2_precondition_candidates contains {
	"precedence": 995,
	"decision": deny_review_required_decision,
} if {
	review_status == "REVIEW_REQUIRED"
}

v2_precondition_candidates contains {
	"precedence": 994,
	"decision": deny_build_security_evidence_missing_decision,
} if {
	build_evidence_missing
}

v2_precondition_candidates contains {
	"precedence": 993,
	"decision": deny_build_security_evidence_invalid_decision,
} if {
	build_evidence_invalid
}

v2_precondition_candidates contains {
	"precedence": 992,
	"decision": deny_build_security_evidence_stale_decision,
} if {
	build_evidence_stale
}

v2_precondition_candidates contains {
	"precedence": 991,
	"decision": deny_build_security_scanner_incomplete_decision,
} if {
	build_evidence_scanner_incomplete
}

v2_precondition_candidates contains {
	"precedence": 990,
	"decision": deny_build_security_assessment_decision,
} if {
	build_evidence_assessment_blocked
}

v2_precondition_candidates contains {
	"precedence": 897,
	"decision": deny_invalid_arguments_decision,
} if {
	not arguments_valid
}

rule_candidates contains {
	"precedence": 1000,
	"decision": deny_missing_or_unapproved_analysis_decision,
} if {
	analysis_blocks_runtime
}

rule_candidates contains {
	"precedence": 999,
	"decision": deny_tool_fingerprint_mismatch_decision,
} if {
	analysis_status in {"APPROVED", "ADMIN_ALLOWED"}
	not approved_fingerprint_match
}

rule_candidates contains {
	"precedence": 998,
	"decision": deny_drift_not_approved_decision,
} if {
	drift_status in {"HIGH", "CRITICAL"}
	not approved_fingerprint_match
}

rule_candidates contains {
	"precedence": 997,
	"decision": deny_deterministic_critical_finding_decision,
} if {
	deterministic_critical_finding
}

rule_candidates contains {
	"precedence": 996,
	"decision": deny_semantic_review_required_decision,
} if {
	semantic_flagged
	not review_status == "APPROVED"
	not review_status == "ADMIN_ALLOWED"
}

rule_candidates contains {
	"precedence": 995,
	"decision": deny_review_required_decision,
} if {
	review_status == "REVIEW_REQUIRED"
}

rule_candidates contains {
	"precedence": 994,
	"decision": deny_build_security_evidence_missing_decision,
} if {
	build_evidence_missing
}

rule_candidates contains {
	"precedence": 993,
	"decision": deny_build_security_evidence_invalid_decision,
} if {
	build_evidence_invalid
}

rule_candidates contains {
	"precedence": 992,
	"decision": deny_build_security_evidence_stale_decision,
} if {
	build_evidence_stale
}

rule_candidates contains {
	"precedence": 991,
	"decision": deny_build_security_scanner_incomplete_decision,
} if {
	build_evidence_scanner_incomplete
}

rule_candidates contains {
	"precedence": 990,
	"decision": deny_build_security_assessment_decision,
} if {
	build_evidence_assessment_blocked
}

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
	"decision": allow_authorized_resource_decision,
} if {
	authorized_legacy_resource_call
}

is_unknown_or_blocked_server if {
	not trusted_server_status
}

trusted_server_status if {
	trust_status in {"trusted", "lab_trusted"}
}

analysis_blocks_runtime if {
	analysis_status in {
		"missing",
		"PENDING_ANALYSIS",
		"QUARANTINED",
		"ANALYSIS_FAILED",
		"BLOCKED",
		"STALE",
	}
}

is_sensitive_path if {
	some pattern in sensitive_path_patterns
	contains(canonical_resource_lower, lower(pattern))
}

authorized_legacy_resource_call if {
	request_operation != "unknown"
	resource_adapter != "unknown"
	resource_type != "unknown"
	resource_resolution_status == "resolved"
	required_capability != "unclassified"
	subject_has_required_capability
	subject_has_required_capability_scope
	operation_allowed_on_scope
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

deny_unverified_identity_decision := object.union(
	{
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
	},
	decision_binding,
)

deny_invalid_or_expired_session_decision := object.union(
	{
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
	},
	decision_binding,
)

deny_unknown_subject_decision := deny_decision(
	"deny_unknown_subject",
	"Subject authorization is unknown.",
)

deny_unknown_tool_security_profile_decision := deny_decision(
	"deny_unknown_tool_security_profile",
	"Tool security profile is unknown.",
)

deny_missing_or_unapproved_analysis_decision := object.union(
	{
		"effect": "DENY",
		"obligations": [
			{"type": "LOG", "parameters": {}},
			{"type": "ALERT", "parameters": {}},
		],
		"rule_ids": ["deny_tool_analysis_not_approved"],
		"reason": "Tool analysis is missing, pending, failed, blocked, stale, or not approved.",
		"severity": tool_analysis_required_severity,
		"evidence": {
			"analysis_status": analysis_status,
			"review_status": review_status,
			"analyzer_revision": analyzer_revision,
		},
		"recommended_action": "Review and approve the exact analyzed tool fingerprint.",
		"policy_revision": policy_revision,
		"decision": "BLOCK",
		"rule_id": "deny_tool_analysis_not_approved",
	},
	decision_binding,
)

deny_tool_fingerprint_mismatch_decision := deny_decision(
	"deny_tool_fingerprint_mismatch",
	"Current tool fingerprint does not match the approved baseline.",
)

deny_drift_not_approved_decision := deny_decision(
	"deny_tool_drift_not_approved",
	"High or critical tool drift is not approved.",
)

deny_deterministic_critical_finding_decision := deny_decision(
	"deny_tool_deterministic_critical_finding",
	"Tool analysis has a deterministic critical finding.",
)

deny_semantic_review_required_decision := object.union(
	{
		"effect": "DENY",
		"obligations": [
			{"type": "LOG", "parameters": {}},
			{"type": "ALERT", "parameters": {}},
		],
		"rule_ids": ["deny_tool_semantic_review_required"],
		"reason": "Semantic analysis flagged the tool for human review.",
		"severity": "high",
		"evidence": {
			"analysis_status": analysis_status,
			"review_status": review_status,
		},
		"recommended_action": "Review the semantic finding before approving this fingerprint.",
		"policy_revision": policy_revision,
		"decision": "BLOCK",
		"rule_id": "deny_tool_semantic_review_required",
	},
	decision_binding,
)

deny_review_required_decision := object.union(
	{
		"effect": "DENY",
		"obligations": [
			{"type": "LOG", "parameters": {}},
			{"type": "ALERT", "parameters": {}},
		],
		"rule_ids": ["deny_tool_review_required"],
		"reason": "Tool analysis requires human review.",
		"severity": "high",
		"evidence": {
			"analysis_status": analysis_status,
			"review_status": review_status,
		},
		"recommended_action": "Approve or block the exact fingerprint through the review workflow.",
		"policy_revision": policy_revision,
		"decision": "BLOCK",
		"rule_id": "deny_tool_review_required",
	},
	decision_binding,
)

deny_build_security_evidence_missing_decision := object.union(
	v2_decision(
		"DENY",
		"BLOCK",
		"deny_build_security_evidence_missing",
		"Required Build Security evidence is missing for this MCP server.",
		"critical",
	),
	{
		"evidence": {
			"build_security_mode": build_security_mode,
		},
		"recommended_action": "Run Build Security and publish the resulting evidence reference.",
	},
)

deny_build_security_evidence_invalid_decision := object.union(
	v2_decision(
		"DENY",
		"BLOCK",
		"deny_build_security_evidence_invalid",
		"Published Build Security evidence is malformed or incomplete.",
		"critical",
	),
	{
		"evidence": {
			"build_security_mode": build_security_mode,
			"scan_id": object.get(build_security_object, "scan_id", null),
		},
		"recommended_action": "Publish a valid Build Security evidence reference.",
	},
)

deny_build_security_evidence_stale_decision := object.union(
	v2_decision(
		"DENY",
		"BLOCK",
		"deny_build_security_evidence_stale",
		"Published Build Security evidence is stale or dated in the future.",
		"critical",
	),
	{
		"evidence": {
			"build_security_mode": build_security_mode,
			"scan_id": object.get(build_security_object, "scan_id", null),
			"completed_at": object.get(build_security_object, "completed_at", null),
			"max_evidence_age_hours": build_max_evidence_age_hours,
		},
		"recommended_action": "Run a current Build Security scan and publish its evidence.",
	},
)

deny_build_security_scanner_incomplete_decision := object.union(
	v2_decision(
		"DENY",
		"BLOCK",
		"deny_build_security_scanner_incomplete",
		"Build Security evidence was produced without all required scanners completing.",
		"critical",
	),
	{
		"evidence": {
			"build_security_mode": build_security_mode,
			"scan_id": object.get(build_security_object, "scan_id", null),
			"assessment_status": build_assessment_status,
		},
		"recommended_action": "Resolve required scanner failures and run Build Security again.",
	},
)

deny_build_security_assessment_decision := object.union(
	v2_decision(
		"DENY",
		"BLOCK",
		"deny_build_security_assessment",
		"Build Security assessment does not satisfy the published Runtime gate.",
		"critical",
	),
	{
		"evidence": {
			"build_security_mode": build_security_mode,
			"scan_id": object.get(build_security_object, "scan_id", null),
			"assessment_status": build_assessment_status,
			"assessment_policy_version": object.get(build_security_object, "assessment_policy_version", null),
		},
		"recommended_action": "Remediate Build findings or publish an evidence status permitted by the configured gate.",
	},
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

deny_sensitive_resource_decision := object.union(
	{
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
	},
	decision_binding,
)

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

allow_authorized_resource_decision := object.union(
	{
		"effect": "ALLOW",
		"obligations": [{"type": "LOG", "parameters": {}}],
		"rule_ids": ["allow_authorized_resource"],
		"reason": "The requested resource operation is authorized.",
		"severity": "low",
		"evidence": {},
		"recommended_action": null,
		"policy_revision": policy_revision,
		"decision": "ALLOW",
		"rule_id": "allow_authorized_resource",
	},
	decision_binding,
)

warn_high_risk_tool_decision := object.union(
	{
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
	},
	decision_binding,
)

require_approval_for_sensitive_tool_decision := object.union(
	{
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
	},
	decision_binding,
)

limit_large_outputs_decision := object.union(
	{
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
	},
	decision_binding,
)

log_normal_runtime_call_decision := object.union(
	{
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
	},
	decision_binding,
)

deny_decision(rule_id, reason) := object.union(
	{
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
	},
	decision_binding,
)
