package mcp.security.runtime

import rego.v1

v2_hash := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
v2_fingerprint := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
v2_evidence := "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

base_v2_input := {
	"subject": {
		"agent_id": "agent-1",
		"identity_status": "verified",
		"identity_issuer": "issuer",
		"identity_binding_revision": v2_hash,
		"session_status": "active",
		"session_reference": "session-1",
		"role": "operator",
		"authorization_status": "resolved",
		"authorization_revision": v2_hash,
		"grants": [{"capability": "message.send", "scopes": ["mail.alice"]}],
		"allowed_capabilities": [],
		"allowed_scopes": [],
	},
	"server": {
		"id": 1,
		"endpoint": "http://127.0.0.1:9000/mcp",
		"server_ref": "demo-mail-server",
		"known": true,
		"trusted": true,
		"trust_status": "trusted",
		"security_status": "approved",
	},
	"tool": {
		"id": 1,
		"name": "send_email",
		"profile_status": "resolved",
		"profile_revision": v2_hash,
		"risk_score": 1,
		"sensitivity": "low",
		"capabilities": [],
		"admission_status": "approved",
		"description_risk_score": 1,
		"capability_mismatch": false,
		"drift_status": "NONE",
		"analysis_status": "APPROVED",
		"current_fingerprint": v2_fingerprint,
		"approved_fingerprint_match": true,
		"risk_level": "low",
		"semantic_flagged": false,
		"deterministic_critical_finding": false,
		"consistency_status": "consistent",
		"review_status": "APPROVED",
		"analyzer_revision": "v1",
	},
	"request": {
		"operation": "message.send",
		"resource_adapter": "generic-declarative",
		"resource_type": "email_address",
		"resource_scope": "v2_authority_scopes",
		"required_capability": "message.send",
		"canonical_resource": "alice@example.com",
		"arguments": {"recipient": "alice@example.com", "subject": "hello", "body": "world"},
		"arguments_valid": true,
		"validation_error_codes": [],
		"resource_sensitivity": "governed",
		"resource_resolution_status": "resolved",
		"resource_flags": [],
		"resource_registry_revision": "v2",
		"tool_profile_revision": v2_hash,
		"operation_allowed_on_scope": false,
		"canonical_arguments_hash": v2_hash,
		"estimated_output_size_mb": 0.001,
		"security_model_version": "2",
		"contract_hash": v2_hash,
		"tool_security_contract": {
			"contract_version": "2",
			"server_ref": "demo-mail-server",
			"tool_name": "send_email",
			"effects": [{
				"effect_id": "send",
				"capability": "message.send",
				"resource_bindings": [{"path": ["recipient"], "resource_type": "email_address"}],
				"max_resource_cardinality": 1,
				"declared_reference_precision": "EXPLICIT",
			}],
			"unbound_arguments": [["subject"], ["body"]],
		},
		"normalized_facts": {
			"facts_schema_version": "1",
			"request": {
				"server_ref": "demo-mail-server",
				"tool_name": "send_email",
				"canonical_args_hash": v2_hash,
				"client_protocol_profile_id": "mcp-modern-2026-07-28-restricted-v1",
				"upstream_protocol_profile_id": "mcp-legacy-2025-11-25-restricted-v1",
			},
			"effects": [{
				"effect_id": "send",
				"capability_id": "message.send",
				"requires_resource": true,
				"adapter_id": "generic-declarative",
				"adapter_api_version": "1",
				"declared_reference_precision": "EXPLICIT",
				"runtime_reference_precision": "EXPLICIT",
				"effective_reference_precision": "EXPLICIT",
				"max_resource_cardinality": 1,
				"bindings": [{
					"path": ["recipient"],
					"status": "resolved",
					"resource_type": "email_address",
					"occurrence_count": 1,
					"truncated": false,
					"references": [{
						"authority": "demo-mail-server",
						"resource_type": "email_address",
						"canonical_value": "alice@example.com",
						"ancestors": [],
					}],
				}],
			}],
			"errors": [],
		},
		"tool_observation_approval": {
			"tool_observation_id": 1,
			"server_ref": "demo-mail-server",
			"upstream_protocol_profile_id": "mcp-legacy-2025-11-25-restricted-v1",
			"tool_fingerprint": v2_fingerprint,
			"contract_hash": v2_hash,
			"evidence_bundle_hash": v2_evidence,
			"admin_id": "admin-1",
			"approved_at": "2026-01-01T00:00:00Z",
			"revision_id": "revision-2",
		},
		"authority_resource_scopes": [{
			"scope_id": "mail.alice",
			"authority": "demo-mail-server",
			"resource_type": "email_address",
			"canonical_value": "alice@example.com",
			"match_mode": "SELF",
			"broad_scope_acknowledged": false,
		}],
		"capability_catalog": [{
			"id": "message.send",
			"domain": "message",
			"verb": "send",
			"destructive": false,
			"requires_resource": true,
			"allowed_resource_types": ["email_address"],
			"lifecycle": "ACTIVE",
		}],
	},
	"runtime": {
		"environment": "test",
		"session_id": "session-1",
		"control_plane_revision_id": "revision-2",
		"control_plane_revision_number": 2,
		"control_plane_content_hash": v2_hash,
		"client_protocol_profile_id": "mcp-modern-2026-07-28-restricted-v1",
		"upstream_protocol_profile_id": "mcp-legacy-2025-11-25-restricted-v1",
	},
}

test_v2_generic_send_email_allow if {
	result := decision with input as base_v2_input
	result.decision == "ALLOW"
}

test_v2_semantic_flag_without_approval_blocks if {
	tool := object.union(base_v2_input.tool, {"semantic_flagged": true, "analysis_status": "REVIEW_REQUIRED", "review_status": "REVIEW_REQUIRED", "approved_fingerprint_match": false})
	result := decision with input as object.union(base_v2_input, {"tool": tool})
	result.decision == "BLOCK"
}

test_v2_semantic_flag_after_exact_admin_approval_can_allow if {
	tool := object.union(base_v2_input.tool, {"semantic_flagged": true, "analysis_status": "APPROVED", "review_status": "APPROVED", "approved_fingerprint_match": true})
	result := decision with input as object.union(base_v2_input, {"tool": tool})
	result.decision == "ALLOW"
}

test_v2_semantic_flag_stale_fingerprint_blocks if {
	tool := object.union(base_v2_input.tool, {"semantic_flagged": true, "current_fingerprint": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", "approved_fingerprint_match": false})
	result := decision with input as object.union(base_v2_input, {"tool": tool})
	result.decision == "BLOCK"
}

test_v2_analysis_failed_blocks if {
	tool := object.union(base_v2_input.tool, {"analysis_status": "ANALYSIS_FAILED", "review_status": "ANALYSIS_FAILED"})
	result := decision with input as object.union(base_v2_input, {"tool": tool})
	result.decision == "BLOCK"
}

test_v2_missing_approval_blocks if {
	request := object.union(base_v2_input.request, {"tool_observation_approval": {"server_ref": ""}})
	result := decision with input as object.union(base_v2_input, {"request": request})
	result.decision == "BLOCK"
}

test_v2_empty_effects_blocks if {
	contract := object.union(base_v2_input.request.tool_security_contract, {"effects": []})
	request := object.union(base_v2_input.request, {"tool_security_contract": contract})
	result := decision with input as object.union(base_v2_input, {"request": request})
	result.decision == "BLOCK"
}

test_v2_missing_reference_blocks if {
	binding := object.union(base_v2_input.request.normalized_facts.effects[0].bindings[0], {"occurrence_count": 0, "references": []})
	fact_effect := object.union(base_v2_input.request.normalized_facts.effects[0], {"bindings": [binding]})
	facts := object.union(base_v2_input.request.normalized_facts, {"effects": [fact_effect]})
	request := object.union(base_v2_input.request, {"normalized_facts": facts})
	result := decision with input as object.union(base_v2_input, {"request": request})
	result.decision == "BLOCK"
}

test_v2_selector_precision_blocks if {
	fact_effect := object.union(base_v2_input.request.normalized_facts.effects[0], {"effective_reference_precision": "SELECTOR"})
	facts := object.union(base_v2_input.request.normalized_facts, {"effects": [fact_effect]})
	request := object.union(base_v2_input.request, {"normalized_facts": facts})
	result := decision with input as object.union(base_v2_input, {"request": request})
	result.decision == "BLOCK"
}

test_v2_opaque_precision_blocks if {
	fact_effect := object.union(base_v2_input.request.normalized_facts.effects[0], {"effective_reference_precision": "OPAQUE"})
	facts := object.union(base_v2_input.request.normalized_facts, {"effects": [fact_effect]})
	request := object.union(base_v2_input.request, {"normalized_facts": facts})
	result := decision with input as object.union(base_v2_input, {"request": request})
	result.decision == "BLOCK"
}

test_v2_adapter_error_blocks if {
	facts := object.union(base_v2_input.request.normalized_facts, {"errors": ["adapter_error"]})
	request := object.union(base_v2_input.request, {"normalized_facts": facts})
	result := decision with input as object.union(base_v2_input, {"request": request})
	result.decision == "BLOCK"
}

test_v2_unknown_capability_blocks if {
	contract_effect := object.union(base_v2_input.request.tool_security_contract.effects[0], {"capability": "message.unknown"})
	contract := object.union(base_v2_input.request.tool_security_contract, {"effects": [contract_effect]})
	fact_effect := object.union(base_v2_input.request.normalized_facts.effects[0], {"capability_id": "message.unknown"})
	facts := object.union(base_v2_input.request.normalized_facts, {"effects": [fact_effect]})
	request := object.union(base_v2_input.request, {"tool_security_contract": contract, "normalized_facts": facts})
	subject := object.union(base_v2_input.subject, {"grants": [{"capability": "message.unknown", "scopes": ["mail.alice"]}]})
	result := decision with input as object.union(base_v2_input, {"request": request, "subject": subject})
	result.decision == "BLOCK"
}

test_v2_stale_approval_fingerprint_blocks if {
	approval := object.union(base_v2_input.request.tool_observation_approval, {"tool_fingerprint": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"})
	request := object.union(base_v2_input.request, {"tool_observation_approval": approval})
	result := decision with input as object.union(base_v2_input, {"request": request})
	result.decision == "BLOCK"
}

test_v2_authority_mismatch_blocks if {
	reference := object.union(base_v2_input.request.normalized_facts.effects[0].bindings[0].references[0], {"authority": "other-server"})
	binding := object.union(base_v2_input.request.normalized_facts.effects[0].bindings[0], {"references": [reference]})
	fact_effect := object.union(base_v2_input.request.normalized_facts.effects[0], {"bindings": [binding]})
	facts := object.union(base_v2_input.request.normalized_facts, {"effects": [fact_effect]})
	request := object.union(base_v2_input.request, {"normalized_facts": facts})
	result := decision with input as object.union(base_v2_input, {"request": request})
	result.decision == "BLOCK"
}

test_v2_cardinality_counts_occurrences_before_deduplication if {
	binding := object.union(base_v2_input.request.normalized_facts.effects[0].bindings[0], {"occurrence_count": 2, "references": array.concat(base_v2_input.request.normalized_facts.effects[0].bindings[0].references, base_v2_input.request.normalized_facts.effects[0].bindings[0].references)})
	fact_effect := object.union(base_v2_input.request.normalized_facts.effects[0], {"bindings": [binding]})
	facts := object.union(base_v2_input.request.normalized_facts, {"effects": [fact_effect]})
	request := object.union(base_v2_input.request, {"normalized_facts": facts})
	result := decision with input as object.union(base_v2_input, {"request": request})
	result.decision == "BLOCK"
}

test_v2_scope_prefix_bypass_blocks if {
	reference := {"authority": "files-a", "resource_type": "filesystem_path", "canonical_value": "/database-secret", "ancestors": ["/", "/database-secret"]}
	binding := {"path": ["path"], "status": "resolved", "resource_type": "filesystem_path", "occurrence_count": 1, "truncated": false, "references": [reference]}
	fact_effect := object.union(base_v2_input.request.normalized_facts.effects[0], {"capability_id": "filesystem.read", "bindings": [binding]})
	facts := object.union(base_v2_input.request.normalized_facts, {"effects": [fact_effect]})
	contract_effect := {"effect_id": "send", "capability": "filesystem.read", "resource_bindings": [{"path": ["path"], "resource_type": "filesystem_path"}], "max_resource_cardinality": 1, "declared_reference_precision": "EXPLICIT"}
	contract := object.union(base_v2_input.request.tool_security_contract, {"effects": [contract_effect]})
	scope := {"scope_id": "files.data", "authority": "files-a", "resource_type": "filesystem_path", "canonical_value": "/data", "match_mode": "SUBTREE", "broad_scope_acknowledged": false}
	catalog := [{"id": "filesystem.read", "domain": "filesystem", "verb": "read", "destructive": false, "requires_resource": true, "allowed_resource_types": ["filesystem_path"], "lifecycle": "ACTIVE"}]
	request := object.union(base_v2_input.request, {"tool_security_contract": contract, "normalized_facts": facts, "authority_resource_scopes": [scope], "capability_catalog": catalog})
	subject := object.union(base_v2_input.subject, {"grants": [{"capability": "filesystem.read", "scopes": ["files.data"]}]})
	result := decision with input as object.union(base_v2_input, {"request": request, "subject": subject})
	result.decision == "BLOCK"
}

test_v2_resource_less_effect_explicitly_allowed if {
	contract_effect := {"effect_id": "ping", "capability": "system.ping", "resource_bindings": [], "max_resource_cardinality": null, "declared_reference_precision": "EXPLICIT"}
	contract := object.union(base_v2_input.request.tool_security_contract, {"effects": [contract_effect]})
	fact_effect := {"effect_id": "ping", "capability_id": "system.ping", "requires_resource": false, "adapter_id": "none", "adapter_api_version": "1", "declared_reference_precision": "EXPLICIT", "runtime_reference_precision": "EXPLICIT", "effective_reference_precision": "EXPLICIT", "max_resource_cardinality": null, "bindings": []}
	facts := object.union(base_v2_input.request.normalized_facts, {"effects": [fact_effect]})
	catalog := [{"id": "system.ping", "domain": "system", "verb": "ping", "destructive": false, "requires_resource": false, "allowed_resource_types": [], "lifecycle": "ACTIVE"}]
	request := object.union(base_v2_input.request, {"tool_security_contract": contract, "normalized_facts": facts, "capability_catalog": catalog})
	subject := object.union(base_v2_input.subject, {"grants": [{"capability": "system.ping", "scopes": []}]})
	result := decision with input as object.union(base_v2_input, {"request": request, "subject": subject})
	result.decision == "ALLOW"
}

test_v2_multi_effect_is_conjunctive if {
	second := object.union(base_v2_input.request.tool_security_contract.effects[0], {"effect_id": "second"})
	contract := object.union(base_v2_input.request.tool_security_contract, {"effects": array.concat(base_v2_input.request.tool_security_contract.effects, [second])})
	request := object.union(base_v2_input.request, {"tool_security_contract": contract})
	result := decision with input as object.union(base_v2_input, {"request": request})
	result.decision == "BLOCK"
}
