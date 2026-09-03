package mcp.security.runtime

import rego.v1

build_context(mode, status, completed_at, complete) := {
	"mode": mode,
	"max_evidence_age_hours": 48,
	"evidence_present": true,
	"scan_id": "11111111-1111-1111-1111-111111111111",
	"source_fingerprint": v2_hash,
	"source_revision": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	"assessment_status": status,
	"assessment_policy_version": "build-policy-v1",
	"required_scanners_complete": complete,
	"completed_at": completed_at,
}

test_build_gate_disabled_allows_without_evidence if {
	context := {
		"mode": "DISABLED",
		"max_evidence_age_hours": 168,
		"evidence_present": false,
		"scan_id": null,
		"source_fingerprint": null,
		"source_revision": null,
		"assessment_status": null,
		"assessment_policy_version": null,
		"required_scanners_complete": false,
		"completed_at": null,
	}
	result := decision with input as object.union(base_v2_input, {"build_security": context})
	result.decision == "ALLOW"
}

test_build_gate_require_pass_missing_evidence_blocks if {
	context := {
		"mode": "REQUIRE_PASS",
		"max_evidence_age_hours": 48,
		"evidence_present": false,
		"scan_id": null,
		"source_fingerprint": null,
		"source_revision": null,
		"assessment_status": null,
		"assessment_policy_version": null,
		"required_scanners_complete": false,
		"completed_at": null,
	}
	result := decision with input as object.union(base_v2_input, {"build_security": context})
	result.decision == "BLOCK"
	result.rule_id == "deny_build_security_evidence_missing"
}

test_build_gate_require_pass_fresh_pass_allows if {
	context := build_context("REQUIRE_PASS", "PASS", "2026-01-01T12:00:00Z", true)
	result := decision with input as object.union(base_v2_input, {"build_security": context}) with time.now_ns as 1767312000000000000
	result.decision == "ALLOW"
}

test_build_gate_require_pass_warn_blocks if {
	context := build_context("REQUIRE_PASS", "WARN", "2026-01-01T12:00:00Z", true)
	result := decision with input as object.union(base_v2_input, {"build_security": context}) with time.now_ns as 1767312000000000000
	result.decision == "BLOCK"
	result.rule_id == "deny_build_security_assessment"
}

test_build_gate_allow_warn_accepts_warn if {
	context := build_context("ALLOW_WARN", "WARN", "2026-01-01T12:00:00Z", true)
	result := decision with input as object.union(base_v2_input, {"build_security": context}) with time.now_ns as 1767312000000000000
	result.decision == "ALLOW"
}

test_build_gate_allow_warn_blocks_block_assessment if {
	context := build_context("ALLOW_WARN", "BLOCK", "2026-01-01T12:00:00Z", true)
	result := decision with input as object.union(base_v2_input, {"build_security": context}) with time.now_ns as 1767312000000000000
	result.decision == "BLOCK"
	result.rule_id == "deny_build_security_assessment"
}

test_build_gate_allow_warn_blocks_error_assessment if {
	context := build_context("ALLOW_WARN", "ERROR", "2026-01-01T12:00:00Z", false)
	result := decision with input as object.union(base_v2_input, {"build_security": context}) with time.now_ns as 1767312000000000000
	result.decision == "BLOCK"
	result.rule_id == "deny_build_security_scanner_incomplete"
}

test_build_gate_required_scanner_incomplete_blocks if {
	context := build_context("REQUIRE_PASS", "PASS", "2026-01-01T12:00:00Z", false)
	result := decision with input as object.union(base_v2_input, {"build_security": context}) with time.now_ns as 1767312000000000000
	result.decision == "BLOCK"
	result.rule_id == "deny_build_security_scanner_incomplete"
}

test_build_gate_stale_evidence_blocks if {
	context := object.union(
		build_context("REQUIRE_PASS", "PASS", "2025-12-01T00:00:00Z", true),
		{"max_evidence_age_hours": 24},
	)
	result := decision with input as object.union(base_v2_input, {"build_security": context}) with time.now_ns as 1767312000000000000
	result.decision == "BLOCK"
	result.rule_id == "deny_build_security_evidence_stale"
}

test_build_gate_future_evidence_blocks if {
	context := build_context("REQUIRE_PASS", "PASS", "2026-01-03T00:00:00Z", true)
	result := decision with input as object.union(base_v2_input, {"build_security": context}) with time.now_ns as 1767312000000000000
	result.decision == "BLOCK"
	result.rule_id == "deny_build_security_evidence_stale"
}

test_build_gate_invalid_timestamp_fails_closed if {
	context := build_context("REQUIRE_PASS", "PASS", "not-a-time", true)
	result := decision with input as object.union(base_v2_input, {"build_security": context})
	result.decision == "BLOCK"
	result.rule_id == "deny_build_security_evidence_invalid"
}
