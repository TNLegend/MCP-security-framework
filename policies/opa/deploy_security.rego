package mcp.security.deploy

import rego.v1

# Deploy Security is a read-only governance signal. This policy NEVER grants
# cloud access and MUST NOT be used as a runtime tools/call allow/deny policy.
policy_revision := "opa-deploy-security-advisory-v1"

default input_object := {}
input_object := value if {
    value := input
    is_object(value)
}

default trusted := false
trusted if {
    object.get(input_object, "schema_version", "") == "deploy-iam-governance-v1"
    object.get(input_object, "scan_kind", "") == "IAM_MCP"
    object.get(input_object, "scan_status", "") == "PARTIAL"
    proof := object.get(input_object, "provenance", {})
    is_object(proof)
    object.get(proof, "signed_revision_verified", false) == true
    object.get(proof, "admin_mapping_approved_verified", false) == true
    object.get(proof, "mapping_digest_matches_scan", false) == true
    object.get(proof, "account_and_endpoint_bound", false) == true
    object.get(proof, "workload_iam_identity_resolved", false) == true
    object.get(proof, "identity_policy_read_complete", false) == true
    object.get(proof, "comparison_integrity_verified", false) == true
    valid_summary
}

required_statuses := {
    "OUTSIDE_MCP_MAPPING",
    "POTENTIAL_EXCESS",
    "POTENTIAL_MISSING",
    "EXPLICIT_DENY",
}

valid_summary if {
    candidate := object.get(input_object, "summary", null)
    is_object(candidate)
    counts := object.get(candidate, "status_counts", null)
    is_object(counts)
    every status in required_statuses {
        value := object.get(counts, status, -1)
        is_number(value)
        value >= 0
        floor(value) == value
    }
    unknown := object.get(candidate, "unknown_count", -1)
    is_number(unknown)
    unknown >= 0
    floor(unknown) == unknown
}

default summary := {}
summary := value if {
    value := object.get(input_object, "summary", {})
    is_object(value)
}

problem_statuses := {
    "OUTSIDE_MCP_MAPPING",
    "POTENTIAL_EXCESS",
    "POTENTIAL_MISSING",
    "EXPLICIT_DENY",
}

has_review_finding if {
    counts := object.get(summary, "status_counts", {})
    is_object(counts)
    some status in problem_statuses
    count := object.get(counts, status, 0)
    is_number(count)
    count > 0
}

unknown_count := value if {
    value := object.get(summary, "unknown_count", 0)
    is_number(value)
    value >= 0
}

default unknown_count := 0

default decision := {
    "classification": "EVIDENCE_INCOMPLETE",
    "rule_ids": ["DEPLOY_EVIDENCE_NOT_VERIFIED"],
    "obligations": ["REVIEW_EVIDENCE", "LOG"],
    "explanation": "Signed approval, source binding or IAM evidence could not be fully verified.",
    "policy_revision": "opa-deploy-security-advisory-v1",
    "runtime_enforcement": false,
    "effective_aws_authorization_proven": false,
}

decision := {
    "classification": "REVIEW_REQUIRED",
    "rule_ids": ["DEPLOY_IAM_APPROVED_NEEDS_DIFFER_FROM_IDENTITY_POLICY"],
    "obligations": ["ADMIN_REVIEW", "LOG"],
    "explanation": "A verified read-only IAM comparison contains differences requiring administrator review; no effective-access verdict is asserted.",
    "policy_revision": "opa-deploy-security-advisory-v1",
    "runtime_enforcement": false,
    "effective_aws_authorization_proven": false,
} if {
    trusted
    has_review_finding
}

decision := {
    "classification": "EVIDENCE_INCOMPLETE",
    "rule_ids": ["DEPLOY_IAM_UNKNOWN_OBSERVATIONS"],
    "obligations": ["REVIEW_EVIDENCE", "LOG"],
    "explanation": "The signed comparison is verified, but unresolved IAM observations prevent a complete review.",
    "policy_revision": "opa-deploy-security-advisory-v1",
    "runtime_enforcement": false,
    "effective_aws_authorization_proven": false,
} if {
    trusted
    not has_review_finding
    unknown_count > 0
}

decision := {
    "classification": "OBSERVATION_ONLY",
    "rule_ids": ["DEPLOY_IAM_NO_REVIEW_FINDING_OBSERVED"],
    "obligations": ["LOG"],
    "explanation": "No mapped identity-policy discrepancy was observed; this is not an effective AWS access or least-privilege certification.",
    "policy_revision": "opa-deploy-security-advisory-v1",
    "runtime_enforcement": false,
    "effective_aws_authorization_proven": false,
} if {
    trusted
    not has_review_finding
    unknown_count == 0
}
