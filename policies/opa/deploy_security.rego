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

# Non-sensitive, enumerated diagnostic codes explain exactly which
# verification gate did not pass. They are explanations, not authorization.
iam_required_provenance_fields := {
    "signed_revision_verified",
    "admin_mapping_approved_verified",
    "mapping_digest_matches_scan",
    "account_and_endpoint_bound",
    "workload_iam_identity_resolved",
    "identity_policy_read_complete",
    "comparison_integrity_verified",
}

iam_failed_checks contains code if {
    some code in iam_required_provenance_fields
    proof := object.get(input_object, "provenance", {})
    object.get(proof, code, false) != true
}
iam_failed_checks contains "SCAN_KIND_OR_STATUS_UNSUPPORTED" if {
    not object.get(input_object, "scan_kind", "") == "IAM_MCP"
}
iam_failed_checks contains "SCAN_KIND_OR_STATUS_UNSUPPORTED" if {
    not object.get(input_object, "scan_status", "") == "PARTIAL"
}
iam_failed_checks contains "SUMMARY_INVALID" if {
    not valid_summary
}

cloud_failed_checks contains code if {
    some code in cloud_provenance_fields
    proof := object.get(input_object, "provenance", {})
    object.get(proof, code, false) != true
}
cloud_failed_checks contains "SCAN_KIND_OR_STATUS_UNSUPPORTED" if {
    not object.get(input_object, "scan_kind", "") in {"IAC_CONFIG", "AWS_ADVANCED"}
}
cloud_failed_checks contains "SCAN_KIND_OR_STATUS_UNSUPPORTED" if {
    not object.get(input_object, "scan_status", "") in {"COMPLETED", "PARTIAL"}
}
cloud_failed_checks contains "SUMMARY_INVALID" if {
    not cloud_summary_valid
}
cloud_summary_valid if {
    candidate := object.get(input_object, "summary", null)
    is_object(candidate)
    findings := object.get(candidate, "finding_count", -1)
    unknown := object.get(candidate, "unknown_count", -1)
    is_number(findings)
    floor(findings) == findings
    findings >= 0
    is_number(unknown)
    floor(unknown) == unknown
    unknown >= 0
}

default failed_checks := ["EVIDENCE_SCHEMA_UNRECOGNIZED"]
failed_checks := sort([code | some code in iam_failed_checks]) if {
    object.get(input_object, "schema_version", "") == "deploy-iam-governance-v1"
}
failed_checks := sort([code | some code in cloud_failed_checks]) if {
    object.get(input_object, "schema_version", "") == "deploy-cloud-governance-v1"
}

default decision := {
    "classification": "EVIDENCE_INCOMPLETE",
    "rule_ids": ["DEPLOY_EVIDENCE_NOT_VERIFIED"],
    "obligations": ["REVIEW_EVIDENCE", "LOG"],
    "explanation": "Signed approval, source binding or IAM evidence could not be fully verified.",
    "policy_revision": "opa-deploy-security-advisory-v1",
    "runtime_enforcement": false,
    "effective_aws_authorization_proven": false,
    "failed_checks": ["EVIDENCE_SCHEMA_UNRECOGNIZED"],
}

# Dynamic diagnostics are emitted through an ordinary rule; Rego default
# objects cannot reference variables. This changes no review classification.
decision := {
    "classification": "EVIDENCE_INCOMPLETE",
    "rule_ids": ["DEPLOY_EVIDENCE_NOT_VERIFIED"],
    "obligations": ["REVIEW_EVIDENCE", "LOG"],
    "explanation": "Signed approval, source binding or scanner evidence could not be fully verified.",
    "policy_revision": "opa-deploy-security-advisory-v1",
    "runtime_enforcement": false,
    "effective_aws_authorization_proven": false,
    "failed_checks": failed_checks,
} if {
    not trusted
    not cloud_trusted
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
    "failed_checks": ["UNRESOLVED_IAM_OBSERVATIONS"],
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


# Cloud scanners are independent of signed MCP contracts. Their evidence is
# validated by a separate provenance builder with strict scan freshness.
cloud_provenance_fields := {
    "scan_completed",
    "scanner_execution_verified",
    "findings_integrity_verified",
    "source_fingerprint_verified",
    "coverage_account_verified",
    "freshness_verified",
}

default cloud_trusted := false
cloud_trusted if {
    object.get(input_object, "schema_version", "") == "deploy-cloud-governance-v1"
    object.get(input_object, "scan_kind", "") in {"IAC_CONFIG", "AWS_ADVANCED"}
    object.get(input_object, "scan_status", "") in {"COMPLETED", "PARTIAL"}
    proof := object.get(input_object, "provenance", {})
    is_object(proof)
    every required in cloud_provenance_fields {
        object.get(proof, required, false) == true
    }
    numbers := object.get(input_object, "summary", {})
    is_object(numbers)
    findings := object.get(numbers, "finding_count", -1)
    unknown := object.get(numbers, "unknown_count", -1)
    is_number(findings)
    floor(findings) == findings
    findings >= 0
    is_number(unknown)
    floor(unknown) == unknown
    unknown >= 0
}

cloud_findings := value if {
    value := object.get(summary, "finding_count", 0)
    is_number(value)
}

default cloud_findings := 0

decision := {
    "classification": "REVIEW_REQUIRED",
    "rule_ids": ["DEPLOY_CLOUD_SCANNER_FINDINGS_REQUIRE_REVIEW"],
    "obligations": ["ADMIN_REVIEW", "LOG"],
    "explanation": "Verified scanner observations contain findings. They are review signals, not proven exploitable vulnerabilities or Runtime enforcement.",
    "policy_revision": "opa-deploy-security-advisory-v1",
    "runtime_enforcement": false,
    "effective_aws_authorization_proven": false,
} if {
    cloud_trusted
    cloud_findings > 0
}

decision := {
    "classification": "EVIDENCE_INCOMPLETE",
    "rule_ids": ["DEPLOY_CLOUD_SCANNER_COVERAGE_UNRESOLVED"],
    "failed_checks": ["UNRESOLVED_CLOUD_CHECKS"],
    "obligations": ["REVIEW_EVIDENCE", "LOG"],
    "explanation": "Scanner evidence is internally verified, but some checks or environments are unassessed.",
    "policy_revision": "opa-deploy-security-advisory-v1",
    "runtime_enforcement": false,
    "effective_aws_authorization_proven": false,
} if {
    cloud_trusted
    cloud_findings == 0
    unknown_count > 0
}

decision := {
    "classification": "OBSERVATION_ONLY",
    "rule_ids": ["DEPLOY_CLOUD_NO_SCANNER_FINDINGS_OBSERVED"],
    "obligations": ["LOG"],
    "explanation": "No findings observed in covered scanner checks; this does not certify cloud security or complete audit coverage.",
    "policy_revision": "opa-deploy-security-advisory-v1",
    "runtime_enforcement": false,
    "effective_aws_authorization_proven": false,
} if {
    cloud_trusted
    cloud_findings == 0
    unknown_count == 0
}
