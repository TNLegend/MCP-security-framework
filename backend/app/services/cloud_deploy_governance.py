"""Build a bounded, read-only OPA Deploy input from verifiable scan records.

The Runtime OPA policy is authoritative for tools/call. This separate Deploy
context is advisory only: it never asserts effective AWS authorization or
enforces any MCP tool call. No raw IAM policy or cloud resource ARN is sent.
"""
from __future__ import annotations

from collections import Counter
import re

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.cloud_security import (
    CloudEnvironment, CloudEvidence, CloudFinding, CloudIAMComparison,
    CloudIAMMapping, CloudResource, CloudScan,
)
from app.models.mcp_server import MCPServer
from app.services.cloud_iam_mapping import digest, verify_approved_mapping
from app.services.published_configuration import PublishedConfigurationProvider

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REVIEW = ("OUTSIDE_MCP_MAPPING", "POTENTIAL_EXCESS",
           "POTENTIAL_MISSING", "EXPLICIT_DENY")
_ALLOWED = set(_REVIEW) | {"UNKNOWN"}
_MAX_COMPARISONS = 250


class DeployGovernanceError(ValueError):
    pass


def _untrusted_input(scan: CloudScan) -> dict:
    return {
        "schema_version": "deploy-iam-governance-v1",
        "scan_kind": scan.kind,
        "scan_status": scan.status,
        "provenance": {
            "signed_revision_verified": False,
            "admin_mapping_approved_verified": False,
            "mapping_digest_matches_scan": False,
            "account_and_endpoint_bound": False,
            "workload_iam_identity_resolved": False,
            "identity_policy_read_complete": False,
            "comparison_integrity_verified": False,
        },
        "summary": {
            "status_counts": {key: 0 for key in _REVIEW},
            "unknown_count": 0,
        },
    }


def build_deploy_iam_governance_input(db: Session, scan_id: str) -> dict:
    """Revalidate signed mapping, revision and persisted IAM evidence.

    If ANY required evidence is absent or unverifiable, return an input whose
    provenance flags remain false. OPA must then report EVIDENCE_INCOMPLETE.

    The internal SHA-256 checks detect accidental/corrupt record mismatches;
    they are not signatures on AWS results and do not attest IAM freshness.
    """
    scan = db.get(CloudScan, scan_id)
    if scan is None:
        raise DeployGovernanceError("DEPLOY_SCAN_NOT_FOUND")
    fail = _untrusted_input(scan)
    if (scan.kind != "IAM_MCP" or scan.status != "PARTIAL"
            or scan.completed_at is None or scan.error_code is not None):
        return fail

    resources = db.scalars(select(CloudResource).where(
        CloudResource.scan_id == scan_id).limit(3)).all()
    if len(resources) != 1 or resources[0].resource_type != "MCP_CLOUD_WORKLOAD":
        return fail
    metadata = resources[0].safe_attributes
    if not isinstance(metadata, dict):
        return fail

    mapping_id = metadata.get("approved_mapping_id")
    mapping = db.get(CloudIAMMapping, mapping_id) if isinstance(mapping_id, str) else None
    if mapping is None or mapping.environment_id != scan.environment_id:
        return fail
    env = db.get(CloudEnvironment, mapping.environment_id)
    server = db.get(MCPServer, mapping.mcp_server_id)
    if not env or not server or server.status != "active" or env.status != "CONNECTED":
        return fail

    try:
        snapshot = PublishedConfigurationProvider(db).load_active_snapshot()
        expected = verify_approved_mapping(mapping, snapshot, server.endpoint,
                                           env.account_id)
    except Exception:
        return fail

    approved_hash = mapping.approval_digest
    content_hash = snapshot.content_hash
    if not all(isinstance(v, str) and _SHA256.fullmatch(v)
               for v in (approved_hash, content_hash)):
        return fail
    if (scan.source_fingerprint != approved_hash
            or metadata.get("approved_mapping_digest") != approved_hash
            or metadata.get("signed_revision_hash") != content_hash
            or metadata.get("signed_revision") != snapshot.revision_number
            or not metadata.get("identity_verified")):
        return fail

    policy_digest = metadata.get("identity_policy_digest")
    if not isinstance(policy_digest, str) or not _SHA256.fullmatch(policy_digest):
        return fail

    rows = db.scalars(select(CloudIAMComparison).where(
        CloudIAMComparison.scan_id == scan_id).limit(_MAX_COMPARISONS + 1)).all()
    if len(rows) > _MAX_COMPARISONS:
        return fail
    if any(x.status not in _ALLOWED
           or x.signed_revision != snapshot.revision_number
           or x.policy_digest != policy_digest
           or x.effective_permission_status not in (
                "UNKNOWN", "DENIED_BY_EXPLICIT_IDENTITY_POLICY"
           )
           or not isinstance(x.role_arn, str)
           or not x.role_arn.startswith(
               "arn:aws:iam::" + str(env.account_id) + ":role/"
           )
           for x in rows):
        return fail
    if len({x.role_arn for x in rows}) != 1:
        return fail

    forward = [row for row in rows if row.tool_name is not None]
    reverse = [row for row in rows if row.tool_name is None]
    needed = Counter(
        (x["tool"], tuple([x["action"]] if x.get("action") else []),
         x.get("resource")) for x in expected
    )
    observed = Counter(
        (x.tool_name, tuple(x.expected_actions), x.expected_resource_arn)
        for x in forward
    )
    if needed != observed or any(x.expected_actions for x in reverse):
        return fail

    proofs = db.scalars(select(CloudEvidence).where(
        CloudEvidence.scan_id == scan_id).limit(_MAX_COMPARISONS + 5)).all()
    if len(proofs) != len(rows) + 2:
        return fail
    proof_by_rule = {e.rule_id: e for e in proofs
                     if e.rule_id in {"IAM_MCP_SIGNED_REVISION",
                                       "IAM_MCP_ADMIN_APPROVAL"}}
    if len(proof_by_rule) != 2:
        return fail
    revision_proof = proof_by_rule["IAM_MCP_SIGNED_REVISION"]
    approval_proof = proof_by_rule["IAM_MCP_ADMIN_APPROVAL"]
    if (revision_proof.outcome != "PASS"
            or revision_proof.safe_summary.get("signed_revision") != snapshot.revision_number
            or revision_proof.safe_summary.get("signed_revision_hash") != content_hash
            or revision_proof.evidence_sha256 != digest([snapshot.revision_number, content_hash])):
        return fail
    if (approval_proof.outcome != "PASS"
            or approval_proof.safe_summary.get("mapping_id") != mapping.id
            or approval_proof.safe_summary.get("approved_digest") != approved_hash
            or approval_proof.safe_summary.get("signed_revision_hash") != content_hash
            or approval_proof.evidence_sha256 != digest(approval_proof.safe_summary)):
        return fail

    forward_proof = Counter()
    reverse_proof = Counter()
    for item in proofs:
        if item.rule_id in proof_by_rule:
            continue
        summary = item.safe_summary
        if (not isinstance(summary, dict)
                or item.evidence_sha256 != digest(summary)
                or summary.get("identity_policy_digest") != policy_digest
                or summary.get("approved_mapping_digest") != approved_hash):
            return fail
        if summary.get("direction") == "IAM_POLICY_TO_APPROVED_MCP_NEEDS":
            reverse_proof[
                (summary.get("status"), summary.get("action"), summary.get("resource"))
            ] += 1
        else:
            forward_proof[
                (summary.get("tool"), summary.get("status"),
                 summary.get("action"), summary.get("resource"))
            ] += 1

    expected_forward_proof = Counter(
        (x.tool_name, x.status,
         x.expected_actions[0] if x.expected_actions else None,
         x.expected_resource_arn) for x in forward)
    expected_reverse_proof = Counter(
        (x.status, x.observed_actions[0] if x.observed_actions else None,
         x.expected_resource_arn) for x in reverse)
    if forward_proof != expected_forward_proof or reverse_proof != expected_reverse_proof:
        return fail

    observed_statuses = Counter(row.status for row in rows)
    issues = sum(observed_statuses[x] for x in _REVIEW)
    if (issues != scan.finding_count
            or observed_statuses["UNKNOWN"] != scan.unknown_checks):
        return fail
    findings = db.scalars(select(CloudFinding).where(
        CloudFinding.scan_id == scan_id).limit(_MAX_COMPARISONS + 1)).all()
    if (len(findings) != issues
            or Counter(x.result for x in findings) != Counter({
                kind: observed_statuses[kind] for kind in _REVIEW
                if observed_statuses[kind] > 0
            })):
        return fail

    outcome = _untrusted_input(scan)
    outcome["provenance"] = {key: True for key in outcome["provenance"]}
    outcome["summary"] = {
        "status_counts": {key: observed_statuses[key] for key in _REVIEW},
        "unknown_count": observed_statuses["UNKNOWN"],
    }
    return outcome
