"""Verified, bounded governance summaries for IaC and Prowler scans.

Never assert that scanner results are a complete cloud audit. Older records
with insufficient hash provenance abstain. No raw scan document enters OPA.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta
import hashlib
import json
import re

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.cloud_security import (
    CloudEnvironment, CloudEvidence, CloudFinding, CloudResource, CloudScan,
)

_SHA = re.compile(r"^[0-9a-f]{64}$")
_LIMIT = 2000
_MAX_AGE = timedelta(days=7)


def _hash(value: object) -> str:
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()).hexdigest()


def _fresh(scan: CloudScan) -> bool:
    now = datetime.utcnow()
    end = scan.completed_at
    return bool(end and scan.started_at and
                scan.created_at <= scan.started_at <= end <= now + timedelta(minutes=5)
                and now - end <= _MAX_AGE)


def _unverified(scan: CloudScan) -> dict:
    return {
        "schema_version": "deploy-cloud-governance-v1",
        "scan_kind": scan.kind,
        "scan_status": scan.status,
        "provenance": {
            "scan_completed": False,
            "scanner_execution_verified": False,
            "findings_integrity_verified": False,
            "source_fingerprint_verified": False,
            "coverage_account_verified": False,
            "freshness_verified": False,
        },
        "summary": {"finding_count": 0, "unknown_count": 0},
    }


def build_deploy_cloud_governance_input(db: Session, scan_id: str) -> dict:
    scan = db.get(CloudScan, scan_id)
    if scan is None:
        raise ValueError("DEPLOY_SCAN_NOT_FOUND")
    result = _unverified(scan)
    if scan.kind not in ("IAC_CONFIG", "AWS_ADVANCED") or (
        scan.status not in ("COMPLETED", "PARTIAL") or scan.error_code is not None
        or not _fresh(scan)
        or scan.finding_count < 0 or scan.unknown_checks < 0
    ):
        return result
    evidence = db.scalars(select(CloudEvidence).where(
        CloudEvidence.scan_id == scan_id).limit(_LIMIT + 1)).all()
    findings = db.scalars(select(CloudFinding).where(
        CloudFinding.scan_id == scan_id).limit(_LIMIT + 1)).all()
    resources = db.scalars(select(CloudResource).where(
        CloudResource.scan_id == scan_id).limit(_LIMIT + 1)).all()
    if (len(evidence) > _LIMIT or len(findings) > _LIMIT
            or len(resources) > _LIMIT or len(findings) != scan.finding_count
            or len(resources) != scan.resource_count):
        return result
    resources_by_id = {r.id: r for r in resources}
    if len(resources_by_id) != len(resources):
        return result
    try:
        if scan.kind == "IAC_CONFIG":
            valid = _verify_iac(scan, resources, evidence, findings, resources_by_id)
        else:
            valid = _verify_prowler(db, scan, resources, evidence, findings, resources_by_id)
    except (ValueError, KeyError, TypeError, AttributeError):
        return result
    if not valid:
        return result
    result["provenance"] = {key: True for key in result["provenance"]}
    result["summary"] = {
        "finding_count": len(findings),
        "unknown_count": scan.unknown_checks,
    }
    return result


def _verify_iac(scan, resources, evidence, findings, resource_by_id) -> bool:
    source = scan.source_fingerprint
    if (scan.environment_id is not None or not isinstance(source, str)
            or not _SHA.fullmatch(source)
            or scan.source_file_count != len(resources)):
        return False
    file_resources = {}
    for r in resources:
        if (r.resource_type != "IAC_FILE" or
                r.safe_attributes != {"source_fingerprint": source} or
                not isinstance(r.display_name, str) or len(r.display_name) > 512 or
                r.resource_arn != "iac://" + source + "/" + _hash(r.display_name) or
                r.display_name in file_resources):
            return False
        file_resources[r.display_name] = r
    status_proofs = {}
    failing = set()
    minimum_unknown = 0
    for item in evidence:
        summary = item.safe_summary
        if not isinstance(summary, dict) or item.resource_id not in (None, *resource_by_id):
            return False
        if item.rule_id in ("IAC_CHECKOV_STATUS", "IAC_TRIVY_STATUS"):
            tool = item.rule_id.split("_")[1].lower()
            if tool in status_proofs or item.resource_id is not None:
                return False
            if (summary.get("scanner") != tool or
                    summary.get("source_fingerprint") != source or
                    not isinstance(summary.get("finding_count"), int)
                    or summary["finding_count"] < 0 or
                    not isinstance(summary.get("status"), str)):
                return False
            expected_hash = _hash({
                "source": source, "scanner": tool,
                "version": summary.get("version"),
                "status": summary["status"],
                "count": summary["finding_count"]
            })
            if item.evidence_sha256 != expected_hash:
                return False
            outcome = "PASS" if summary["status"] == "COMPLETED" else "UNKNOWN"
            if item.outcome != outcome:
                return False
            if outcome == "UNKNOWN":
                minimum_unknown += 1
            if outcome == "PASS":
                from app.core.runtime_paths import CHECKOV_VERSION, TRIVY_VERSION
                if summary.get("version") != {
                    "checkov": CHECKOV_VERSION, "trivy": TRIVY_VERSION
                }[tool]:
                    return False
            status_proofs[tool] = summary
        else:
            # The newer scanner evidence includes the rule and resource hash;
            # old records cannot be independently re-hashed and abstain.
            tool = summary.get("scanner")
            target = file_resources.get(summary.get("file"))
            if (tool not in ("checkov", "trivy") or
                    not target or item.resource_id != target.id or
                    summary.get("source_fingerprint") != source or
                    summary.get("rule") != item.rule_id or
                    not isinstance(summary.get("line"), int) or
                    summary["line"] < 0 or
                    not isinstance(summary.get("resource_hash"), str) or
                    not _SHA.fullmatch(summary["resource_hash"])):
                return False
            reference = {
                "source": source, "scanner": tool, "rule": item.rule_id,
                "file": summary["file"], "resource_hash": summary["resource_hash"],
                "line": summary["line"],
            }
            if item.outcome != "FAIL" or item.evidence_sha256 != _hash(reference):
                return False
            failing.add((item.resource_id, item.rule_id, tool,
                         summary["file"], summary["resource_hash"]))
    if set(status_proofs) != {"checkov", "trivy"}:
        return False
    if scan.unknown_checks < minimum_unknown:
        return False
    if scan.status == "COMPLETED" and minimum_unknown > 0:
        return False
    for f in findings:
        if (f.result != "FAIL" or f.resource_id not in resource_by_id
                or not any(
                    f.resource_id == rid and f.rule_id == rule
                    and f.fingerprint == _hash((tool, rule, file, resource_hash))
                    for rid, rule, tool, file, resource_hash in failing
                )):
            return False
    return True


def _verify_prowler(db, scan, resources, evidence, findings, resource_by_id):
    env = db.get(CloudEnvironment, scan.environment_id) if scan.environment_id else None
    if not env or env.status != "CONNECTED" or not env.account_id or not env.role_arn:
        return False
    resource_hashes = {}
    for r in resources:
        attrs = r.safe_attributes
        if (r.environment_id != env.id or r.resource_type != "AWS_RESOURCE" or
                not isinstance(attrs, dict) or attrs.get("scanner") != "prowler" or
                not isinstance(attrs.get("resource_sha256"), str) or
                not _SHA.fullmatch(attrs["resource_sha256"]) or
                r.resource_arn != "prowler://" + attrs["resource_sha256"]):
            return False
        resource_hashes[r.id] = attrs["resource_sha256"]
    from app.core.runtime_paths import PROWLER_VERSION
    from app.services.cloud_prowler_security import SERVICES
    execution = 0
    identity_binding = 0
    failing = set()
    services_observed = set()
    normalized_records = 0
    unknown_floor = 0
    observed_scanner_checks = 0
    for e in evidence:
        x = e.safe_summary
        if not isinstance(x, dict):
            return False
        if e.rule_id == "PROWLER_IDENTITY_BOUND":
            identity_binding += 1
            expected = {
                "scanner": "prowler",
                "account_sha256": _hash(env.account_id),
                "audit_role_sha256": _hash(env.role_arn),
                "regions_sha256": _hash(sorted(env.regions)),
            }
            if (e.resource_id is not None or e.outcome != "PASS"
                    or x != expected or e.evidence_sha256 != _hash(expected)):
                return False
        elif e.rule_id == "PROWLER_EXECUTION":
            execution += 1
            if (e.resource_id is not None or
                    x.get("scanner") != "prowler" or
                    x.get("version") != PROWLER_VERSION or
                    not isinstance(x.get("records"), int) or
                    x["records"] < 0 or
                    x.get("execution_status") not in ("COMPLETED", "PARTIAL") or
                    e.evidence_sha256 != _hash({
                        "scanner": "prowler", "version": x.get("version"),
                        "status": x["execution_status"],
                    }) or e.outcome != (
                        "PASS" if x["execution_status"] == "COMPLETED" else "UNKNOWN"
                    )):
                return False
            if e.outcome == "UNKNOWN":
                unknown_floor += 1
        elif e.rule_id.startswith("PROWLER_READ_"):
            observed_scanner_checks += 1
            if (e.resource_id is not None or e.outcome != "UNKNOWN" or
                    e.evidence_sha256 != _hash(x) or
                    x.get("scanner") != "prowler" or
                    x.get("coverage") != "UNKNOWN"):
                return False
            unknown_floor += 1
        else:
            normalized_records += 1
            services_observed.add(x.get("service"))
            if (e.resource_id not in resource_hashes or
                    x.get("version") != PROWLER_VERSION or
                    x.get("scanner") != "prowler" or
                    x.get("resource_hash") != resource_hashes[e.resource_id] or
                    x.get("rule") != e.rule_id or
                    x.get("status") not in ("PASS", "FAIL", "UNKNOWN")
                    or e.outcome != x["status"] or
                    e.evidence_sha256 != _hash(x)):
                return False
            if e.outcome == "FAIL":
                failing.add((e.resource_id, e.rule_id))
            if e.outcome == "UNKNOWN":
                unknown_floor += 1
    exec_item = next((e for e in evidence if e.rule_id == "PROWLER_EXECUTION"), None)
    if (execution != 1 or identity_binding != 1
            or observed_scanner_checks > len(SERVICES) or
            not exec_item or exec_item.safe_summary["records"] != normalized_records):
        return False
    unknown_floor += len(set(SERVICES) - services_observed)
    if scan.unknown_checks < unknown_floor:
        return False
    if scan.status == "COMPLETED" and scan.unknown_checks > 0:
        return False
    for f in findings:
        if (f.result != "FAIL" or f.resource_id not in resource_by_id
                or (f.resource_id, f.rule_id) not in failing
                or f.fingerprint != _hash({
                    "rule": f.rule_id,
                    "resource": resource_hashes[f.resource_id],
                })):
            return False
    return True
