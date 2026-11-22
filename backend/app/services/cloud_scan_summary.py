"""UX-19: execution, observed findings and coverage as three separate facts.

The aggregate ``CloudScan.status`` mixes execution with completeness. This
summary reads each fact from its own durable source so the UI never has to
infer one from another:

- execution: the scanner's own execution evidence (``PROWLER_EXECUTION``)
  when recorded, otherwise the scan status for a terminal failure or an
  in-progress run;
- findings: a GROUP BY over *every* persisted finding of the scan (not the
  capped detail page), so severity totals are scan-wide;
- coverage: observed resources and unresolved observations, with
  ``available = False`` when a run failed before collecting anything. Zero
  findings in that case means "not collected", never "clean".
"""
from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.cloud_security import CloudEvidence, CloudFinding, CloudScan, CloudScanEvent

TERMINAL_FAILURE_STATES = frozenset({"FAILED", "TIMED_OUT", "INTERRUPTED", "CANCELLED"})
TERMINAL_STATES = TERMINAL_FAILURE_STATES | {"COMPLETED", "PARTIAL"}
EXECUTION_EVIDENCE_RULES = ("PROWLER_EXECUTION",)


def scan_assessment_summary(db: Session, scan: CloudScan) -> dict:
    by_severity: dict[str, int] = {}
    for severity, count in db.execute(
        select(CloudFinding.severity, func.count(CloudFinding.id))
        .where(CloudFinding.scan_id == scan.id)
        .group_by(CloudFinding.severity)
    ).all():
        key = str(severity or "UNSPECIFIED").upper()
        by_severity[key] = by_severity.get(key, 0) + int(count or 0)
    total = sum(by_severity.values())

    execution_evidence = db.scalars(
        select(CloudEvidence)
        .where(CloudEvidence.scan_id == scan.id, CloudEvidence.rule_id.in_(EXECUTION_EVIDENCE_RULES))
        .order_by(CloudEvidence.checked_at.desc(), CloudEvidence.id.desc())
        .limit(1)
    ).first()
    if execution_evidence is not None:
        summary = execution_evidence.safe_summary or {}
        execution = {
            "state": str(summary.get("execution_status") or execution_evidence.outcome),
            "source": "SCANNER_EXECUTION_EVIDENCE",
            "scanner": summary.get("scanner"),
            "scanner_version": summary.get("version"),
            "records_returned": summary.get("records"),
        }
    elif scan.status in TERMINAL_FAILURE_STATES or scan.status not in TERMINAL_STATES:
        execution = {"state": scan.status, "source": "SCAN_STATUS"}
    else:
        execution = {"state": "NOT_RECORDED", "source": "NONE"}
    execution["error_code"] = scan.error_code

    unknown_service_reads = int(db.scalar(
        select(func.count(CloudEvidence.id)).where(
            CloudEvidence.scan_id == scan.id,
            CloudEvidence.rule_id.like("PROWLER_READ_%"),
            CloudEvidence.outcome == "UNKNOWN",
        )
    ) or 0)
    unassessed_services = int(db.scalar(
        select(func.count(CloudScanEvent.id)).where(
            CloudScanEvent.scan_id == scan.id,
            CloudScanEvent.message_code.like("PROWLER_UNASSESSED_%"),
        )
    ) or 0)
    in_progress = scan.status not in TERMINAL_STATES
    failed_without_collection = (
        scan.status in TERMINAL_FAILURE_STATES and not scan.resource_count and not total
    )
    coverage = {
        "available": not (in_progress or failed_without_collection),
        "reason": ("SCAN_NOT_FINISHED" if in_progress
                   else "SCAN_FAILED_BEFORE_COLLECTION" if failed_without_collection else None),
        "resources_observed": scan.resource_count,
        "unresolved_observations": scan.unknown_checks,
        "unknown_service_reads": unknown_service_reads,
        "unassessed_services": unassessed_services,
    }
    return {
        "schema": "cloud.scan_assessment_summary.v1",
        "execution": execution,
        "findings": {
            "total": total,
            "by_severity": by_severity,
            "population": "ALL_PERSISTED_FINDINGS_FOR_SCAN",
            "matches_scan_counter": total == scan.finding_count,
        },
        "coverage": coverage,
    }
