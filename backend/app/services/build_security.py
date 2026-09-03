from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.build_security import (
    BuildAssessment,
    BuildFinding,
    BuildScannerRun,
    BuildScanRun,
)
from scanners.contracts import (
    BuildAssessmentStatus,
    BuildTargetSnapshot,
    FindingState,
    NormalizedFinding,
    ScannerRunStatus,
    sanitize_scanner_metadata,
)


class BuildSecurityStateError(ValueError):
    pass


def create_build_scan(
    db: Session,
    *,
    target: BuildTargetSnapshot,
    requested_by: str | None,
) -> BuildScanRun:
    scan = BuildScanRun(
        target_type=target.target_type.value,
        display_name=target.display_name,
        source_locator=target.source_locator,
        source_revision=target.source_revision,
        source_fingerprint=target.source_fingerprint,
        linked_server_id=target.linked_server_id,
        status="PENDING",
        requested_by=requested_by,
    )
    db.add(scan)
    db.flush()
    return scan


def create_scanner_run(
    db: Session,
    *,
    build_scan_id: str,
    scanner_id: str,
    required: bool = True,
    scanner_version: str | None = None,
) -> BuildScannerRun:
    scanner_id = scanner_id.strip().lower()
    if not scanner_id:
        raise BuildSecurityStateError("scanner_id_required")
    scanner_run = BuildScannerRun(
        build_scan_id=build_scan_id,
        scanner_id=scanner_id,
        scanner_version=scanner_version,
        required=required,
        status=ScannerRunStatus.PENDING.value,
    )
    db.add(scanner_run)
    db.flush()
    return scanner_run


def persist_normalized_finding(
    db: Session,
    *,
    build_scan_id: str,
    scanner_run_id: str,
    finding: NormalizedFinding,
    state: FindingState = FindingState.NEW,
) -> BuildFinding:
    scanner_run = db.get(BuildScannerRun, scanner_run_id)
    if scanner_run is None or scanner_run.build_scan_id != build_scan_id:
        raise BuildSecurityStateError("scanner_run_scan_mismatch")
    if scanner_run.scanner_id != finding.scanner_id:
        raise BuildSecurityStateError("scanner_finding_identity_mismatch")

    existing = db.scalar(
        select(BuildFinding).where(
            BuildFinding.build_scan_id == build_scan_id,
            BuildFinding.fingerprint == finding.fingerprint,
        )
    )
    if existing is not None:
        return existing

    for value in (
        finding.line_start,
        finding.line_end,
        finding.column_start,
        finding.column_end,
    ):
        if value is not None and value < 1:
            raise BuildSecurityStateError("finding_location_must_be_positive")

    persisted = BuildFinding(
        build_scan_id=build_scan_id,
        scanner_run_id=scanner_run_id,
        scanner_id=finding.scanner_id,
        rule_id=finding.rule_id,
        category=finding.category,
        severity=finding.severity.value,
        confidence=finding.confidence.value,
        finding_state=state.value,
        fingerprint=finding.fingerprint,
        title=finding.title,
        description=finding.description,
        remediation=finding.remediation,
        file_path=finding.file_path,
        line_start=finding.line_start,
        line_end=finding.line_end,
        column_start=finding.column_start,
        column_end=finding.column_end,
        vulnerability_id=finding.vulnerability_id,
        package_name=finding.package_name,
        package_version=finding.package_version,
        fixed_version=finding.fixed_version,
        references=list(finding.references),
        safe_metadata=sanitize_scanner_metadata(finding.safe_metadata),
    )
    db.add(persisted)
    db.flush()
    return persisted


def mark_scanner_run_finished(
    db: Session,
    *,
    scanner_run: BuildScannerRun,
    status: ScannerRunStatus,
    finding_count: int,
    error_code: str | None = None,
) -> BuildScannerRun:
    if finding_count < 0:
        raise BuildSecurityStateError("finding_count_must_be_non_negative")
    if status == ScannerRunStatus.COMPLETED and error_code:
        raise BuildSecurityStateError("completed_scanner_run_cannot_have_error")
    if status != ScannerRunStatus.COMPLETED and finding_count:
        raise BuildSecurityStateError("incomplete_scanner_run_cannot_claim_findings")

    scanner_run.status = status.value
    scanner_run.finding_count = finding_count
    scanner_run.error_code = error_code
    scanner_run.completed_at = datetime.utcnow()
    db.flush()
    return scanner_run


def create_build_assessment(
    db: Session,
    *,
    build_scan_id: str,
    status: BuildAssessmentStatus,
    required_scanners_complete: bool,
    policy_version: str,
    reason_codes: Iterable[str] = (),
    summary: str | None = None,
) -> BuildAssessment:
    if status == BuildAssessmentStatus.PASS and not required_scanners_complete:
        raise BuildSecurityStateError("incomplete_required_scanners_cannot_pass")
    if db.scalar(
        select(BuildAssessment).where(BuildAssessment.build_scan_id == build_scan_id)
    ) is not None:
        raise BuildSecurityStateError("build_assessment_already_exists")

    severities = db.scalars(
        select(BuildFinding.severity).where(
            BuildFinding.build_scan_id == build_scan_id,
            BuildFinding.finding_state != FindingState.RESOLVED.value,
        )
    ).all()
    counts = Counter(severities)
    assessment = BuildAssessment(
        build_scan_id=build_scan_id,
        status=status.value,
        policy_version=policy_version,
        required_scanners_complete=required_scanners_complete,
        reason_codes=[str(code)[:128] for code in list(reason_codes)[:100]],
        summary=summary[:4000] if summary else None,
        critical_count=counts["CRITICAL"],
        high_count=counts["HIGH"],
        medium_count=counts["MEDIUM"],
        low_count=counts["LOW"],
        info_count=counts["INFO"],
    )
    db.add(assessment)
    db.flush()
    return assessment
