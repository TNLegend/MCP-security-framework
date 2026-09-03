from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Sequence

from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from app.models.build_security import BuildFinding, BuildScanRun
from app.services.build_security import (
    create_build_assessment,
    create_build_scan,
    create_scanner_run,
    mark_scanner_run_finished,
    persist_normalized_finding,
)
from scanners.assessment import (
    BUILD_ASSESSMENT_POLICY_VERSION,
    AssessmentInput,
    active_severities_from_values,
    decide_build_assessment,
)
from scanners.base import BuildScanner
from scanners.contracts import (
    FindingConfidence,
    FindingSeverity,
    FindingState,
    NormalizedFinding,
    ScannerExecutionResult,
    ScannerRunStatus,
    ValidatedWorkspace,
)
from scanners.gitleaks import GitleaksScanner
from scanners.semgrep import SemgrepScanner
from scanners.trivy import TrivyScanner


@dataclass(frozen=True, slots=True)
class BuildScannerRegistration:
    scanner: BuildScanner
    required: bool = True


def default_build_scanners() -> tuple[BuildScannerRegistration, ...]:
    return (
        BuildScannerRegistration(SemgrepScanner(), required=True),
        BuildScannerRegistration(GitleaksScanner(), required=True),
        BuildScannerRegistration(TrivyScanner(), required=True),
    )


def _logical_target_predicate(scan: BuildScanRun):
    if scan.linked_server_id is not None:
        return BuildScanRun.linked_server_id == scan.linked_server_id
    return and_(
        BuildScanRun.linked_server_id.is_(None),
        BuildScanRun.target_type == scan.target_type,
        BuildScanRun.source_locator == scan.source_locator,
    )


def _previous_completed_scan(
    db: Session,
    *,
    current_scan: BuildScanRun,
) -> BuildScanRun | None:
    return db.scalar(
        select(BuildScanRun)
        .where(
            BuildScanRun.id != current_scan.id,
            BuildScanRun.status == "COMPLETED",
            _logical_target_predicate(current_scan),
        )
        .order_by(BuildScanRun.created_at.desc(), BuildScanRun.id.desc())
        .limit(1)
    )


def _previous_active_findings(
    db: Session,
    *,
    previous_scan_id: str | None,
    scanner_id: str,
) -> dict[str, BuildFinding]:
    if previous_scan_id is None:
        return {}
    rows = db.scalars(
        select(BuildFinding).where(
            BuildFinding.build_scan_id == previous_scan_id,
            BuildFinding.scanner_id == scanner_id,
            BuildFinding.finding_state != FindingState.RESOLVED.value,
        )
    ).all()
    return {row.fingerprint: row for row in rows}


def _historical_fingerprints(
    db: Session,
    *,
    current_scan: BuildScanRun,
    scanner_id: str,
    previous_scan_id: str | None,
) -> set[str]:
    excluded = [current_scan.id]
    if previous_scan_id is not None:
        excluded.append(previous_scan_id)
    return set(
        db.scalars(
            select(BuildFinding.fingerprint)
            .join(BuildScanRun, BuildScanRun.id == BuildFinding.build_scan_id)
            .where(
                BuildFinding.scanner_id == scanner_id,
                BuildFinding.finding_state != FindingState.RESOLVED.value,
                BuildScanRun.status == "COMPLETED",
                _logical_target_predicate(current_scan),
                BuildScanRun.id.not_in(excluded),
            )
        ).all()
    )


def _finding_from_persisted(row: BuildFinding) -> NormalizedFinding:
    return NormalizedFinding(
        scanner_id=row.scanner_id,
        rule_id=row.rule_id,
        category=row.category,
        severity=FindingSeverity(row.severity),
        confidence=FindingConfidence(row.confidence),
        title=row.title,
        fingerprint=row.fingerprint,
        file_path=row.file_path,
        line_start=row.line_start,
        line_end=row.line_end,
        column_start=row.column_start,
        column_end=row.column_end,
        description=row.description,
        remediation=row.remediation,
        vulnerability_id=row.vulnerability_id,
        package_name=row.package_name,
        package_version=row.package_version,
        fixed_version=row.fixed_version,
        references=tuple(row.references or ()),
        safe_metadata=dict(row.safe_metadata or {}),
    )


def _persist_completed_scanner_findings(
    db: Session,
    *,
    current_scan: BuildScanRun,
    scanner_run_id: str,
    scanner_id: str,
    findings: Sequence[NormalizedFinding],
    previous_scan_id: str | None,
) -> int:
    previous = _previous_active_findings(
        db,
        previous_scan_id=previous_scan_id,
        scanner_id=scanner_id,
    )
    historical = _historical_fingerprints(
        db,
        current_scan=current_scan,
        scanner_id=scanner_id,
        previous_scan_id=previous_scan_id,
    )

    current_fingerprints: set[str] = set()
    for finding in findings:
        if finding.scanner_id != scanner_id:
            raise ValueError("scanner_finding_identity_mismatch")
        if finding.fingerprint in current_fingerprints:
            continue
        if finding.fingerprint in previous:
            state = FindingState.UNCHANGED
        elif finding.fingerprint in historical:
            state = FindingState.REGRESSED
        else:
            state = FindingState.NEW
        persist_normalized_finding(
            db,
            build_scan_id=current_scan.id,
            scanner_run_id=scanner_run_id,
            finding=finding,
            state=state,
        )
        current_fingerprints.add(finding.fingerprint)

    for fingerprint, old in previous.items():
        if fingerprint in current_fingerprints:
            continue
        persist_normalized_finding(
            db,
            build_scan_id=current_scan.id,
            scanner_run_id=scanner_run_id,
            finding=_finding_from_persisted(old),
            state=FindingState.RESOLVED,
        )

    return len(current_fingerprints)


def run_build_security_scan(
    db: Session,
    *,
    workspace: ValidatedWorkspace,
    requested_by: str | None,
    scanners: Sequence[BuildScannerRegistration] | None = None,
    scanner_timeout_seconds: int = 300,
    max_scanner_output_bytes: int = 10 * 1024 * 1024,
) -> BuildScanRun:
    if not workspace.target.source_fingerprint:
        raise ValueError("build_source_fingerprint_required")
    if scanner_timeout_seconds < 1:
        raise ValueError("scanner_timeout_must_be_positive")
    if max_scanner_output_bytes < 1024:
        raise ValueError("scanner_output_limit_too_small")

    registrations = tuple(scanners or default_build_scanners())
    if not registrations:
        raise ValueError("at_least_one_build_scanner_required")
    scanner_ids = [registration.scanner.scanner_id.strip().lower() for registration in registrations]
    if any(not scanner_id for scanner_id in scanner_ids):
        raise ValueError("scanner_id_required")
    if len(set(scanner_ids)) != len(scanner_ids):
        raise ValueError("duplicate_build_scanner_id")
    if not any(registration.required for registration in registrations):
        raise ValueError("at_least_one_required_build_scanner")

    scan = create_build_scan(
        db,
        target=workspace.target,
        requested_by=requested_by,
    )
    scan.status = "RUNNING"
    scan.started_at = datetime.utcnow()
    db.flush()

    previous_scan = _previous_completed_scan(db, current_scan=scan)
    previous_scan_id = previous_scan.id if previous_scan is not None else None
    required_statuses: list[ScannerRunStatus] = []

    from scanners.contracts import ScannerContext

    context = ScannerContext(
        scan_id=scan.id,
        timeout_seconds=scanner_timeout_seconds,
        max_output_bytes=max_scanner_output_bytes,
    )

    for registration, scanner_id in zip(registrations, scanner_ids, strict=True):
        scanner_run = create_scanner_run(
            db,
            build_scan_id=scan.id,
            scanner_id=scanner_id,
            required=registration.required,
        )
        scanner_run.status = ScannerRunStatus.RUNNING.value
        scanner_run.started_at = datetime.utcnow()
        db.flush()

        try:
            result = registration.scanner.scan(workspace, context)
        except Exception:
            result = ScannerExecutionResult(
                scanner_id=scanner_id,
                status=ScannerRunStatus.FAILED,
                error_code="scanner_exception",
            )

        if result.scanner_id.strip().lower() != scanner_id:
            result = ScannerExecutionResult(
                scanner_id=scanner_id,
                status=ScannerRunStatus.FAILED,
                scanner_version=result.scanner_version,
                error_code="scanner_identity_mismatch",
            )

        scanner_run.scanner_version = result.scanner_version
        finding_count = 0
        if result.status == ScannerRunStatus.COMPLETED:
            try:
                with db.begin_nested():
                    finding_count = _persist_completed_scanner_findings(
                        db,
                        current_scan=scan,
                        scanner_run_id=scanner_run.id,
                        scanner_id=scanner_id,
                        findings=result.findings,
                        previous_scan_id=previous_scan_id,
                    )
            except Exception:
                result = ScannerExecutionResult(
                    scanner_id=scanner_id,
                    status=ScannerRunStatus.FAILED,
                    scanner_version=result.scanner_version,
                    error_code="finding_persistence_failed",
                )
                finding_count = 0

        mark_scanner_run_finished(
            db,
            scanner_run=scanner_run,
            status=result.status,
            finding_count=finding_count,
            error_code=result.error_code,
        )
        if registration.required:
            required_statuses.append(result.status)

    active_severity_values = db.scalars(
        select(BuildFinding.severity).where(
            BuildFinding.build_scan_id == scan.id,
            BuildFinding.finding_state != FindingState.RESOLVED.value,
        )
    ).all()
    decision = decide_build_assessment(
        AssessmentInput(
            required_scanner_statuses=tuple(required_statuses),
            active_severities=active_severities_from_values(active_severity_values),
        )
    )
    create_build_assessment(
        db,
        build_scan_id=scan.id,
        status=decision.status,
        required_scanners_complete=decision.required_scanners_complete,
        policy_version=BUILD_ASSESSMENT_POLICY_VERSION,
        reason_codes=decision.reason_codes,
        summary=decision.summary,
    )

    scan.status = "COMPLETED" if decision.required_scanners_complete else "FAILED"
    scan.failure_code = None if decision.required_scanners_complete else "required_scanner_incomplete"
    scan.completed_at = datetime.utcnow()
    db.flush()
    return scan
