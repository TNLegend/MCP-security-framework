from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.models  # noqa: F401
from app.db.database import Base
from app.models.build_security import (
    BuildAssessment,
    BuildFinding,
    BuildScannerRun,
)
from app.services.build_scan_orchestrator import (
    BuildScannerRegistration,
    run_build_security_scan,
)
from scanners.contracts import (
    BuildTargetSnapshot,
    BuildTargetType,
    FindingConfidence,
    FindingSeverity,
    NormalizedFinding,
    ScannerAvailability,
    ScannerContext,
    ScannerExecutionResult,
    ScannerRunStatus,
    ValidatedWorkspace,
)


class _FakeScanner:
    def __init__(
        self,
        scanner_id: str,
        *,
        status: ScannerRunStatus = ScannerRunStatus.COMPLETED,
        findings: tuple[NormalizedFinding, ...] = (),
        error_code: str | None = None,
        returned_scanner_id: str | None = None,
        raise_exception: bool = False,
    ) -> None:
        self.scanner_id = scanner_id
        self._status = status
        self._findings = findings
        self._error_code = error_code
        self._returned_scanner_id = returned_scanner_id
        self._raise_exception = raise_exception

    def probe(self) -> ScannerAvailability:
        return ScannerAvailability(
            available=self._status != ScannerRunStatus.UNAVAILABLE,
            scanner_id=self.scanner_id,
            version="1.0",
        )

    def scan(
        self,
        workspace: ValidatedWorkspace,
        context: ScannerContext,
    ) -> ScannerExecutionResult:
        if self._raise_exception:
            raise RuntimeError("must-not-leak")
        return ScannerExecutionResult(
            scanner_id=self._returned_scanner_id or self.scanner_id,
            status=self._status,
            findings=self._findings,
            scanner_version="1.0",
            error_code=self._error_code,
        )


def _session():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return engine, sessionmaker(bind=engine, expire_on_commit=False)()


def _workspace(tmp_path: Path, *, fingerprint: str = "a" * 64) -> ValidatedWorkspace:
    root = tmp_path / "workspace"
    root.mkdir(exist_ok=True)
    return ValidatedWorkspace(
        root=root.resolve(),
        target=BuildTargetSnapshot(
            target_type=BuildTargetType.LOCAL_DIRECTORY,
            display_name="fixture-mcp",
            source_locator=str(root.resolve()),
            source_revision=None,
            source_fingerprint=fingerprint,
        ),
        file_count=0,
        total_bytes=0,
    )


def _finding(
    scanner_id: str,
    *,
    severity: FindingSeverity,
    rule_id: str = "RULE-1",
    line_start: int = 10,
) -> NormalizedFinding:
    return NormalizedFinding.create(
        scanner_id=scanner_id,
        rule_id=rule_id,
        category="TEST",
        severity=severity,
        confidence=FindingConfidence.HIGH,
        title=f"{rule_id} finding",
        file_path="server.py",
        line_start=line_start,
    )


def _assessment(db, scan_id: str) -> BuildAssessment:
    result = db.scalar(
        select(BuildAssessment).where(BuildAssessment.build_scan_id == scan_id)
    )
    assert result is not None
    return result


def test_all_required_scanners_clean_produces_pass(tmp_path: Path) -> None:
    engine, db = _session()
    try:
        scan = run_build_security_scan(
            db,
            workspace=_workspace(tmp_path),
            requested_by="admin",
            scanners=(
                BuildScannerRegistration(_FakeScanner("semgrep")),
                BuildScannerRegistration(_FakeScanner("gitleaks")),
                BuildScannerRegistration(_FakeScanner("trivy")),
            ),
        )

        assert scan.status == "COMPLETED"
        assessment = _assessment(db, scan.id)
        assert assessment.status == "PASS"
        assert assessment.required_scanners_complete is True
        assert assessment.reason_codes == []
        assert assessment.critical_count == 0
        runs = db.scalars(
            select(BuildScannerRun).where(BuildScannerRun.build_scan_id == scan.id)
        ).all()
        assert {run.status for run in runs} == {"COMPLETED"}
    finally:
        db.close()
        engine.dispose()


def test_high_finding_warns_and_critical_finding_blocks(tmp_path: Path) -> None:
    engine, db = _session()
    try:
        warning_scan = run_build_security_scan(
            db,
            workspace=_workspace(tmp_path, fingerprint="b" * 64),
            requested_by=None,
            scanners=(
                BuildScannerRegistration(
                    _FakeScanner(
                        "semgrep",
                        findings=(
                            _finding("semgrep", severity=FindingSeverity.HIGH),
                        ),
                    )
                ),
            ),
        )
        warning = _assessment(db, warning_scan.id)
        assert warning.status == "WARN"
        assert warning.high_count == 1
        assert warning.reason_codes == ["high_findings"]

        blocking_scan = run_build_security_scan(
            db,
            workspace=_workspace(tmp_path, fingerprint="c" * 64),
            requested_by=None,
            scanners=(
                BuildScannerRegistration(
                    _FakeScanner(
                        "semgrep",
                        findings=(
                            _finding(
                                "semgrep",
                                severity=FindingSeverity.CRITICAL,
                                rule_id="RULE-CRIT",
                            ),
                        ),
                    )
                ),
            ),
        )
        blocked = _assessment(db, blocking_scan.id)
        assert blocked.status == "BLOCK"
        assert blocked.critical_count == 1
        assert blocked.reason_codes == ["critical_findings"]
    finally:
        db.close()
        engine.dispose()


@pytest.mark.parametrize(
    ("status", "error_code"),
    [
        (ScannerRunStatus.FAILED, "scanner_failed"),
        (ScannerRunStatus.TIMED_OUT, "scanner_timeout"),
        (ScannerRunStatus.UNAVAILABLE, "scanner_unavailable"),
    ],
)
def test_required_scanner_incomplete_is_error_not_pass(
    tmp_path: Path,
    status: ScannerRunStatus,
    error_code: str,
) -> None:
    engine, db = _session()
    try:
        scan = run_build_security_scan(
            db,
            workspace=_workspace(tmp_path),
            requested_by=None,
            scanners=(
                BuildScannerRegistration(
                    _FakeScanner(
                        "required",
                        status=status,
                        error_code=error_code,
                    )
                ),
            ),
        )

        assert scan.status == "FAILED"
        assert scan.failure_code == "required_scanner_incomplete"
        assessment = _assessment(db, scan.id)
        assert assessment.status == "ERROR"
        assert assessment.required_scanners_complete is False
        assert assessment.reason_codes == ["required_scanner_incomplete"]
    finally:
        db.close()
        engine.dispose()


def test_scanner_exception_is_bounded_to_safe_error_code(tmp_path: Path) -> None:
    engine, db = _session()
    try:
        scan = run_build_security_scan(
            db,
            workspace=_workspace(tmp_path),
            requested_by=None,
            scanners=(
                BuildScannerRegistration(
                    _FakeScanner("semgrep", raise_exception=True)
                ),
            ),
        )
        run = db.scalar(
            select(BuildScannerRun).where(BuildScannerRun.build_scan_id == scan.id)
        )
        assert run is not None
        assert run.status == "FAILED"
        assert run.error_code == "scanner_exception"
        assert "must-not-leak" not in repr(run.__dict__)
    finally:
        db.close()
        engine.dispose()


def test_scanner_identity_mismatch_fails_closed(tmp_path: Path) -> None:
    engine, db = _session()
    try:
        scan = run_build_security_scan(
            db,
            workspace=_workspace(tmp_path),
            requested_by=None,
            scanners=(
                BuildScannerRegistration(
                    _FakeScanner(
                        "semgrep",
                        returned_scanner_id="gitleaks",
                    )
                ),
            ),
        )
        run = db.scalar(
            select(BuildScannerRun).where(BuildScannerRun.build_scan_id == scan.id)
        )
        assert run is not None
        assert run.status == "FAILED"
        assert run.error_code == "scanner_identity_mismatch"
        assert _assessment(db, scan.id).status == "ERROR"
    finally:
        db.close()
        engine.dispose()


def test_findings_transition_new_unchanged_resolved_regressed(tmp_path: Path) -> None:
    engine, db = _session()
    try:
        finding = _finding(
            "semgrep",
            severity=FindingSeverity.CRITICAL,
            rule_id="MCP-SEC-001",
        )
        registration_with_finding = (
            BuildScannerRegistration(
                _FakeScanner("semgrep", findings=(finding,))
            ),
        )
        registration_clean = (
            BuildScannerRegistration(_FakeScanner("semgrep")),
        )

        scan1 = run_build_security_scan(
            db,
            workspace=_workspace(tmp_path, fingerprint="1" * 64),
            requested_by=None,
            scanners=registration_with_finding,
        )
        rows1 = db.scalars(
            select(BuildFinding).where(BuildFinding.build_scan_id == scan1.id)
        ).all()
        assert [row.finding_state for row in rows1] == ["NEW"]
        assert _assessment(db, scan1.id).status == "BLOCK"

        scan2 = run_build_security_scan(
            db,
            workspace=_workspace(tmp_path, fingerprint="2" * 64),
            requested_by=None,
            scanners=registration_with_finding,
        )
        rows2 = db.scalars(
            select(BuildFinding).where(BuildFinding.build_scan_id == scan2.id)
        ).all()
        assert [row.finding_state for row in rows2] == ["UNCHANGED"]

        scan3 = run_build_security_scan(
            db,
            workspace=_workspace(tmp_path, fingerprint="3" * 64),
            requested_by=None,
            scanners=registration_clean,
        )
        rows3 = db.scalars(
            select(BuildFinding).where(BuildFinding.build_scan_id == scan3.id)
        ).all()
        assert [row.finding_state for row in rows3] == ["RESOLVED"]
        resolved_assessment = _assessment(db, scan3.id)
        assert resolved_assessment.status == "PASS"
        assert resolved_assessment.critical_count == 0

        scan4 = run_build_security_scan(
            db,
            workspace=_workspace(tmp_path, fingerprint="4" * 64),
            requested_by=None,
            scanners=registration_with_finding,
        )
        rows4 = db.scalars(
            select(BuildFinding).where(BuildFinding.build_scan_id == scan4.id)
        ).all()
        assert [row.finding_state for row in rows4] == ["REGRESSED"]
        assert _assessment(db, scan4.id).status == "BLOCK"
    finally:
        db.close()
        engine.dispose()


def test_failed_scanner_does_not_claim_previous_finding_resolved(tmp_path: Path) -> None:
    engine, db = _session()
    try:
        finding = _finding(
            "semgrep",
            severity=FindingSeverity.HIGH,
        )
        scan1 = run_build_security_scan(
            db,
            workspace=_workspace(tmp_path, fingerprint="5" * 64),
            requested_by=None,
            scanners=(
                BuildScannerRegistration(
                    _FakeScanner("semgrep", findings=(finding,))
                ),
            ),
        )
        assert _assessment(db, scan1.id).status == "WARN"

        scan2 = run_build_security_scan(
            db,
            workspace=_workspace(tmp_path, fingerprint="6" * 64),
            requested_by=None,
            scanners=(
                BuildScannerRegistration(
                    _FakeScanner(
                        "semgrep",
                        status=ScannerRunStatus.FAILED,
                        error_code="scanner_failed",
                    )
                ),
            ),
        )
        assert db.scalars(
            select(BuildFinding).where(BuildFinding.build_scan_id == scan2.id)
        ).all() == []
        assert _assessment(db, scan2.id).status == "ERROR"
    finally:
        db.close()
        engine.dispose()


def test_duplicate_scanner_ids_and_no_required_scanners_are_rejected(
    tmp_path: Path,
) -> None:
    engine, db = _session()
    try:
        with pytest.raises(ValueError, match="duplicate_build_scanner_id"):
            run_build_security_scan(
                db,
                workspace=_workspace(tmp_path),
                requested_by=None,
                scanners=(
                    BuildScannerRegistration(_FakeScanner("same")),
                    BuildScannerRegistration(_FakeScanner("same")),
                ),
            )

        with pytest.raises(ValueError, match="at_least_one_required_build_scanner"):
            run_build_security_scan(
                db,
                workspace=_workspace(tmp_path),
                requested_by=None,
                scanners=(
                    BuildScannerRegistration(_FakeScanner("optional"), required=False),
                ),
            )
    finally:
        db.close()
        engine.dispose()


def test_source_fingerprint_is_mandatory(tmp_path: Path) -> None:
    engine, db = _session()
    try:
        workspace = _workspace(tmp_path, fingerprint="")
        with pytest.raises(ValueError, match="build_source_fingerprint_required"):
            run_build_security_scan(
                db,
                workspace=workspace,
                requested_by=None,
                scanners=(BuildScannerRegistration(_FakeScanner("semgrep")),),
            )
    finally:
        db.close()
        engine.dispose()
