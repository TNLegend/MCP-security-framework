from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.models  # noqa: F401
from app.db.database import Base
from app.models.build_security import BuildAssessment, BuildFinding
from app.schemas.build_security import BuildFindingPublic, BuildTargetRequest
from app.services.build_security import (
    BuildSecurityStateError,
    create_build_assessment,
    create_build_scan,
    create_scanner_run,
    mark_scanner_run_finished,
    persist_normalized_finding,
)
from scanners import BuildScanner
from scanners.contracts import (
    BuildAssessmentStatus,
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
    finding_fingerprint,
    sanitize_scanner_metadata,
)


def _session():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    return engine, sessionmaker(bind=engine, expire_on_commit=False)()


def _target() -> BuildTargetSnapshot:
    return BuildTargetSnapshot(
        target_type=BuildTargetType.LOCAL_DIRECTORY,
        display_name="example-mcp",
        source_locator="D:/workspace/example-mcp",
        source_revision="abc123",
        source_fingerprint="a" * 64,
    )


def _finding(**overrides) -> NormalizedFinding:
    values = {
        "scanner_id": "semgrep",
        "rule_id": "MCP-SEC-001",
        "category": "COMMAND_INJECTION",
        "severity": FindingSeverity.HIGH,
        "confidence": FindingConfidence.HIGH,
        "title": "Unsafe shell execution",
        "file_path": r".\server\tools.py",
        "line_start": 42,
        "line_end": 43,
        "safe_metadata": {"cwe": ["CWE-78"]},
    }
    values.update(overrides)
    return NormalizedFinding.create(**values)


def test_finding_fingerprint_is_stable_across_path_separators() -> None:
    first = finding_fingerprint(
        scanner_id="Semgrep",
        rule_id="MCP-SEC-001",
        category="command_injection",
        file_path=r".\server\tools.py",
        line_start=42,
    )
    second = finding_fingerprint(
        scanner_id="semgrep",
        rule_id="MCP-SEC-001",
        category="COMMAND_INJECTION",
        file_path="server/tools.py",
        line_start=42,
    )
    assert first == second
    assert len(first) == 64


def test_finding_fingerprint_changes_when_security_identity_changes() -> None:
    base = _finding()
    changed = _finding(line_start=43)
    assert base.fingerprint != changed.fingerprint


def test_normalized_finding_does_not_put_metadata_or_titles_in_identity() -> None:
    first = _finding(title="First title", safe_metadata={"cwe": ["CWE-78"]})
    second = _finding(title="Updated title", safe_metadata={"cwe": ["CWE-78"], "vendor": "x"})
    assert first.fingerprint == second.fingerprint


def test_scanner_metadata_redaction_is_recursive_and_bounded() -> None:
    sanitized = sanitize_scanner_metadata(
        {
            "cwe": "CWE-798",
            "nested": {
                "api_key": "must-never-survive",
                "raw_match": "must-never-survive",
                "safe": "x" * 2000,
            },
            "authorization_header": "must-never-survive",
        }
    )
    assert sanitized["cwe"] == "CWE-798"
    assert "api_key" not in sanitized["nested"]
    assert "raw_match" not in sanitized["nested"]
    assert "authorization_header" not in sanitized
    assert len(sanitized["nested"]["safe"]) == 1000
    assert "must-never-survive" not in repr(sanitized)


def test_workspace_contract_requires_absolute_non_negative_workspace() -> None:
    with pytest.raises(ValueError, match="workspace_root_must_be_absolute"):
        ValidatedWorkspace(
            root=Path("relative"),
            target=_target(),
            file_count=1,
            total_bytes=1,
        )
    with pytest.raises(ValueError, match="workspace_size_must_be_non_negative"):
        ValidatedWorkspace(
            root=Path.cwd().resolve(),
            target=_target(),
            file_count=-1,
            total_bytes=1,
        )


def test_scanner_result_cannot_claim_findings_on_failed_run() -> None:
    with pytest.raises(ValueError, match="incomplete_scanner_run_cannot_claim_findings"):
        ScannerExecutionResult(
            scanner_id="semgrep",
            status=ScannerRunStatus.FAILED,
            findings=(_finding(),),
            error_code="scanner_failed",
        )


class _FakeScanner:
    scanner_id = "fake"

    def probe(self) -> ScannerAvailability:
        return ScannerAvailability(available=True, scanner_id=self.scanner_id, version="1")

    def scan(
        self,
        workspace: ValidatedWorkspace,
        context: ScannerContext,
    ) -> ScannerExecutionResult:
        return ScannerExecutionResult(
            scanner_id=self.scanner_id,
            status=ScannerRunStatus.COMPLETED,
            scanner_version="1",
        )


def test_generic_scanner_protocol_accepts_adapter_without_tool_specific_coupling() -> None:
    assert isinstance(_FakeScanner(), BuildScanner)


def test_build_security_tables_are_created_on_fresh_database() -> None:
    engine, db = _session()
    try:
        tables = set(inspect(engine).get_table_names())
        assert {
            "build_scan_runs",
            "build_scanner_runs",
            "build_findings",
            "build_assessments",
        } <= tables
    finally:
        db.close()
        engine.dispose()


def test_persistence_deduplicates_and_redacts_normalized_finding() -> None:
    engine, db = _session()
    try:
        scan = create_build_scan(db, target=_target(), requested_by="admin-id")
        scanner_run = create_scanner_run(
            db,
            build_scan_id=scan.id,
            scanner_id="semgrep",
            scanner_version="1.2.3",
        )
        finding = _finding(
            safe_metadata={
                "cwe": "CWE-78",
                "secret": "must-never-survive",
                "nested": {"token_value": "must-never-survive", "safe": "ok"},
            }
        )
        first = persist_normalized_finding(
            db,
            build_scan_id=scan.id,
            scanner_run_id=scanner_run.id,
            finding=finding,
        )
        second = persist_normalized_finding(
            db,
            build_scan_id=scan.id,
            scanner_run_id=scanner_run.id,
            finding=finding,
        )

        assert first.id == second.id
        persisted = db.get(BuildFinding, first.id)
        assert persisted is not None
        assert persisted.file_path == "server/tools.py"
        assert persisted.safe_metadata == {"cwe": "CWE-78", "nested": {"safe": "ok"}}
        assert "must-never-survive" not in repr(persisted.safe_metadata)
    finally:
        db.close()
        engine.dispose()


def test_persistence_rejects_scanner_identity_mismatch() -> None:
    engine, db = _session()
    try:
        scan = create_build_scan(db, target=_target(), requested_by=None)
        scanner_run = create_scanner_run(
            db,
            build_scan_id=scan.id,
            scanner_id="trivy",
        )
        with pytest.raises(BuildSecurityStateError, match="scanner_finding_identity_mismatch"):
            persist_normalized_finding(
                db,
                build_scan_id=scan.id,
                scanner_run_id=scanner_run.id,
                finding=_finding(scanner_id="semgrep"),
            )
    finally:
        db.close()
        engine.dispose()


def test_required_scanner_incomplete_can_never_assess_pass() -> None:
    engine, db = _session()
    try:
        scan = create_build_scan(db, target=_target(), requested_by=None)
        with pytest.raises(
            BuildSecurityStateError,
            match="incomplete_required_scanners_cannot_pass",
        ):
            create_build_assessment(
                db,
                build_scan_id=scan.id,
                status=BuildAssessmentStatus.PASS,
                required_scanners_complete=False,
                policy_version="build-policy-v1",
            )
    finally:
        db.close()
        engine.dispose()


def test_assessment_counts_persisted_findings() -> None:
    engine, db = _session()
    try:
        scan = create_build_scan(db, target=_target(), requested_by=None)
        scanner_run = create_scanner_run(
            db,
            build_scan_id=scan.id,
            scanner_id="semgrep",
        )
        persist_normalized_finding(
            db,
            build_scan_id=scan.id,
            scanner_run_id=scanner_run.id,
            finding=_finding(severity=FindingSeverity.CRITICAL),
        )
        persist_normalized_finding(
            db,
            build_scan_id=scan.id,
            scanner_run_id=scanner_run.id,
            finding=_finding(
                rule_id="MCP-SEC-002",
                line_start=12,
                severity=FindingSeverity.MEDIUM,
            ),
        )
        mark_scanner_run_finished(
            db,
            scanner_run=scanner_run,
            status=ScannerRunStatus.COMPLETED,
            finding_count=2,
        )
        assessment = create_build_assessment(
            db,
            build_scan_id=scan.id,
            status=BuildAssessmentStatus.BLOCK,
            required_scanners_complete=True,
            policy_version="build-policy-v1",
            reason_codes=["critical_finding"],
        )
        db.flush()

        stored = db.get(BuildAssessment, assessment.id)
        assert stored is not None
        assert stored.critical_count == 1
        assert stored.medium_count == 1
        assert stored.high_count == 0
    finally:
        db.close()
        engine.dispose()


def test_public_finding_schema_forbids_secret_bearing_extra_fields() -> None:
    field_names = set(BuildFindingPublic.model_fields)
    assert not {
        "secret",
        "raw_secret",
        "matched_secret",
        "raw_match",
        "snippet",
        "content",
    } & field_names

    payload = {
        "id": "f",
        "build_scan_id": "s",
        "scanner_run_id": "r",
        "scanner_id": "gitleaks",
        "rule_id": "generic-api-key",
        "category": "SECRET",
        "severity": "CRITICAL",
        "confidence": "HIGH",
        "finding_state": "NEW",
        "fingerprint": "a" * 64,
        "title": "Secret detected",
        "references": [],
        "safe_metadata": {},
        "created_at": "2026-08-30T20:00:00",
        "raw_secret": "must-never-survive",
    }
    with pytest.raises(ValidationError):
        BuildFindingPublic.model_validate(payload)


def test_build_target_request_is_strict_and_normalized() -> None:
    parsed = BuildTargetRequest.model_validate(
        {
            "target_type": "LOCAL_DIRECTORY",
            "display_name": "  example-mcp  ",
            "source_locator": "  D:/src/example-mcp  ",
        }
    )
    assert parsed.display_name == "example-mcp"
    assert parsed.source_locator == "D:/src/example-mcp"

    with pytest.raises(ValidationError):
        BuildTargetRequest.model_validate(
            {
                "target_type": "LOCAL_DIRECTORY",
                "display_name": "example",
                "source_locator": "D:/src/example",
                "unexpected": True,
            }
        )
