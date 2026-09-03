from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.core.runtime_paths import TRIVY_EXE, TRIVY_VERSION
from scanners.contracts import (
    BuildTargetSnapshot,
    BuildTargetType,
    ScannerContext,
    ScannerRunStatus,
    ValidatedWorkspace,
)
from scanners.trivy.scanner import (
    TrivyScanner,
    _trivy_command,
    _trivy_environment,
    parse_trivy_report,
)


def _workspace(root: Path) -> ValidatedWorkspace:
    files = [path for path in root.rglob("*") if path.is_file()]
    return ValidatedWorkspace(
        root=root.resolve(),
        target=BuildTargetSnapshot(
            target_type=BuildTargetType.LOCAL_DIRECTORY,
            display_name="trivy-fixture",
            source_locator=str(root.resolve()),
            source_fingerprint="c" * 64,
        ),
        file_count=len(files),
        total_bytes=sum(path.stat().st_size for path in files),
    )


def test_trivy_environment_removes_external_credentials_and_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in (
        "TRIVY_USERNAME",
        "TRIVY_PASSWORD",
        "TRIVY_TOKEN",
        "TRIVY_CONFIG",
        "TRIVY_DB_REPOSITORY",
        "DOCKER_AUTH_CONFIG",
    ):
        monkeypatch.setenv(name, "must-not-survive")
    env = _trivy_environment()

    for name in (
        "TRIVY_USERNAME",
        "TRIVY_PASSWORD",
        "TRIVY_TOKEN",
        "TRIVY_CONFIG",
        "TRIVY_DB_REPOSITORY",
        "DOCKER_AUTH_CONFIG",
    ):
        assert name not in env
    assert env["GIT_TERMINAL_PROMPT"] == "0"
    assert env["DOCKER_CONFIG"]


def test_trivy_command_is_offline_vulnerability_only_and_uses_external_ignore(
    tmp_path: Path,
) -> None:
    workspace = _workspace(tmp_path)
    control = tmp_path.parent / "control"
    control.mkdir()
    report = control / "report.json"
    ignore = control / ".trivyignore"
    ignore.write_text("", encoding="utf-8")
    command = _trivy_command(
        Path("trivy"),
        workspace=workspace,
        report_path=report,
        ignore_path=ignore,
        context=ScannerContext(scan_id="command", timeout_seconds=47),
    )

    assert command[:2] == ["trivy", "filesystem"]
    assert "--scanners" in command and command[command.index("--scanners") + 1] == "vuln"
    assert "--pkg-types" in command and command[command.index("--pkg-types") + 1] == "library"
    assert "--offline-scan" in command
    assert "--skip-db-update" in command
    assert "--skip-java-db-update" in command
    assert "--include-dev-deps" in command
    assert "--quiet" in command
    assert "--skip-version-check" in command
    assert command[command.index("--ignorefile") + 1] == str(ignore)
    assert command[command.index("--timeout") + 1] == "47s"
    assert command[-1] == str(tmp_path.resolve())


def test_trivy_report_normalizes_dependency_vulnerability_without_raw_db_payload(
    tmp_path: Path,
) -> None:
    report = {
        "SchemaVersion": 2,
        "Results": [
            {
                "Target": "requirements.txt",
                "Class": "lang-pkgs",
                "Type": "pip",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2099-0001",
                        "PkgName": "example",
                        "InstalledVersion": "1.0.0",
                        "FixedVersion": "1.0.1",
                        "Severity": "HIGH",
                        "Title": "Example vulnerability",
                        "Description": "large upstream description should not be persisted",
                        "PrimaryURL": "https://example.invalid/CVE-2099-0001",
                        "References": [
                            "https://advisories.example.invalid/1",
                            "https://example.invalid/CVE-2099-0001",
                        ],
                        "PkgID": "example@1.0.0",
                        "DataSource": {"ID": "secret-ish-source-payload"},
                    }
                ],
            }
        ],
    }

    findings = parse_trivy_report(
        json.dumps(report).encode("utf-8"),
        workspace_root=tmp_path.resolve(),
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding.scanner_id == "trivy"
    assert finding.rule_id == "CVE-2099-0001"
    assert finding.category == "DEPENDENCY_VULNERABILITY"
    assert finding.severity.value == "HIGH"
    assert finding.confidence.value == "HIGH"
    assert finding.file_path == "requirements.txt"
    assert finding.package_name == "example"
    assert finding.package_version == "1.0.0"
    assert finding.fixed_version == "1.0.1"
    assert finding.vulnerability_id == "CVE-2099-0001"
    assert finding.safe_metadata == {
        "trivy_severity": "HIGH",
        "package_type": "pip",
        "result_class": "lang-pkgs",
    }
    serialized = repr(finding)
    assert "large upstream description should not be persisted" not in serialized
    assert "secret-ish-source-payload" not in serialized
    assert "example@1.0.0" not in serialized


def test_trivy_unknown_severity_is_conservatively_normalized_to_medium(
    tmp_path: Path,
) -> None:
    payload = {
        "SchemaVersion": 2,
        "Results": [
            {
                "Target": "requirements.txt",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2099-0002",
                        "PkgName": "pkg",
                        "InstalledVersion": "1",
                        "Severity": "UNKNOWN",
                    }
                ],
            }
        ],
    }
    finding = parse_trivy_report(
        json.dumps(payload).encode(),
        workspace_root=tmp_path.resolve(),
    )[0]
    assert finding.severity.value == "MEDIUM"
    assert finding.safe_metadata["trivy_severity"] == "UNKNOWN"


@pytest.mark.parametrize(
    ("payload", "error"),
    [
        (b"not-json", "trivy_invalid_json"),
        (json.dumps([]).encode(), "trivy_invalid_report"),
        (json.dumps({"SchemaVersion": 1, "Results": []}).encode(), "trivy_schema_unsupported"),
        (
            json.dumps({"SchemaVersion": 2, "Results": "bad"}).encode(),
            "trivy_results_invalid",
        ),
        (
            json.dumps(
                {
                    "SchemaVersion": 2,
                    "Results": [{"Target": "../outside", "Vulnerabilities": []}],
                }
            ).encode(),
            "trivy_result_path_invalid",
        ),
    ],
)
def test_trivy_report_fails_closed_for_invalid_evidence(
    tmp_path: Path,
    payload: bytes,
    error: str,
) -> None:
    with pytest.raises(ValueError, match=error):
        parse_trivy_report(payload, workspace_root=tmp_path.resolve())


def test_trivy_empty_results_are_valid_clean_evidence(tmp_path: Path) -> None:
    assert (
        parse_trivy_report(
            json.dumps({"SchemaVersion": 2, "Results": None}).encode(),
            workspace_root=tmp_path.resolve(),
        )
        == ()
    )


def test_project_managed_trivy_probe_is_exact_version_with_database() -> None:
    assert TRIVY_EXE.is_file(), "setup must provision project-managed Trivy"
    availability = TrivyScanner().probe()
    assert availability.available is True
    assert availability.version == TRIVY_VERSION


def test_real_trivy_scan_detects_known_vulnerable_python_dependency(
    tmp_path: Path,
) -> None:
    (tmp_path / "requirements.txt").write_text(
        "urllib3==1.25.2\n",
        encoding="utf-8",
    )
    result = TrivyScanner().scan(
        _workspace(tmp_path),
        ScannerContext(
            scan_id="vulnerable-python",
            timeout_seconds=90,
            max_output_bytes=10 * 1024 * 1024,
        ),
    )

    assert result.status == ScannerRunStatus.COMPLETED
    urllib_findings = [
        finding for finding in result.findings if finding.package_name == "urllib3"
    ]
    assert urllib_findings
    assert any(finding.severity.value in {"HIGH", "CRITICAL"} for finding in urllib_findings)
    assert all(finding.vulnerability_id for finding in urllib_findings)
    assert all(len(finding.fingerprint) == 64 for finding in urllib_findings)


def test_real_trivy_scan_does_not_honor_source_trivyignore(
    tmp_path: Path,
) -> None:
    (tmp_path / "requirements.txt").write_text("urllib3==1.25.2\n", encoding="utf-8")
    (tmp_path / ".trivyignore").write_text("CVE-2020-7212\n", encoding="utf-8")
    (tmp_path / "trivy.yaml").write_text(
        "severity:\n  - CRITICAL\n",
        encoding="utf-8",
    )

    result = TrivyScanner().scan(
        _workspace(tmp_path),
        ScannerContext(
            scan_id="ignore-bypass",
            timeout_seconds=90,
            max_output_bytes=10 * 1024 * 1024,
        ),
    )

    assert result.status == ScannerRunStatus.COMPLETED
    assert any(
        finding.vulnerability_id == "CVE-2020-7212"
        for finding in result.findings
    )


def test_real_trivy_clean_fixture_has_no_findings(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text(
        "urllib3==2.7.0\n",
        encoding="utf-8",
    )
    result = TrivyScanner().scan(
        _workspace(tmp_path),
        ScannerContext(
            scan_id="clean-python",
            timeout_seconds=90,
            max_output_bytes=10 * 1024 * 1024,
        ),
    )

    assert result.status == ScannerRunStatus.COMPLETED
    assert not [finding for finding in result.findings if finding.package_name == "urllib3"]
