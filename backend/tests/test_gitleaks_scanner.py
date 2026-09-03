from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.core.runtime_paths import GITLEAKS_EXE, GITLEAKS_VERSION
from scanners.contracts import (
    BuildTargetSnapshot,
    BuildTargetType,
    ScannerContext,
    ScannerRunStatus,
    ValidatedWorkspace,
)
from scanners.gitleaks.scanner import (
    CONFIG_PATH,
    GitleaksScanner,
    _gitleaks_command,
    _gitleaks_environment,
    parse_gitleaks_report,
)


def _workspace(root: Path) -> ValidatedWorkspace:
    files = [path for path in root.rglob("*") if path.is_file()]
    return ValidatedWorkspace(
        root=root.resolve(),
        target=BuildTargetSnapshot(
            target_type=BuildTargetType.LOCAL_DIRECTORY,
            display_name="gitleaks-fixture",
            source_locator=str(root.resolve()),
            source_fingerprint="b" * 64,
        ),
        file_count=len(files),
        total_bytes=sum(path.stat().st_size for path in files),
    )


def test_gitleaks_environment_ignores_target_or_process_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GITLEAKS_CONFIG", "must-not-survive")
    monkeypatch.setenv("GITLEAKS_CONFIG_TOML", "must-not-survive")
    env = _gitleaks_environment()
    assert "GITLEAKS_CONFIG" not in env
    assert "GITLEAKS_CONFIG_TOML" not in env
    assert env["GIT_TERMINAL_PROMPT"] == "0"


def test_gitleaks_command_forces_trusted_config_redaction_and_no_target_allow_comments(
    tmp_path: Path,
) -> None:
    report = tmp_path / "report.json"
    ignore = tmp_path / ".gitleaksignore"
    ignore.write_text("", encoding="utf-8")
    command = _gitleaks_command(
        Path("gitleaks"),
        config_path=CONFIG_PATH,
        report_path=report,
        ignore_path=ignore,
        context=ScannerContext(scan_id="command", timeout_seconds=42),
        max_target_bytes=100 * 1024 * 1024,
        target_path=tmp_path,
    )

    assert command[0] == "gitleaks"
    assert command[1] == "dir"
    assert "--redact=100" in command
    assert "--exit-code=0" in command
    assert "--report-format=json" in command
    assert f"--config={CONFIG_PATH.resolve()}" in command
    assert f"--gitleaks-ignore-path={ignore}" in command
    assert "--ignore-gitleaks-allow" in command
    assert "--max-archive-depth=0" in command
    assert "--max-decode-depth=0" in command
    assert "--timeout=42" in command
    assert command[-1] == str(tmp_path.resolve())


def test_gitleaks_report_never_persists_secret_match_or_identity_data(tmp_path: Path) -> None:
    report = [
        {
            "RuleID": "aws-access-token",
            "Description": "Potential AWS credential.",
            "StartLine": 3,
            "EndLine": 3,
            "StartColumn": 10,
            "EndColumn": 29,
            "Match": "REDACTED",
            "Secret": "REDACTED",
            "File": "config/settings.py",
            "SymlinkFile": "",
            "Commit": "c" * 40,
            "Entropy": 4.2,
            "Author": "Sensitive Name",
            "Email": "sensitive@example.invalid",
            "Date": "",
            "Message": "commit message with secret context",
            "Tags": ["key", "aws"],
            "Fingerprint": "config/settings.py:aws-access-token:3",
        }
    ]
    findings = parse_gitleaks_report(
        json.dumps(report).encode("utf-8"),
        workspace_root=tmp_path.resolve(),
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding.scanner_id == "gitleaks"
    assert finding.rule_id == "aws-access-token"
    assert finding.category == "SECRET"
    assert finding.severity.value == "CRITICAL"
    assert finding.confidence.value == "HIGH"
    assert finding.file_path == "config/settings.py"
    assert finding.safe_metadata == {"entropy": 4.2, "tags": ["key", "aws"]}
    serialized = repr(finding)
    for forbidden in (
        "REDACTED",
        "Sensitive Name",
        "sensitive@example.invalid",
        "commit message with secret context",
        "config/settings.py:aws-access-token:3",
    ):
        assert forbidden not in serialized


@pytest.mark.parametrize(
    ("payload", "error"),
    [
        (b"not-json", "gitleaks_invalid_json"),
        (json.dumps({}).encode(), "gitleaks_invalid_report"),
        (json.dumps([1]).encode(), "gitleaks_result_invalid"),
        (
            json.dumps(
                [
                    {
                        "RuleID": "x",
                        "File": "../outside.txt",
                        "StartLine": 1,
                        "EndLine": 1,
                    }
                ]
            ).encode(),
            "gitleaks_result_path_invalid",
        ),
    ],
)
def test_gitleaks_report_fails_closed_on_malformed_or_escaping_results(
    tmp_path: Path,
    payload: bytes,
    error: str,
) -> None:
    with pytest.raises(ValueError, match=error):
        parse_gitleaks_report(payload, workspace_root=tmp_path.resolve())


def test_project_managed_gitleaks_probe_is_exact_version() -> None:
    assert GITLEAKS_EXE.is_file(), "setup must provision project-managed Gitleaks"
    availability = GitleaksScanner().probe()
    assert availability.available is True
    assert availability.version == GITLEAKS_VERSION


def test_real_gitleaks_scan_detects_fake_credential_and_exposes_no_secret(
    tmp_path: Path,
) -> None:
    fake_access_key = "AKIAQWERTYUIOPASDFGH"
    fake_secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    (tmp_path / "credentials.txt").write_text(
        f'aws_access_key_id = "{fake_access_key}"\n'
        f'aws_secret_access_key = "{fake_secret}"\n',
        encoding="utf-8",
    )

    result = GitleaksScanner(max_target_bytes=10 * 1024 * 1024).scan(
        _workspace(tmp_path),
        ScannerContext(scan_id="real-secret", timeout_seconds=30),
    )

    assert result.status == ScannerRunStatus.COMPLETED
    assert any(finding.rule_id == "aws-access-token" for finding in result.findings)
    serialized = repr(result)
    assert fake_access_key not in serialized
    assert fake_secret not in serialized
    assert "REDACTED" not in serialized


def test_real_gitleaks_scan_ignores_source_controlled_allow_comment(
    tmp_path: Path,
) -> None:
    fake_access_key = "AKIAQWERTYUIOPASDFGH"
    (tmp_path / "credentials.txt").write_text(
        f'aws_access_key_id = "{fake_access_key}" # gitleaks:allow\n',
        encoding="utf-8",
    )
    (tmp_path / ".gitleaksignore").write_text(
        "credentials.txt:aws-access-token:1\n",
        encoding="utf-8",
    )

    result = GitleaksScanner(max_target_bytes=10 * 1024 * 1024).scan(
        _workspace(tmp_path),
        ScannerContext(scan_id="ignore-bypass", timeout_seconds=30),
    )

    assert result.status == ScannerRunStatus.COMPLETED
    assert any(finding.rule_id == "aws-access-token" for finding in result.findings)


def test_real_gitleaks_clean_fixture_has_no_findings(tmp_path: Path) -> None:
    (tmp_path / "settings.py").write_text(
        "DATABASE_HOST = '127.0.0.1'\nDEBUG = False\n",
        encoding="utf-8",
    )
    result = GitleaksScanner(max_target_bytes=10 * 1024 * 1024).scan(
        _workspace(tmp_path),
        ScannerContext(scan_id="clean", timeout_seconds=30),
    )

    assert result.status == ScannerRunStatus.COMPLETED
    assert result.findings == ()
