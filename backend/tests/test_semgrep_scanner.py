from __future__ import annotations

import json
from pathlib import Path
import sys

import pytest

from app.core.runtime_paths import SEMGREP_EXE, SEMGREP_VERSION
from scanners.contracts import (
    BuildTargetSnapshot,
    BuildTargetType,
    ScannerContext,
    ScannerRunStatus,
    ValidatedWorkspace,
)
from scanners.semgrep.scanner import (
    RULES_PATH,
    SemgrepScanner,
    _run_bounded_semgrep,
    _semgrep_environment,
    parse_semgrep_report,
)


def _workspace(root: Path) -> ValidatedWorkspace:
    return ValidatedWorkspace(
        root=root.resolve(),
        target=BuildTargetSnapshot(
            target_type=BuildTargetType.LOCAL_DIRECTORY,
            display_name="semgrep-fixture",
            source_locator=str(root.resolve()),
            source_fingerprint="a" * 64,
        ),
        file_count=sum(1 for path in root.rglob("*") if path.is_file()),
        total_bytes=sum(path.stat().st_size for path in root.rglob("*") if path.is_file()),
    )


def test_semgrep_environment_disables_cloud_identity_and_metrics(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SEMGREP_APP_TOKEN", "must-not-survive")
    monkeypatch.setenv("SEMGREP_REPO_NAME", "must-not-survive")
    monkeypatch.setenv("SEMGREP_JOB_URL", "must-not-survive")
    monkeypatch.setenv("TEMP", "must-not-survive")
    monkeypatch.setenv("TMP", "must-not-survive")
    monkeypatch.setenv("TMPDIR", "must-not-survive")
    env = _semgrep_environment()

    assert "SEMGREP_APP_TOKEN" not in env
    assert "SEMGREP_REPO_NAME" not in env
    assert "SEMGREP_JOB_URL" not in env
    if sys.platform == "win32":
        assert "TEMP" not in env
        assert "TMP" not in env
        assert "TMPDIR" not in env
    assert env["SEMGREP_SEND_METRICS"] == "off"
    assert env["SEMGREP_ENABLE_VERSION_CHECK"] == "0"
    assert env["GIT_TERMINAL_PROMPT"] == "0"


def test_semgrep_command_is_local_deterministic_and_non_cloud(tmp_path: Path) -> None:
    (tmp_path / "server.py").write_text("x = 1\n", encoding="utf-8")
    scanner = SemgrepScanner(
        executable=Path("semgrep"),
        rules_path=RULES_PATH,
        max_target_bytes=123456,
    )
    command = scanner.command_for(_workspace(tmp_path))
    joined = " ".join(command)

    assert command[0] == "semgrep"
    assert "--metrics=off" in command
    assert "--disable-version-check" in command
    assert "--no-rewrite-rule-ids" in command
    assert "--quiet" in command
    assert "--jobs=1" in command
    assert "--timeout-threshold=1" in command
    assert "--max-target-bytes=123456" in command
    assert "--project-root" in command
    assert command[command.index("--project-root") + 1] == "."
    assert "--no-git-ignore" in command
    assert "--config" in command
    assert str(RULES_PATH.resolve()) in command
    assert command[-1] == "."
    assert "p/" not in joined
    assert "SEMGREP_APP_TOKEN" not in joined


def test_semgrep_report_normalizes_only_safe_evidence() -> None:
    report = {
        "version": SEMGREP_VERSION,
        "results": [
            {
                "check_id": "mcp.python.tool-os-system",
                "path": r".\server\tools.py",
                "start": {"line": 12, "col": 5, "offset": 100},
                "end": {"line": 12, "col": 23, "offset": 118},
                "extra": {
                    "message": "MCP tool executes a shell command through os.system.",
                    "severity": "ERROR",
                    "lines": "os.system(secret_command)",
                    "metavars": {"$X": {"abstract_content": "secret_command"}},
                    "fingerprint": "requires login",
                    "metadata": {
                        "mcp_framework_severity": "CRITICAL",
                        "mcp_framework_category": "COMMAND_EXECUTION",
                        "confidence": "HIGH",
                        "cwe": ["CWE-78"],
                        "owasp": ["A03:2021"],
                        "technology": ["python"],
                        "references": ["https://example.invalid/rule"],
                        "raw_match": "must-never-survive",
                        "secret": "must-never-survive",
                    },
                },
            }
        ],
        "errors": [],
        "paths": {"scanned": [r".\server\tools.py"]},
        "skipped_rules": [],
    }

    findings = parse_semgrep_report(json.dumps(report).encode("utf-8"))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "mcp.python.tool-os-system"
    assert finding.category == "COMMAND_EXECUTION"
    assert finding.severity.value == "CRITICAL"
    assert finding.confidence.value == "HIGH"
    assert finding.file_path == "server/tools.py"
    assert finding.line_start == 12
    assert finding.safe_metadata == {
        "cwe": ["CWE-78"],
        "owasp": ["A03:2021"],
        "technology": ["python"],
    }
    serialized = repr(finding)
    assert "secret_command" not in serialized
    assert "must-never-survive" not in serialized
    assert "requires login" not in serialized


@pytest.mark.parametrize(
    ("report", "error"),
    [
        (b"", "semgrep_empty_output"),
        (b"not-json", "semgrep_invalid_json"),
        (json.dumps([]).encode(), "semgrep_invalid_report"),
        (
            json.dumps({"results": [], "errors": [{"code": 1}], "skipped_rules": []}).encode(),
            "semgrep_reported_errors",
        ),
        (
            json.dumps({"results": [], "errors": [], "skipped_rules": ["x"]}).encode(),
            "semgrep_skipped_rules",
        ),
        (
            json.dumps(
                {
                    "results": [],
                    "errors": [],
                    "skipped_rules": [],
                    "paths": {"skipped": [{"path": "large.py"}]},
                }
            ).encode(),
            "semgrep_skipped_targets",
        ),
        (
            json.dumps({"errors": [], "skipped_rules": []}).encode(),
            "semgrep_results_missing",
        ),
    ],
)
def test_semgrep_report_fails_closed_for_incomplete_or_malformed_evidence(
    report: bytes,
    error: str,
) -> None:
    with pytest.raises(ValueError, match=error):
        parse_semgrep_report(report)


def test_bounded_runner_enforces_timeout(tmp_path: Path) -> None:
    context = ScannerContext(
        scan_id="timeout",
        timeout_seconds=1,
        max_output_bytes=4096,
    )
    outcome, raw = _run_bounded_semgrep(
        [sys.executable, "-c", "import time; time.sleep(5); print('{}')"],
        cwd=tmp_path,
        context=context,
    )
    assert outcome == "timeout"
    assert raw is None


def test_bounded_runner_enforces_output_limit(tmp_path: Path) -> None:
    context = ScannerContext(
        scan_id="output",
        timeout_seconds=10,
        max_output_bytes=1024,
    )
    outcome, raw = _run_bounded_semgrep(
        [sys.executable, "-c", "print('x' * 4096)"],
        cwd=tmp_path,
        context=context,
    )
    assert outcome == "output_limit"
    assert raw is None


def test_project_managed_semgrep_probe_is_exact_version() -> None:
    assert SEMGREP_EXE.is_file(), "setup must provision project-managed Semgrep"
    availability = SemgrepScanner().probe()
    assert availability.available is True
    assert availability.version == SEMGREP_VERSION
    assert availability.reason_code is None


def test_real_semgrep_scan_detects_mcp_command_execution_without_duplicate_generic_rule(
    tmp_path: Path,
) -> None:
    (tmp_path / "server.py").write_text(
        "import os\n"
        "class Dummy:\n"
        "    def tool(self):\n"
        "        return lambda fn: fn\n"
        "mcp = Dummy()\n"
        "@mcp.tool()\n"
        "def run(command):\n"
        "    os.system(command)\n",
        encoding="utf-8",
    )
    result = SemgrepScanner(max_target_bytes=1_000_000).scan(
        _workspace(tmp_path),
        ScannerContext(scan_id="real-vulnerable", timeout_seconds=30),
    )

    assert result.status == ScannerRunStatus.COMPLETED
    rule_ids = [finding.rule_id for finding in result.findings]
    assert "mcp.python.tool-os-system" in rule_ids
    assert "python.os-system" not in rule_ids
    assert all(finding.file_path == "server.py" for finding in result.findings)
    assert all(len(finding.fingerprint) == 64 for finding in result.findings)


def test_real_semgrep_scan_ignores_ancestor_git_discovery_and_completes(
    tmp_path: Path,
) -> None:
    git_root = tmp_path / "repo"
    nested = git_root / "nested" / "fixture"
    nested.mkdir(parents=True)
    (git_root / ".git").mkdir()
    (nested / "server.py").write_text(
        "def health_check():\n    return {'status': 'ok'}\n",
        encoding="utf-8",
    )

    result = SemgrepScanner(max_target_bytes=1_000_000).scan(
        _workspace(nested),
        ScannerContext(scan_id="nested-git-root", timeout_seconds=30),
    )

    assert result.status == ScannerRunStatus.COMPLETED
    assert result.findings == ()


def test_real_semgrep_scan_detects_javascript_dynamic_code_execution(
    tmp_path: Path,
) -> None:
    (tmp_path / "index.js").write_text(
        "function formatUserInput(value) {\n"
        "  return eval(value);\n"
        "}\n"
        "const build = new Function('x', 'return x + 1');\n",
        encoding="utf-8",
    )
    result = SemgrepScanner(max_target_bytes=1_000_000).scan(
        _workspace(tmp_path),
        ScannerContext(scan_id="javascript-code-execution", timeout_seconds=30),
    )

    assert result.status == ScannerRunStatus.COMPLETED
    rules = {finding.rule_id: finding for finding in result.findings}
    assert rules["javascript.dangerous-eval"].severity.value == "HIGH"
    assert rules["javascript.function-constructor"].severity.value == "HIGH"
    assert all(finding.category == "CODE_EXECUTION" for finding in rules.values())


def test_real_semgrep_scan_detects_asyncio_interpreter_code_execution(
    tmp_path: Path,
) -> None:
    (tmp_path / "server.py").write_text(
        "import asyncio\n"
        "import sys\n"
        "async def execute_code(code):\n"
        "    return await asyncio.create_subprocess_exec("
        "sys.executable, '-c', code, cwd='.')\n",
        encoding="utf-8",
    )
    result = SemgrepScanner(max_target_bytes=1_000_000).scan(
        _workspace(tmp_path),
        ScannerContext(scan_id="asyncio-code-execution", timeout_seconds=30),
    )

    assert result.status == ScannerRunStatus.COMPLETED
    matching = [
        finding
        for finding in result.findings
        if finding.rule_id == "python.asyncio-interpreter-c"
    ]
    assert len(matching) == 1
    assert matching[0].severity.value == "HIGH"
    assert matching[0].category == "CODE_EXECUTION"


def test_real_semgrep_scan_clean_fixture_has_no_findings(tmp_path: Path) -> None:
    (tmp_path / "server.py").write_text(
        "from pathlib import Path\n"
        "def read_config(path: str):\n"
        "    return Path(path).name\n",
        encoding="utf-8",
    )
    result = SemgrepScanner(max_target_bytes=1_000_000).scan(
        _workspace(tmp_path),
        ScannerContext(scan_id="real-clean", timeout_seconds=30),
    )

    assert result.status == ScannerRunStatus.COMPLETED
    assert result.findings == ()
