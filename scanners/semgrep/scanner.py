from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import time
from typing import Any
from uuid import uuid4

from app.core.runtime_paths import SEMGREP_EXE, SEMGREP_VERSION
from scanners.base import BuildScanner
from scanners.contracts import (
    FindingConfidence,
    FindingSeverity,
    NormalizedFinding,
    ScannerAvailability,
    ScannerContext,
    ScannerExecutionResult,
    ScannerRunStatus,
    ValidatedWorkspace,
)

SCANNER_ID = "semgrep"
RULES_PATH = Path(__file__).resolve().parent / "rules" / "mcp_security.yml"
DEFAULT_RULE_TIMEOUT_SECONDS = 5
DEFAULT_TIMEOUT_THRESHOLD = 1


def _semgrep_environment() -> dict[str, str]:
    env = dict(os.environ)
    for key in (
        "SEMGREP_APP_TOKEN",
        "SEMGREP_REPO_NAME",
        "SEMGREP_REPO_URL",
        "SEMGREP_JOB_URL",
        "SEMGREP_PR_ID",
    ):
        env.pop(key, None)
    if os.name == "nt":
        # Semgrep 1.175.0 exits with code 2 and "<ERROR: missing output>"
        # when TEMP/TMP point at the framework-managed runtime directory.
        # Removing these variables lets Windows select its normal per-user temp
        # directory without changing any scanner target or evidence boundary.
        for key in ("TEMP", "TMP", "TMPDIR"):
            env.pop(key, None)
    env["SEMGREP_SEND_METRICS"] = "off"
    env["SEMGREP_ENABLE_VERSION_CHECK"] = "0"
    env["GIT_TERMINAL_PROMPT"] = "0"
    return env


def _safe_version(executable: Path) -> str | None:
    if not executable.is_file():
        return None
    try:
        completed = subprocess.run(
            [str(executable), "--version"],
            cwd=executable.parent,
            env=_semgrep_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=20,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0 or len(completed.stdout or b"") > 65_536:
        return None
    lines = (completed.stdout or b"").decode("utf-8", errors="replace").strip().splitlines()
    return lines[-1].strip() if lines else None


def _terminate_process_tree(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    if os.name == "nt":
        taskkill = shutil.which("taskkill")
        if taskkill:
            subprocess.run(
                [taskkill, "/PID", str(process.pid), "/T", "/F"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
                check=False,
                shell=False,
            )
        if process.poll() is None:
            process.kill()
        return

    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (OSError, ProcessLookupError):
        process.kill()


def _run_bounded_semgrep(
    command: list[str],
    *,
    cwd: Path,
    context: ScannerContext,
) -> tuple[str, bytes | None]:
    control_dir = cwd.parent / ".scanner-control" / str(uuid4())
    control_dir.mkdir(parents=True, exist_ok=False)
    stdout_path = control_dir / "semgrep.json"
    stderr_path = control_dir / "semgrep.stderr"

    popen_kwargs: dict[str, Any] = {}
    if os.name == "nt":
        popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        popen_kwargs["start_new_session"] = True

    try:
        with stdout_path.open("wb") as stdout_handle, stderr_path.open("wb") as stderr_handle:
            try:
                process = subprocess.Popen(
                    command,
                    cwd=cwd,
                    env=_semgrep_environment(),
                    stdin=subprocess.DEVNULL,
                    stdout=stdout_handle,
                    stderr=stderr_handle,
                    shell=False,
                    **popen_kwargs,
                )
            except OSError:
                return "unavailable", None

            deadline = time.monotonic() + context.timeout_seconds
            while process.poll() is None:
                if time.monotonic() >= deadline:
                    _terminate_process_tree(process)
                    return "timeout", None
                try:
                    if (
                        stdout_path.stat().st_size > context.max_output_bytes
                        or stderr_path.stat().st_size > context.max_output_bytes
                    ):
                        _terminate_process_tree(process)
                        return "output_limit", None
                except OSError:
                    _terminate_process_tree(process)
                    return "io_error", None
                time.sleep(0.05)

            returncode = process.wait(timeout=10)

        try:
            if (
                stdout_path.stat().st_size > context.max_output_bytes
                or stderr_path.stat().st_size > context.max_output_bytes
            ):
                return "output_limit", None
            raw = stdout_path.read_bytes()
        except OSError:
            return "io_error", None

        if returncode != 0:
            return "nonzero_exit", None
        return "ok", raw
    finally:
        shutil.rmtree(control_dir, ignore_errors=True)


def _severity_from_result(extra: dict[str, Any]) -> FindingSeverity:
    metadata = extra.get("metadata")
    if isinstance(metadata, dict):
        configured = str(metadata.get("mcp_framework_severity", "")).upper()
        if configured in FindingSeverity.__members__:
            return FindingSeverity[configured]

    fallback = str(extra.get("severity", "")).upper()
    return {
        "ERROR": FindingSeverity.HIGH,
        "WARNING": FindingSeverity.MEDIUM,
        "INFO": FindingSeverity.LOW,
    }.get(fallback, FindingSeverity.MEDIUM)


def _confidence_from_result(extra: dict[str, Any]) -> FindingConfidence:
    metadata = extra.get("metadata")
    if isinstance(metadata, dict):
        configured = str(metadata.get("confidence", "")).upper()
        if configured in FindingConfidence.__members__:
            return FindingConfidence[configured]
    return FindingConfidence.MEDIUM


def _safe_references(metadata: dict[str, Any]) -> tuple[str, ...]:
    candidates: list[str] = []
    for key in ("references", "source-rule-url"):
        value = metadata.get(key)
        if isinstance(value, str):
            candidates.append(value)
        elif isinstance(value, list):
            candidates.extend(str(item) for item in value if isinstance(item, str))
    return tuple(item[:1000] for item in candidates[:50])


def _safe_metadata(metadata: dict[str, Any]) -> dict[str, Any]:
    safe: dict[str, Any] = {}
    for key in ("cwe", "owasp", "technology"):
        value = metadata.get(key)
        if isinstance(value, (str, int, float, bool, list, tuple)):
            safe[key] = value
    return safe


def _positive_int(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        return None
    return value


def parse_semgrep_report(raw: bytes) -> tuple[NormalizedFinding, ...]:
    if not raw:
        raise ValueError("semgrep_empty_output")
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("semgrep_invalid_json") from exc
    if not isinstance(document, dict):
        raise ValueError("semgrep_invalid_report")

    if document.get("errors"):
        raise ValueError("semgrep_reported_errors")
    if document.get("skipped_rules"):
        raise ValueError("semgrep_skipped_rules")
    paths = document.get("paths")
    if isinstance(paths, dict) and paths.get("skipped"):
        raise ValueError("semgrep_skipped_targets")

    results = document.get("results")
    if not isinstance(results, list):
        raise ValueError("semgrep_results_missing")

    findings: list[NormalizedFinding] = []
    for result in results:
        if not isinstance(result, dict):
            raise ValueError("semgrep_result_invalid")
        check_id = result.get("check_id")
        path = result.get("path")
        start = result.get("start")
        end = result.get("end")
        extra = result.get("extra")
        if (
            not isinstance(check_id, str)
            or not check_id.strip()
            or not isinstance(path, str)
            or not path.strip()
            or not isinstance(start, dict)
            or not isinstance(end, dict)
            or not isinstance(extra, dict)
        ):
            raise ValueError("semgrep_result_invalid")

        start_line = _positive_int(start.get("line"))
        end_line = _positive_int(end.get("line"))
        start_col = _positive_int(start.get("col"))
        end_col = _positive_int(end.get("col"))
        if start_line is None or end_line is None:
            raise ValueError("semgrep_result_invalid")

        metadata = extra.get("metadata")
        if metadata is None:
            metadata = {}
        if not isinstance(metadata, dict):
            raise ValueError("semgrep_result_invalid")

        category = str(metadata.get("mcp_framework_category") or "SAST").strip().upper()
        message = extra.get("message")
        title = str(message).strip() if isinstance(message, str) and message.strip() else check_id

        findings.append(
            NormalizedFinding.create(
                scanner_id=SCANNER_ID,
                rule_id=check_id,
                category=category,
                severity=_severity_from_result(extra),
                confidence=_confidence_from_result(extra),
                title=title,
                file_path=path,
                line_start=start_line,
                line_end=end_line,
                column_start=start_col,
                column_end=end_col,
                remediation=(
                    str(metadata["remediation"])[:4000]
                    if isinstance(metadata.get("remediation"), str)
                    else None
                ),
                references=_safe_references(metadata),
                safe_metadata=_safe_metadata(metadata),
            )
        )
    return tuple(findings)


class SemgrepScanner(BuildScanner):
    scanner_id = SCANNER_ID

    def __init__(
        self,
        *,
        executable: Path = SEMGREP_EXE,
        rules_path: Path = RULES_PATH,
        max_target_bytes: int = 100_000_000,
    ) -> None:
        self.executable = Path(executable)
        self.rules_path = Path(rules_path)
        self.max_target_bytes = max_target_bytes

    def probe(self) -> ScannerAvailability:
        if not self.rules_path.is_file():
            return ScannerAvailability(
                available=False,
                scanner_id=self.scanner_id,
                reason_code="semgrep_rule_pack_missing",
            )
        version = _safe_version(self.executable)
        if version is None:
            return ScannerAvailability(
                available=False,
                scanner_id=self.scanner_id,
                reason_code="semgrep_unavailable",
            )
        if version != SEMGREP_VERSION:
            return ScannerAvailability(
                available=False,
                scanner_id=self.scanner_id,
                version=version,
                reason_code="semgrep_version_mismatch",
            )
        return ScannerAvailability(
            available=True,
            scanner_id=self.scanner_id,
            version=version,
        )

    def command_for(self, workspace: ValidatedWorkspace) -> list[str]:
        return [
            str(self.executable),
            "scan",
            "--json",
            "--metrics=off",
            "--disable-version-check",
            "--no-rewrite-rule-ids",
            "--quiet",
            "--jobs=1",
            f"--timeout={DEFAULT_RULE_TIMEOUT_SECONDS}",
            f"--timeout-threshold={DEFAULT_TIMEOUT_THRESHOLD}",
            f"--max-target-bytes={self.max_target_bytes}",
            "--project-root",
            ".",
            "--no-git-ignore",
            "--config",
            str(self.rules_path.resolve(strict=True)),
            ".",
        ]

    def scan(
        self,
        workspace: ValidatedWorkspace,
        context: ScannerContext,
    ) -> ScannerExecutionResult:
        availability = self.probe()
        if not availability.available:
            return ScannerExecutionResult(
                scanner_id=self.scanner_id,
                status=ScannerRunStatus.UNAVAILABLE,
                scanner_version=availability.version,
                error_code=availability.reason_code or "semgrep_unavailable",
            )

        try:
            command = self.command_for(workspace)
        except (OSError, RuntimeError):
            return ScannerExecutionResult(
                scanner_id=self.scanner_id,
                status=ScannerRunStatus.UNAVAILABLE,
                scanner_version=availability.version,
                error_code="semgrep_rule_pack_missing",
            )

        outcome, raw = _run_bounded_semgrep(
            command,
            cwd=workspace.root,
            context=context,
        )
        if outcome == "timeout":
            return ScannerExecutionResult(
                scanner_id=self.scanner_id,
                status=ScannerRunStatus.TIMED_OUT,
                scanner_version=availability.version,
                error_code="semgrep_timeout",
            )
        if outcome == "unavailable":
            return ScannerExecutionResult(
                scanner_id=self.scanner_id,
                status=ScannerRunStatus.UNAVAILABLE,
                scanner_version=availability.version,
                error_code="semgrep_unavailable",
            )
        if outcome != "ok" or raw is None:
            return ScannerExecutionResult(
                scanner_id=self.scanner_id,
                status=ScannerRunStatus.FAILED,
                scanner_version=availability.version,
                error_code=f"semgrep_{outcome}",
            )

        try:
            findings = parse_semgrep_report(raw)
        except ValueError as exc:
            return ScannerExecutionResult(
                scanner_id=self.scanner_id,
                status=ScannerRunStatus.FAILED,
                scanner_version=availability.version,
                error_code=str(exc),
            )

        return ScannerExecutionResult(
            scanner_id=self.scanner_id,
            status=ScannerRunStatus.COMPLETED,
            findings=findings,
            scanner_version=availability.version,
        )
