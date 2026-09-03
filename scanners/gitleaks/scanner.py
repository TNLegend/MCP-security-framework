from __future__ import annotations

import json
import math
import os
from pathlib import Path
import shutil
import signal
import subprocess
import time
from typing import Any
from uuid import uuid4

from app.core.runtime_paths import GITLEAKS_EXE, GITLEAKS_VERSION
from common.project_paths import is_path_within
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

SCANNER_ID = "gitleaks"
CONFIG_PATH = Path(__file__).resolve().parent / "config.toml"
_DEFAULT_REMEDIATION = (
    "Revoke or rotate the exposed credential, remove it from source and history where "
    "applicable, and replace it with an approved secret-management reference."
)


def _gitleaks_environment() -> dict[str, str]:
    env = dict(os.environ)
    for key in (
        "GITLEAKS_CONFIG",
        "GITLEAKS_CONFIG_TOML",
    ):
        env.pop(key, None)
    env["GIT_TERMINAL_PROMPT"] = "0"
    return env


def _safe_version(executable: Path) -> str | None:
    if not executable.is_file():
        return None
    try:
        completed = subprocess.run(
            [str(executable), "version"],
            cwd=executable.parent,
            env=_gitleaks_environment(),
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


def _gitleaks_command(
    executable: Path,
    *,
    config_path: Path,
    report_path: Path,
    ignore_path: Path,
    context: ScannerContext,
    max_target_bytes: int,
    target_path: Path,
) -> list[str]:
    max_target_megabytes = max(1, math.ceil(max_target_bytes / (1024 * 1024)))
    return [
        str(executable),
        "dir",
        "--no-banner",
        "--no-color",
        "--redact=100",
        "--exit-code=0",
        "--report-format=json",
        f"--report-path={report_path}",
        f"--config={config_path.resolve(strict=True)}",
        f"--gitleaks-ignore-path={ignore_path}",
        "--ignore-gitleaks-allow",
        "--max-archive-depth=0",
        "--max-decode-depth=0",
        f"--max-target-megabytes={max_target_megabytes}",
        f"--timeout={context.timeout_seconds}",
        str(target_path.resolve(strict=True)),
    ]


def _run_bounded_gitleaks(
    executable: Path,
    *,
    config_path: Path,
    workspace: ValidatedWorkspace,
    context: ScannerContext,
    max_target_bytes: int,
) -> tuple[str, bytes | None]:
    control_dir = workspace.root.parent / ".gitleaks-control" / str(uuid4())
    control_dir.mkdir(parents=True, exist_ok=False)
    report_path = control_dir / "report.json"
    stdout_path = control_dir / "stdout.log"
    stderr_path = control_dir / "stderr.log"
    ignore_path = control_dir / ".gitleaksignore"
    ignore_path.write_text("", encoding="utf-8")
    command = _gitleaks_command(
        executable,
        config_path=config_path,
        report_path=report_path,
        ignore_path=ignore_path,
        context=context,
        max_target_bytes=max_target_bytes,
        target_path=workspace.root,
    )

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
                    cwd=control_dir,
                    env=_gitleaks_environment(),
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
                    report_size = report_path.stat().st_size if report_path.exists() else 0
                    if (
                        report_size > context.max_output_bytes
                        or stdout_path.stat().st_size > context.max_output_bytes
                        or stderr_path.stat().st_size > context.max_output_bytes
                    ):
                        _terminate_process_tree(process)
                        return "output_limit", None
                except OSError:
                    _terminate_process_tree(process)
                    return "io_error", None
                time.sleep(0.05)

            returncode = process.wait(timeout=10)

        if returncode != 0:
            return "nonzero_exit", None
        if not report_path.is_file():
            return "report_missing", None
        try:
            if (
                report_path.stat().st_size > context.max_output_bytes
                or stdout_path.stat().st_size > context.max_output_bytes
                or stderr_path.stat().st_size > context.max_output_bytes
            ):
                return "output_limit", None
            return "ok", report_path.read_bytes()
        except OSError:
            return "io_error", None
    finally:
        shutil.rmtree(control_dir, ignore_errors=True)


def _safe_relative_path(value: str, workspace_root: Path) -> str:
    raw = value.strip()
    if not raw:
        raise ValueError("gitleaks_result_invalid")
    candidate = Path(raw)
    if candidate.is_absolute():
        try:
            resolved = candidate.resolve(strict=False)
        except (OSError, RuntimeError) as exc:
            raise ValueError("gitleaks_result_path_invalid") from exc
        if not is_path_within(resolved, workspace_root):
            raise ValueError("gitleaks_result_path_escape")
        relative = resolved.relative_to(workspace_root).as_posix()
    else:
        normalized = raw.replace("\\", "/")
        while normalized.startswith("./"):
            normalized = normalized[2:]
        parts = Path(normalized).parts
        if not parts or any(part in {"", ".", ".."} for part in parts):
            raise ValueError("gitleaks_result_path_invalid")
        relative = Path(*parts).as_posix()
    return relative


def _positive_int(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        return None
    return value


def parse_gitleaks_report(
    raw: bytes,
    *,
    workspace_root: Path,
) -> tuple[NormalizedFinding, ...]:
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("gitleaks_invalid_json") from exc
    if not isinstance(document, list):
        raise ValueError("gitleaks_invalid_report")

    findings: list[NormalizedFinding] = []
    for item in document:
        if not isinstance(item, dict):
            raise ValueError("gitleaks_result_invalid")

        rule_id = item.get("RuleID")
        file_path = item.get("File")
        start_line = _positive_int(item.get("StartLine"))
        end_line = _positive_int(item.get("EndLine"))
        start_column = _positive_int(item.get("StartColumn"))
        end_column = _positive_int(item.get("EndColumn"))
        if (
            not isinstance(rule_id, str)
            or not rule_id.strip()
            or not isinstance(file_path, str)
            or start_line is None
            or end_line is None
        ):
            raise ValueError("gitleaks_result_invalid")

        normalized_path = _safe_relative_path(file_path, workspace_root)
        description = item.get("Description")
        title = (
            str(description).strip()[:1000]
            if isinstance(description, str) and description.strip()
            else f"Potential secret detected by {rule_id.strip()}"
        )

        safe_metadata: dict[str, Any] = {}
        entropy = item.get("Entropy")
        if isinstance(entropy, (int, float)) and not isinstance(entropy, bool):
            safe_metadata["entropy"] = float(entropy)
        tags = item.get("Tags")
        if isinstance(tags, list):
            safe_metadata["tags"] = [
                str(tag)[:128]
                for tag in tags[:50]
                if isinstance(tag, (str, int, float, bool))
            ]

        findings.append(
            NormalizedFinding.create(
                scanner_id=SCANNER_ID,
                rule_id=rule_id.strip(),
                category="SECRET",
                severity=FindingSeverity.CRITICAL,
                confidence=FindingConfidence.HIGH,
                title=title,
                file_path=normalized_path,
                line_start=start_line,
                line_end=end_line,
                column_start=start_column,
                column_end=end_column,
                remediation=_DEFAULT_REMEDIATION,
                safe_metadata=safe_metadata,
            )
        )
    return tuple(findings)


class GitleaksScanner(BuildScanner):
    scanner_id = SCANNER_ID

    def __init__(
        self,
        *,
        executable: Path = GITLEAKS_EXE,
        config_path: Path = CONFIG_PATH,
        max_target_bytes: int = 100_000_000,
    ) -> None:
        self.executable = Path(executable)
        self.config_path = Path(config_path)
        self.max_target_bytes = max_target_bytes

    def probe(self) -> ScannerAvailability:
        if not self.config_path.is_file():
            return ScannerAvailability(
                available=False,
                scanner_id=self.scanner_id,
                reason_code="gitleaks_config_missing",
            )
        version = _safe_version(self.executable)
        if version is None:
            return ScannerAvailability(
                available=False,
                scanner_id=self.scanner_id,
                reason_code="gitleaks_unavailable",
            )
        if version != GITLEAKS_VERSION:
            return ScannerAvailability(
                available=False,
                scanner_id=self.scanner_id,
                version=version,
                reason_code="gitleaks_version_mismatch",
            )
        return ScannerAvailability(
            available=True,
            scanner_id=self.scanner_id,
            version=version,
        )

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
                error_code=availability.reason_code or "gitleaks_unavailable",
            )

        outcome, raw = _run_bounded_gitleaks(
            self.executable,
            config_path=self.config_path,
            workspace=workspace,
            context=context,
            max_target_bytes=self.max_target_bytes,
        )
        if outcome == "timeout":
            return ScannerExecutionResult(
                scanner_id=self.scanner_id,
                status=ScannerRunStatus.TIMED_OUT,
                scanner_version=availability.version,
                error_code="gitleaks_timeout",
            )
        if outcome == "unavailable":
            return ScannerExecutionResult(
                scanner_id=self.scanner_id,
                status=ScannerRunStatus.UNAVAILABLE,
                scanner_version=availability.version,
                error_code="gitleaks_unavailable",
            )
        if outcome != "ok" or raw is None:
            return ScannerExecutionResult(
                scanner_id=self.scanner_id,
                status=ScannerRunStatus.FAILED,
                scanner_version=availability.version,
                error_code=f"gitleaks_{outcome}",
            )

        try:
            findings = parse_gitleaks_report(raw, workspace_root=workspace.root)
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
