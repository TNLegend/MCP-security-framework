from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import time
from typing import Any
from uuid import uuid4

from app.core.config import settings
from app.core.runtime_paths import (
    TRIVY_CACHE_DIR,
    TRIVY_DOCKER_CONFIG_DIR,
    TRIVY_EXE,
    TRIVY_VERSION,
)
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

SCANNER_ID = "trivy"


def _trivy_environment() -> dict[str, str]:
    env = dict(os.environ)
    for key in list(env):
        if key.startswith("TRIVY_"):
            env.pop(key, None)
    for key in (
        "DOCKER_AUTH_CONFIG",
        "REGISTRY_AUTH_FILE",
    ):
        env.pop(key, None)
    TRIVY_DOCKER_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    config = TRIVY_DOCKER_CONFIG_DIR / "config.json"
    if not config.is_file():
        config.write_text("{}\n", encoding="utf-8")
    env["DOCKER_CONFIG"] = str(TRIVY_DOCKER_CONFIG_DIR)
    env["GIT_TERMINAL_PROMPT"] = "0"
    return env


def _safe_version(executable: Path) -> str | None:
    if not executable.is_file():
        return None
    try:
        completed = subprocess.run(
            [str(executable), "--version"],
            cwd=executable.parent,
            env=_trivy_environment(),
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
    for line in (completed.stdout or b"").decode("utf-8", errors="replace").splitlines():
        if line.startswith("Version:"):
            return line.split(":", 1)[1].strip()
    return None


def _metadata_datetime(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _database_available(*, now: datetime | None = None) -> bool:
    database = TRIVY_CACHE_DIR / "db" / "trivy.db"
    metadata = TRIVY_CACHE_DIR / "db" / "metadata.json"
    if not database.is_file() or database.stat().st_size < 1_000_000 or not metadata.is_file():
        return False
    try:
        parsed = json.loads(metadata.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    if not isinstance(parsed, dict):
        return False

    updated_at = _metadata_datetime(parsed.get("UpdatedAt"))
    if updated_at is None:
        updated_at = _metadata_datetime(parsed.get("DownloadedAt"))
    if updated_at is None:
        return False

    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    else:
        current = current.astimezone(timezone.utc)
    age = current - updated_at
    if age < timedelta(minutes=-5):
        return False
    return age <= timedelta(hours=settings.build_scan_trivy_db_max_age_hours)


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


def _trivy_command(
    executable: Path,
    *,
    workspace: ValidatedWorkspace,
    report_path: Path,
    ignore_path: Path,
    context: ScannerContext,
) -> list[str]:
    return [
        str(executable),
        "filesystem",
        "--scanners",
        "vuln",
        "--pkg-types",
        "library",
        "--include-dev-deps",
        "--format",
        "json",
        "--output",
        str(report_path),
        "--cache-dir",
        str(TRIVY_CACHE_DIR),
        "--skip-db-update",
        "--skip-java-db-update",
        "--offline-scan",
        "--ignorefile",
        str(ignore_path),
        "--quiet",
        "--skip-version-check",
        "--parallel",
        "1",
        "--timeout",
        f"{context.timeout_seconds}s",
        str(workspace.root.resolve(strict=True)),
    ]


def _run_bounded_trivy(
    executable: Path,
    *,
    workspace: ValidatedWorkspace,
    context: ScannerContext,
) -> tuple[str, bytes | None]:
    control_dir = workspace.root.parent / ".trivy-control" / str(uuid4())
    control_dir.mkdir(parents=True, exist_ok=False)
    report_path = control_dir / "report.json"
    ignore_path = control_dir / ".trivyignore"
    stdout_path = control_dir / "stdout.log"
    stderr_path = control_dir / "stderr.log"
    ignore_path.write_text("", encoding="utf-8")
    command = _trivy_command(
        executable,
        workspace=workspace,
        report_path=report_path,
        ignore_path=ignore_path,
        context=context,
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
                    env=_trivy_environment(),
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


def _safe_relative_target(value: str, workspace_root: Path) -> str:
    raw = value.strip()
    if not raw:
        raise ValueError("trivy_result_invalid")
    candidate = Path(raw)
    if candidate.is_absolute():
        try:
            resolved = candidate.resolve(strict=False)
        except (OSError, RuntimeError) as exc:
            raise ValueError("trivy_result_path_invalid") from exc
        if not is_path_within(resolved, workspace_root):
            raise ValueError("trivy_result_path_escape")
        return resolved.relative_to(workspace_root).as_posix()

    normalized = raw.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    parts = Path(normalized).parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise ValueError("trivy_result_path_invalid")
    return Path(*parts).as_posix()


def _severity(value: Any) -> FindingSeverity:
    normalized = str(value or "UNKNOWN").upper()
    if normalized == "CRITICAL":
        return FindingSeverity.CRITICAL
    if normalized == "HIGH":
        return FindingSeverity.HIGH
    if normalized == "MEDIUM":
        return FindingSeverity.MEDIUM
    if normalized == "LOW":
        return FindingSeverity.LOW
    return FindingSeverity.MEDIUM


def _references(vulnerability: dict[str, Any]) -> tuple[str, ...]:
    values: list[str] = []
    primary = vulnerability.get("PrimaryURL")
    if isinstance(primary, str) and primary.strip():
        values.append(primary.strip())
    refs = vulnerability.get("References")
    if isinstance(refs, list):
        values.extend(item.strip() for item in refs if isinstance(item, str) and item.strip())
    unique: list[str] = []
    for value in values:
        if value not in unique:
            unique.append(value[:1000])
        if len(unique) >= 50:
            break
    return tuple(unique)


def parse_trivy_report(
    raw: bytes,
    *,
    workspace_root: Path,
) -> tuple[NormalizedFinding, ...]:
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("trivy_invalid_json") from exc
    if not isinstance(document, dict):
        raise ValueError("trivy_invalid_report")
    if document.get("SchemaVersion") != 2:
        raise ValueError("trivy_schema_unsupported")

    results = document.get("Results")
    if results is None:
        return ()
    if not isinstance(results, list):
        raise ValueError("trivy_results_invalid")

    findings: list[NormalizedFinding] = []
    for result in results:
        if not isinstance(result, dict):
            raise ValueError("trivy_result_invalid")
        target = result.get("Target")
        if not isinstance(target, str) or not target.strip():
            raise ValueError("trivy_result_invalid")
        file_path = _safe_relative_target(target, workspace_root)
        vulnerabilities = result.get("Vulnerabilities")
        if vulnerabilities is None:
            continue
        if not isinstance(vulnerabilities, list):
            raise ValueError("trivy_vulnerabilities_invalid")

        result_type = result.get("Type")
        result_class = result.get("Class")
        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, dict):
                raise ValueError("trivy_vulnerability_invalid")
            vulnerability_id = vulnerability.get("VulnerabilityID")
            package_name = vulnerability.get("PkgName")
            installed_version = vulnerability.get("InstalledVersion")
            if (
                not isinstance(vulnerability_id, str)
                or not vulnerability_id.strip()
                or not isinstance(package_name, str)
                or not package_name.strip()
                or not isinstance(installed_version, str)
                or not installed_version.strip()
            ):
                raise ValueError("trivy_vulnerability_invalid")

            fixed_version = vulnerability.get("FixedVersion")
            if not isinstance(fixed_version, str) or not fixed_version.strip():
                fixed_version = None
            title = vulnerability.get("Title")
            if not isinstance(title, str) or not title.strip():
                title = f"{vulnerability_id.strip()} affects {package_name.strip()}"

            remediation = (
                f"Upgrade {package_name.strip()} from {installed_version.strip()} "
                f"to a fixed version ({fixed_version})."
                if fixed_version
                else f"Review and remediate {vulnerability_id.strip()} affecting {package_name.strip()}."
            )
            safe_metadata: dict[str, Any] = {
                "trivy_severity": str(vulnerability.get("Severity") or "UNKNOWN").upper(),
            }
            if isinstance(result_type, str) and result_type:
                safe_metadata["package_type"] = result_type[:128]
            if isinstance(result_class, str) and result_class:
                safe_metadata["result_class"] = result_class[:128]

            findings.append(
                NormalizedFinding.create(
                    scanner_id=SCANNER_ID,
                    rule_id=vulnerability_id.strip(),
                    category="DEPENDENCY_VULNERABILITY",
                    severity=_severity(vulnerability.get("Severity")),
                    confidence=FindingConfidence.HIGH,
                    title=title.strip()[:1000],
                    file_path=file_path,
                    vulnerability_id=vulnerability_id.strip(),
                    package_name=package_name.strip(),
                    package_version=installed_version.strip(),
                    fixed_version=fixed_version,
                    remediation=remediation,
                    references=_references(vulnerability),
                    safe_metadata=safe_metadata,
                )
            )
    return tuple(findings)


class TrivyScanner(BuildScanner):
    scanner_id = SCANNER_ID

    def __init__(self, *, executable: Path = TRIVY_EXE) -> None:
        self.executable = Path(executable)

    def probe(self) -> ScannerAvailability:
        version = _safe_version(self.executable)
        if version is None:
            return ScannerAvailability(
                available=False,
                scanner_id=self.scanner_id,
                reason_code="trivy_unavailable",
            )
        if version != TRIVY_VERSION:
            return ScannerAvailability(
                available=False,
                scanner_id=self.scanner_id,
                version=version,
                reason_code="trivy_version_mismatch",
            )
        if not _database_available():
            return ScannerAvailability(
                available=False,
                scanner_id=self.scanner_id,
                version=version,
                reason_code="trivy_database_missing",
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
                error_code=availability.reason_code or "trivy_unavailable",
            )

        outcome, raw = _run_bounded_trivy(
            self.executable,
            workspace=workspace,
            context=context,
        )
        if outcome == "timeout":
            return ScannerExecutionResult(
                scanner_id=self.scanner_id,
                status=ScannerRunStatus.TIMED_OUT,
                scanner_version=availability.version,
                error_code="trivy_timeout",
            )
        if outcome == "unavailable":
            return ScannerExecutionResult(
                scanner_id=self.scanner_id,
                status=ScannerRunStatus.UNAVAILABLE,
                scanner_version=availability.version,
                error_code="trivy_unavailable",
            )
        if outcome != "ok" or raw is None:
            return ScannerExecutionResult(
                scanner_id=self.scanner_id,
                status=ScannerRunStatus.FAILED,
                scanner_version=availability.version,
                error_code=f"trivy_{outcome}",
            )

        try:
            findings = parse_trivy_report(raw, workspace_root=workspace.root)
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
