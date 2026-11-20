"""Bounded, local Terraform ZIP scans for Deploy Security.

The uploaded source is transient and never inserted in PostgreSQL. Only
normalized rule IDs, source fingerprints, safe paths and evidence digests
are retained. These scanners do not apply Terraform or mutate AWS.
"""
from __future__ import annotations

import hashlib
import io
import json
import logging
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import time
from datetime import datetime
from threading import BoundedSemaphore
from concurrent.futures import ThreadPoolExecutor
from uuid import UUID
from zipfile import BadZipFile, ZipFile

from sqlalchemy import select

from app.core.runtime_paths import (
    CHECKOV_EXE, CHECKOV_PYTHON, CHECKOV_VERSION, RUNTIME_TMP_DIR, TRIVY_CACHE_DIR, TRIVY_EXE,
    TRIVY_VERSION,
)
from app.db.database import SessionLocal
from app.models.cloud_security import (
    CloudEvidence, CloudFinding, CloudResource, CloudScan, CloudScanEvent, new_id,
)
from scanners.trivy.scanner import _terminate_process_tree

log = logging.getLogger(__name__)
IAC_VERSION = "iac-config-v1"
IAC_ROOT = RUNTIME_TMP_DIR / "cloud-iac"
MAX_ZIP_BYTES = 2 * 1024 * 1024
MAX_SOURCE_BYTES = 8 * 1024 * 1024
MAX_FILE_BYTES = 512 * 1024
MAX_FILE_COUNT = 60
MAX_SCANNER_OUTPUT = 6 * 1024 * 1024
MAX_REPORTED_FINDINGS = 250
SCANNER_TIMEOUT = 90
_IAC_POOL = ThreadPoolExecutor(max_workers=2, thread_name_prefix="cloud-iac")
_IAC_CAPACITY = BoundedSemaphore(2)
_VALID_PATH_PART = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,79}$")
_VALID_RULE = re.compile(r"^[A-Za-z0-9_.:-]{3,96}$")
_FORBIDDEN_MODULE = re.compile(r"\bmodule\b", re.IGNORECASE)

# Verified equivalent checks: same logical SG description requirement.
# Only merge when the logical Terraform resource hashes also match.
_EQUIVALENT_RULES = {
    ("checkov", "CKV_AWS_23"): "AWS_SG_DESCRIPTION",
    ("trivy", "AWS-0099"): "AWS_SG_DESCRIPTION",
}
_REMEDIATIONS = {
    "CKV_AWS_23": (
        "Security group description is missing.",
        "Add meaningful descriptions to the security group and its rules.",
    ),
    "AWS-0099": (
        "Security group description is missing.",
        "Add meaningful descriptions to the security group and its rules.",
    ),
    "CKV_AWS_24": (
        "Security group permits SSH access from the internet.",
        "Restrict TCP port 22 to trusted networks or use AWS Systems Manager.",
    ),
    "AWS-0107": (
        "Security group allows unrestricted SSH or RDP ingress.",
        "Restrict administrative ports to trusted networks or use private access.",
    ),
}



class IaCIntakeError(ValueError):
    pass


def _sha(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()


def _safe_name(raw: str) -> str:
    if not raw or len(raw) > 220 or "\\" in raw or "\x00" in raw or ":" in raw:
        raise IaCIntakeError("IAC_UNSAFE_ARCHIVE_PATH")
    if raw.startswith("/") or raw.startswith("./") or raw.endswith("/"):
        raise IaCIntakeError("IAC_UNSAFE_ARCHIVE_PATH")
    parts = PurePosixPath(raw).parts
    if len(parts) > 8 or not parts or any(
        part in (".", "..") or not _VALID_PATH_PART.fullmatch(part)
        or part.endswith(".") or part.split(".")[0].upper() in
        {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)),
         *(f"LPT{i}" for i in range(1, 10))}
        for part in parts
    ):
        raise IaCIntakeError("IAC_UNSAFE_ARCHIVE_PATH")
    if not (raw.endswith(".tf") or raw.endswith(".tf.json")):
        raise IaCIntakeError("IAC_UNSUPPORTED_FILE")
    return "/".join(parts)


def _module_free(filename: str, content: bytes) -> None:
    try:
        value = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise IaCIntakeError("IAC_INVALID_SOURCE_ENCODING") from exc
    # Deliberately scan only root modules in v1. Imported module sources can
    # trigger network fetches or evaluation of untrusted linked directories.
    if filename.endswith(".tf.json"):
        try:
            document = json.loads(value)
        except json.JSONDecodeError as exc:
            raise IaCIntakeError("IAC_INVALID_TERRAFORM_JSON") from exc
        if not isinstance(document, dict) or "module" in document:
            raise IaCIntakeError("IAC_MODULES_UNSUPPORTED")
    elif _FORBIDDEN_MODULE.search(value):
        raise IaCIntakeError("IAC_MODULES_UNSUPPORTED")
    if re.search(r"(?i)(?:checkov\s*:\s*skip|trivy\s*:\s*ignore)", value):
        raise IaCIntakeError("IAC_SUPPRESSION_UNSUPPORTED")


def stage_archive(raw: bytes, scan_id: str) -> tuple[str, int]:
    """Validate before writing, then place only allowlisted files in a private dir."""
    if not (0 < len(raw) <= MAX_ZIP_BYTES):
        raise IaCIntakeError("IAC_ARCHIVE_SIZE_INVALID")
    try:
        UUID(scan_id)
    except ValueError as exc:
        raise IaCIntakeError("IAC_SCAN_ID_INVALID") from exc

    files: list[tuple[str, bytes]] = []
    seen: set[str] = set()
    total = 0
    try:
        with ZipFile(io.BytesIO(raw)) as archive:
            for info in archive.infolist():
                if info.is_dir():
                    continue
                # Reject symlinks even if archive came from a Unix host.
                if stat.S_ISLNK((info.external_attr >> 16) & 0xFFFF):
                    raise IaCIntakeError("IAC_LINK_NOT_ALLOWED")
                name = _safe_name(info.filename)
                if name.casefold() in seen:
                    raise IaCIntakeError("IAC_DUPLICATE_PATH")
                seen.add(name.casefold())
                if len(seen) > MAX_FILE_COUNT or info.file_size > MAX_FILE_BYTES:
                    raise IaCIntakeError("IAC_SOURCE_LIMIT")
                if info.file_size > max(info.compress_size, 1) * 200:
                    raise IaCIntakeError("IAC_ARCHIVE_COMPRESSION_LIMIT")
                total += info.file_size
                if total > MAX_SOURCE_BYTES:
                    raise IaCIntakeError("IAC_SOURCE_LIMIT")
                with archive.open(info) as f:
                    data = f.read(MAX_FILE_BYTES + 1)
                if len(data) != info.file_size:
                    raise IaCIntakeError("IAC_SOURCE_LIMIT")
                _module_free(name, data)
                files.append((name, data))
    except (BadZipFile, OSError, RuntimeError) as exc:
        raise IaCIntakeError("IAC_INVALID_ARCHIVE") from exc
    if not files:
        raise IaCIntakeError("IAC_NO_TERRAFORM_FILES")
    fingerprint = _sha([
        {"path": name, "sha256": hashlib.sha256(data).hexdigest()}
        for name, data in sorted(files)
    ])
    target = IAC_ROOT / scan_id
    IAC_ROOT.mkdir(parents=True, exist_ok=True)
    try:
        target.mkdir(mode=0o700, exist_ok=False)
        source = target / "source"
        source.mkdir(mode=0o700)
        for name, data in files:
            path = source.joinpath(*PurePosixPath(name).parts)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
    except Exception:
        shutil.rmtree(target, ignore_errors=True)
        raise
    return fingerprint, len(files)


def discard_source(scan_id: str) -> None:
    try:
        UUID(scan_id)
    except ValueError:
        return
    shutil.rmtree(IAC_ROOT / scan_id, ignore_errors=True)


def _isolated_env(control_dir: Path) -> dict[str, str]:
    # Never pass AWS/cloud credentials, service auth, or provider settings into
    # scanners. Proxy values fail closed for normal HTTP(S) traffic. This is
    # defense in depth, NOT an OS-enforced network sandbox.
    retained = {"PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "LANG", "LC_ALL"}
    env = {key: val for key, val in os.environ.items() if key.upper() in retained}
    env.update({
        "HOME": str(control_dir),
        "USERPROFILE": str(control_dir),
        "XDG_CONFIG_HOME": str(control_dir),
        "TMP": str(control_dir), "TEMP": str(control_dir), "TMPDIR": str(control_dir),
        "DOCKER_CONFIG": str(control_dir),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "HTTP_PROXY": "http://127.0.0.1:9",
        "HTTPS_PROXY": "http://127.0.0.1:9",
        "ALL_PROXY": "http://127.0.0.1:9",
        "NO_PROXY": "localhost,127.0.0.1",
        "CHECKOV_ENABLE_TELEMETRY": "false",
        "DOWNLOAD_EXTERNAL_MODULES": "false",
        "BC_SKIP_MAPPING": "true",
    })
    return env


def _version(executable: Path, expected: str | None = None) -> str | None:
    if not executable.is_file():
        return None
    try:
        c = subprocess.run([str(executable), "--version"], cwd=executable.parent,
                           env=_isolated_env(executable.parent), shell=False,
                           stdin=subprocess.DEVNULL, capture_output=True, timeout=20)
        if c.returncode or len(c.stdout) > 10000:
            return None
        text = c.stdout.decode("utf-8", "replace")
        match = re.search(r"(?m)(?:Version:\s*)?(\d+\.\d+\.\d+)", text)
        value = match.group(1) if match else None
        return value if value and (expected is None or value == expected) else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def _checkov_version() -> str | None:
    if not CHECKOV_PYTHON.is_file() or not CHECKOV_EXE.is_file():
        return None
    try:
        c = subprocess.run(
            [str(CHECKOV_PYTHON), "-c",
             "import importlib.metadata;print(importlib.metadata.version('checkov'))"],
            cwd=CHECKOV_PYTHON.parent, env=_isolated_env(CHECKOV_PYTHON.parent),
            stdin=subprocess.DEVNULL, capture_output=True, shell=False, timeout=15,
        )
        return CHECKOV_VERSION if c.returncode == 0 and (
            c.stdout.decode("utf-8", "replace").strip() == CHECKOV_VERSION
        ) else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def scanner_availability() -> list[dict]:
    return [
        {"scanner": "trivy", "available": _version(TRIVY_EXE, TRIVY_VERSION) is not None,
         "expected_version": TRIVY_VERSION},
        {"scanner": "checkov", "available": _checkov_version() is not None,
         "expected_version": CHECKOV_VERSION},
    ]


def _safe_path(value: object, source: Path, *, checkov_project_path: bool = False) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("IAC_RESULT_PATH_INVALID")
    value = value.replace("\\", "/")
    if value.startswith("//"):
        raise ValueError("IAC_RESULT_PATH_INVALID")
    candidate = Path(value)
    if candidate.is_absolute():
        try:
            relative = candidate.resolve(strict=False).relative_to(source.resolve())
        except (OSError, ValueError):
            # Checkov's JSON convention uses /main.tf for project-relative files.
            # That convention is not accepted for Trivy or other scanner outputs.
            if not checkov_project_path or not value.startswith("/"):
                raise ValueError("IAC_RESULT_PATH_INVALID") from None
            relative = PurePosixPath(value[1:])
    elif value.startswith("/"):
        if not checkov_project_path:
            raise ValueError("IAC_RESULT_PATH_INVALID")
        relative = PurePosixPath(value[1:])
    else:
        relative = PurePosixPath(value)
    name = relative.as_posix()
    try:
        _safe_name(name)
    except IaCIntakeError as exc:
        raise ValueError("IAC_RESULT_PATH_INVALID") from exc
    if not (source / name).is_file():
        raise ValueError("IAC_RESULT_PATH_INVALID")
    return name


def _logical_resource_hash(value: object) -> str | None:
    if not isinstance(value, str) or len(value) > 255:
        return None
    # Do not persist raw Terraform resource names from third-party reports.
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.\[\]-]+", value):
        return None
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:20]


def _rule(value: object) -> str:
    if not isinstance(value, str) or not _VALID_RULE.fullmatch(value):
        raise ValueError("IAC_RESULT_RULE_INVALID")
    return value


def _normalize_checkov(report: bytes, source: Path) -> list[dict]:
    doc = json.loads(report.decode("utf-8"))
    if isinstance(doc, list) and len(doc) == 1:
        doc = doc[0]
    if not isinstance(doc, dict) or not isinstance(doc.get("results"), dict):
        raise ValueError("IAC_CHECKOV_REPORT_INVALID")
    failed = doc["results"].get("failed_checks")
    if not isinstance(failed, list):
        raise ValueError("IAC_CHECKOV_REPORT_INVALID")
    normalized = []
    for item in failed[:MAX_REPORTED_FINDINGS + 1]:
        if not isinstance(item, dict):
            raise ValueError("IAC_CHECKOV_REPORT_INVALID")
        path = _safe_path(item.get("file_path"), source, checkov_project_path=True)
        rule = _rule(item.get("check_id"))
        resource_hash = hashlib.sha256(str(item.get("resource", "")).encode()).hexdigest()[:16]
        logical_resource_hash = _logical_resource_hash(item.get("resource"))
        sev = item.get("severity")
        severity = str(sev).upper() if sev is not None else "UNKNOWN"
        if severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
            severity = "UNKNOWN"
        line = item.get("file_line_range")
        line_no = line[0] if isinstance(line, list) and line and isinstance(line[0], int) and line[0] > 0 else None
        normalized.append({"scanner": "checkov", "rule": rule, "file": path,
                           "resource_hash": resource_hash,
                           "logical_resource_hash": logical_resource_hash,
                           "severity": severity, "line": line_no})
    if len(failed) > MAX_REPORTED_FINDINGS:
        raise ValueError("IAC_RESULT_LIMIT")
    return normalized


def _normalize_trivy(report: bytes, source: Path) -> list[dict]:
    doc = json.loads(report.decode("utf-8"))
    if not isinstance(doc, dict) or doc.get("SchemaVersion") != 2:
        raise ValueError("IAC_TRIVY_REPORT_INVALID")
    results = doc.get("Results", [])
    if not isinstance(results, list):
        raise ValueError("IAC_TRIVY_REPORT_INVALID")
    normalized = []
    for group in results:
        if not isinstance(group, dict):
            raise ValueError("IAC_TRIVY_REPORT_INVALID")
        issues = group.get("Misconfigurations", [])
        if issues is None:
            issues = []
        if not isinstance(issues, list):
            raise ValueError("IAC_TRIVY_REPORT_INVALID")
        if not issues:
            continue
        path = _safe_path(group.get("Target"), source)
        for item in issues:
            if not isinstance(item, dict):
                raise ValueError("IAC_TRIVY_REPORT_INVALID")
            rule = _rule(item.get("ID"))
            severity = str(item.get("Severity") or "UNKNOWN").upper()
            if severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
                severity = "UNKNOWN"
            cause = item.get("CauseMetadata") or {}
            line = cause.get("StartLine") if isinstance(cause, dict) else None
            line_no = line if isinstance(line, int) and line > 0 else None
            resource_hash = hashlib.sha256(str(item.get("ID", "") + "|" + str(line_no)).encode()).hexdigest()[:16]
            logical_resource_hash = _logical_resource_hash(cause.get("Resource")) if isinstance(cause, dict) else None
            normalized.append({"scanner": "trivy", "rule": rule, "file": path,
                               "resource_hash": resource_hash,
                               "logical_resource_hash": logical_resource_hash,
                               "severity": severity, "line": line_no})
            if len(normalized) > MAX_REPORTED_FINDINGS:
                raise ValueError("IAC_RESULT_LIMIT")
    return normalized


def _run_process(argv: list[str], source: Path, control: Path, report_name: str,
                 *, valid_codes: tuple[int, ...]) -> tuple[str, bytes | None]:
    report = control / report_name
    stdout = control / (report_name + ".stdout")
    stderr = control / (report_name + ".stderr")
    kwargs = ({"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt"
              else {"start_new_session": True})
    try:
        with stdout.open("wb") as out, stderr.open("wb") as err:
            try:
                child = subprocess.Popen(
                    argv, cwd=control, env=_isolated_env(control),
                    stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                    shell=False, **kwargs
                )
            except OSError:
                return "UNAVAILABLE", None
            end = time.monotonic() + SCANNER_TIMEOUT
            while child.poll() is None:
                try:
                    sizes = [f.stat().st_size for f in (stdout, stderr, report) if f.exists()]
                except OSError:
                    _terminate_process_tree(child)
                    return "IO_FAILED", None
                if any(x > MAX_SCANNER_OUTPUT for x in sizes):
                    _terminate_process_tree(child)
                    return "OUTPUT_LIMIT", None
                if time.monotonic() >= end:
                    _terminate_process_tree(child)
                    return "TIMED_OUT", None
                time.sleep(0.075)
            code = child.wait(timeout=10)
        if code not in valid_codes or not report.exists() or report.stat().st_size > MAX_SCANNER_OUTPUT:
            return "FAILED", None
        data = report.read_bytes()
        if not data:
            return "FAILED", None
        return "COMPLETED", data
    except (OSError, subprocess.TimeoutExpired):
        return "FAILED", None


def _scan_tool(name: str, source: Path, ctl: Path) -> tuple[str, list[dict], str | None]:
    executable = CHECKOV_EXE if name == "checkov" else TRIVY_EXE
    expected = CHECKOV_VERSION if name == "checkov" else TRIVY_VERSION
    version = _checkov_version() if name == "checkov" else _version(executable, expected)
    if version is None:
        return "UNAVAILABLE", [], None
    if name == "trivy":
        argv = [str(executable), "config", "--misconfig-scanners", "terraform",
                "--format", "json", "--output", str(ctl / "trivy.json"),
                "--cache-dir", str(TRIVY_CACHE_DIR), "--skip-check-update",
                "--disable-telemetry", "--skip-version-check", "--quiet",
                "--timeout", f"{SCANNER_TIMEOUT}s", str(source)]
        report_name = "trivy.json"
        codes = (0,)
    else:
        # Checkov may exit 1 when a check fails. Never treat it as a parser error.
        argv = [str(CHECKOV_PYTHON), "-c",
                "from checkov.main import Checkov;raise SystemExit(Checkov().run())",
                "--framework", "terraform", "--directory", str(source),
                "--output", "json", "--output-file-path", str(ctl),
                "--skip-download", "--skip-results-upload",
                "--download-external-modules", "False", "--quiet"]
        report_name = "results_json.json"
        codes = (0, 1)
    result, data = _run_process(argv, source, ctl, report_name, valid_codes=codes)
    if result != "COMPLETED" or data is None:
        return result, [], version
    try:
        items = (_normalize_trivy(data, source) if name == "trivy"
                 else _normalize_checkov(data, source))
    except (ValueError, UnicodeError, json.JSONDecodeError):
        return "INVALID_REPORT", [], version
    return "COMPLETED", items, version


def _store_results(db, scan: CloudScan, fingerprint: str,
                   tool_results: list[tuple[str, str, list[dict], str | None]]) -> tuple[int, int]:
    source = IAC_ROOT / scan.id / "source"
    files = sorted(p.relative_to(source).as_posix() for p in source.rglob("*") if p.is_file())
    resources = {}
    for name in files:
        res = CloudResource(
            id=new_id(), scan_id=scan.id, environment_id=None,
            resource_type="IAC_FILE", resource_arn=f"iac://{fingerprint}/{_sha(name)}",
            region="local", display_name=name,
            safe_attributes={"source_fingerprint": fingerprint},
        )
        db.add(res)
        resources[name] = res
    db.flush()
    findings_seen = set()
    semantic_seen = set()
    findings_total = 0
    unknown = 0
    merged_equivalent = 0
    for tool, result, issues, version in tool_results:
        successful = result == "COMPLETED"
        if not successful:
            unknown += 1
        db.add(CloudScanEvent(scan_id=scan.id, event_type="SCANNER",
                              message_code=f"{tool.upper()}_{result}"[:96]))
        db.add(CloudEvidence(scan_id=scan.id, resource_id=None,
            rule_id=f"IAC_{tool.upper()}_STATUS", outcome="PASS" if successful else "UNKNOWN",
            evidence_sha256=_sha({"source": fingerprint, "scanner": tool,
                                  "version": version, "status": result, "count": len(issues)}),
            safe_summary={"scanner": tool, "version": version, "status": result,
                          "finding_count": len(issues), "source_fingerprint": fingerprint}))
        if not successful:
            continue
        for item in issues:
            file = item["file"]
            if file not in resources:
                raise ValueError("IAC_RESULT_PATH_INVALID")
            # Deduplicate equivalent observations within a scanner with exact
            # identifiers. Cross-scanner rules are not guessed to be equivalent.
            identity = (tool, item["rule"], file, item["resource_hash"])
            if identity in findings_seen:
                continue
            findings_seen.add(identity)
            res = resources[file]
            tag = _EQUIVALENT_RULES.get((tool, item["rule"]))
            logical = item.get("logical_resource_hash")
            semkey = (tag, file, logical) if tag and logical else None
            if semkey is not None and semkey in semantic_seen:
                merged_equivalent += 1
                # Keep independent evidence for the second scanner below.
            else:
                if findings_total >= MAX_REPORTED_FINDINGS:
                    unknown += 1
                    break
                if semkey is not None:
                    semantic_seen.add(semkey)
                title, remediation = _REMEDIATIONS.get(
                    item["rule"],
                    (f"{item['rule']} - Terraform configuration risk",
                     "Review the policy and correct the Terraform configuration before deployment."),
                )
                db.add(CloudFinding(
                    scan_id=scan.id, resource_id=res.id, rule_id=item["rule"],
                    fingerprint=_sha(identity), severity=item["severity"], result="FAIL",
                    title=title,
                    description=f"{tool.capitalize()} identified a configuration risk in {file}.",
                    remediation=remediation,
                ))
                findings_total += 1
            db.add(CloudEvidence(
                scan_id=scan.id, resource_id=res.id, rule_id=item["rule"],
                outcome="FAIL", evidence_sha256=_sha({
                    "source":fingerprint, "scanner":tool, "rule":item["rule"],
                    "file":file, "resource_hash":item["resource_hash"], "line":item["line"]
                }),
                safe_summary={"scanner":tool,"version":version, "file":file,
                              "line":item["line"],"source_fingerprint":fingerprint,
                              "rule":item["rule"],
                              "resource_hash":item["resource_hash"]},
            ))
    if merged_equivalent:
        db.add(CloudScanEvent(scan_id=scan.id, event_type="SCANNER",
                              message_code="IAC_EQUIVALENT_FINDINGS_MERGED"))
    return findings_total, unknown


def _worker(scan_id: str) -> None:
    try:
        with SessionLocal.begin() as db:
            scan = db.get(CloudScan, scan_id)
            if scan is None or scan.status != "QUEUED":
                return
            scan.status = "RUNNING"
            scan.started_at = datetime.utcnow()
            db.add(CloudScanEvent(scan_id=scan_id, event_type="STATE", message_code="STARTED"))
        folder = IAC_ROOT / scan_id
        results = []
        for name in ("checkov", "trivy"):
            control = folder / f"control-{name}"
            control.mkdir(mode=0o700, exist_ok=True)
            result = _scan_tool(name, folder / "source", control)
            results.append((name, *result))
        with SessionLocal.begin() as db:
            scan = db.get(CloudScan, scan_id)
            if scan is None or scan.status != "RUNNING":
                return
            count, unknown = _store_results(db, scan, scan.source_fingerprint, results)
            scan.resource_count = scan.source_file_count
            scan.finding_count = count
            scan.unknown_checks = unknown
            completed = sum(result == "COMPLETED" for _, result, _, _ in results)
            scan.status = ("COMPLETED" if completed == 2 and unknown == 0
                           else "PARTIAL" if completed else "FAILED")
            scan.error_code = "IAC_SCANNER_UNAVAILABLE" if not completed else None
            scan.completed_at = datetime.utcnow()
            db.add(CloudScanEvent(scan_id=scan_id, event_type="STATE",
                                  message_code=scan.status))
    except Exception:
        # Do not expose scanner stderr, Terraform text or raw exception strings.
        log.warning("Cloud IaC scan failed (code=IAC_SCAN_FAILED)")
        try:
            with SessionLocal.begin() as db:
                scan = db.get(CloudScan, scan_id)
                if scan and scan.status in ("QUEUED", "RUNNING"):
                    scan.status = "FAILED"
                    scan.error_code = "IAC_SCAN_FAILED"
                    scan.completed_at = datetime.utcnow()
                    db.add(CloudScanEvent(scan_id=scan_id, event_type="STATE",
                                          message_code="FAILED"))
        except Exception:
            log.error("Cloud IaC scan status persistence failed")
    finally:
        discard_source(scan_id)
        _IAC_CAPACITY.release()


def enqueue_iac(scan_id: str) -> bool:
    if not _IAC_CAPACITY.acquire(blocking=False):
        return False
    try:
        _IAC_POOL.submit(_worker, scan_id)
    except Exception:
        _IAC_CAPACITY.release()
        raise
    return True


def discard_interrupted_archives() -> None:
    if not IAC_ROOT.exists():
        return
    for child in IAC_ROOT.iterdir():
        if child.is_dir():
            discard_source(child.name)
