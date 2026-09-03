from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Mapping, Sequence

from common.canonical_json import sha256_canonical_json


class BuildTargetType(str, Enum):
    LOCAL_DIRECTORY = "LOCAL_DIRECTORY"
    GIT_REPOSITORY = "GIT_REPOSITORY"


class BuildScanStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class ScannerRunStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    TIMED_OUT = "TIMED_OUT"
    UNAVAILABLE = "UNAVAILABLE"


class FindingSeverity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FindingConfidence(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class FindingState(str, Enum):
    NEW = "NEW"
    UNCHANGED = "UNCHANGED"
    RESOLVED = "RESOLVED"
    REGRESSED = "REGRESSED"


class BuildAssessmentStatus(str, Enum):
    PASS = "PASS"
    WARN = "WARN"
    BLOCK = "BLOCK"
    ERROR = "ERROR"


_SENSITIVE_METADATA_FRAGMENTS = {
    "secret",
    "password",
    "passwd",
    "token",
    "credential",
    "authorization",
    "private_key",
    "api_key",
    "access_key",
    "client_secret",
    "raw_match",
    "matched_text",
    "line_text",
    "snippet",
    "content",
}


def _bounded_text(value: Any, *, limit: int = 1000) -> str:
    return str(value)[:limit]


def sanitize_scanner_metadata(
    value: Any,
    *,
    _depth: int = 0,
    max_depth: int = 8,
    max_items: int = 100,
) -> Any:
    """Keep bounded non-secret scanner metadata only.

    Scanner adapters must never put raw source snippets or detected secret material
    into normalized evidence. This function is a second fail-closed boundary before
    persistence/API layers.
    """

    if _depth >= max_depth:
        return None
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, item in list(value.items())[:max_items]:
            key_text = _bounded_text(key, limit=128)
            lowered = key_text.lower()
            if any(fragment in lowered for fragment in _SENSITIVE_METADATA_FRAGMENTS):
                continue
            result[key_text] = sanitize_scanner_metadata(
                item,
                _depth=_depth + 1,
                max_depth=max_depth,
                max_items=max_items,
            )
        return result
    if isinstance(value, (list, tuple)):
        return [
            sanitize_scanner_metadata(
                item,
                _depth=_depth + 1,
                max_depth=max_depth,
                max_items=max_items,
            )
            for item in list(value)[:max_items]
        ]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return _bounded_text(value) if isinstance(value, str) else value
    return _bounded_text(type(value).__name__, limit=128)


def normalize_finding_path(path: str | None) -> str | None:
    if path is None:
        return None
    normalized = path.strip().replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    while "//" in normalized:
        normalized = normalized.replace("//", "/")
    return normalized or None


def finding_fingerprint(
    *,
    scanner_id: str,
    rule_id: str,
    category: str,
    file_path: str | None = None,
    line_start: int | None = None,
    vulnerability_id: str | None = None,
    package_name: str | None = None,
    package_version: str | None = None,
) -> str:
    return sha256_canonical_json(
        {
            "scanner_id": scanner_id.strip().lower(),
            "rule_id": rule_id.strip(),
            "category": category.strip().upper(),
            "file_path": normalize_finding_path(file_path),
            "line_start": line_start,
            "vulnerability_id": vulnerability_id,
            "package_name": package_name,
            "package_version": package_version,
        }
    )


@dataclass(frozen=True, slots=True)
class BuildTargetSnapshot:
    target_type: BuildTargetType
    display_name: str
    source_locator: str
    source_revision: str | None = None
    source_fingerprint: str | None = None
    linked_server_id: int | None = None


@dataclass(frozen=True, slots=True)
class ValidatedWorkspace:
    root: Path
    target: BuildTargetSnapshot
    file_count: int
    total_bytes: int

    def __post_init__(self) -> None:
        if not self.root.is_absolute():
            raise ValueError("workspace_root_must_be_absolute")
        if self.file_count < 0 or self.total_bytes < 0:
            raise ValueError("workspace_size_must_be_non_negative")


@dataclass(frozen=True, slots=True)
class NormalizedFinding:
    scanner_id: str
    rule_id: str
    category: str
    severity: FindingSeverity
    confidence: FindingConfidence
    title: str
    fingerprint: str
    file_path: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    column_start: int | None = None
    column_end: int | None = None
    description: str | None = None
    remediation: str | None = None
    vulnerability_id: str | None = None
    package_name: str | None = None
    package_version: str | None = None
    fixed_version: str | None = None
    references: tuple[str, ...] = ()
    safe_metadata: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        *,
        scanner_id: str,
        rule_id: str,
        category: str,
        severity: FindingSeverity,
        confidence: FindingConfidence,
        title: str,
        file_path: str | None = None,
        line_start: int | None = None,
        line_end: int | None = None,
        column_start: int | None = None,
        column_end: int | None = None,
        description: str | None = None,
        remediation: str | None = None,
        vulnerability_id: str | None = None,
        package_name: str | None = None,
        package_version: str | None = None,
        fixed_version: str | None = None,
        references: Sequence[str] = (),
        safe_metadata: Mapping[str, Any] | None = None,
    ) -> "NormalizedFinding":
        normalized_path = normalize_finding_path(file_path)
        fingerprint = finding_fingerprint(
            scanner_id=scanner_id,
            rule_id=rule_id,
            category=category,
            file_path=normalized_path,
            line_start=line_start,
            vulnerability_id=vulnerability_id,
            package_name=package_name,
            package_version=package_version,
        )
        sanitized = sanitize_scanner_metadata(safe_metadata or {})
        return cls(
            scanner_id=scanner_id.strip().lower(),
            rule_id=rule_id.strip(),
            category=category.strip().upper(),
            severity=severity,
            confidence=confidence,
            title=title.strip()[:1000],
            fingerprint=fingerprint,
            file_path=normalized_path,
            line_start=line_start,
            line_end=line_end,
            column_start=column_start,
            column_end=column_end,
            description=description[:4000] if description else None,
            remediation=remediation[:4000] if remediation else None,
            vulnerability_id=vulnerability_id,
            package_name=package_name,
            package_version=package_version,
            fixed_version=fixed_version,
            references=tuple(str(item)[:1000] for item in references[:50]),
            safe_metadata=sanitized,
        )


@dataclass(frozen=True, slots=True)
class ScannerAvailability:
    available: bool
    scanner_id: str
    version: str | None = None
    reason_code: str | None = None


@dataclass(frozen=True, slots=True)
class ScannerContext:
    scan_id: str
    timeout_seconds: int = 300
    max_output_bytes: int = 10 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class ScannerExecutionResult:
    scanner_id: str
    status: ScannerRunStatus
    findings: tuple[NormalizedFinding, ...] = ()
    scanner_version: str | None = None
    error_code: str | None = None
    error_summary: str | None = None

    def __post_init__(self) -> None:
        if self.status == ScannerRunStatus.COMPLETED and self.error_code:
            raise ValueError("completed_scanner_run_cannot_have_error")
        if self.status != ScannerRunStatus.COMPLETED and self.findings:
            raise ValueError("incomplete_scanner_run_cannot_claim_findings")
