from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

BuildTargetTypeValue = Literal["LOCAL_DIRECTORY", "GIT_REPOSITORY"]
BuildScanStatusValue = Literal["PENDING", "RUNNING", "COMPLETED", "FAILED"]
ScannerRunStatusValue = Literal[
    "PENDING",
    "RUNNING",
    "COMPLETED",
    "FAILED",
    "TIMED_OUT",
    "UNAVAILABLE",
]
FindingSeverityValue = Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
FindingConfidenceValue = Literal["LOW", "MEDIUM", "HIGH"]
FindingStateValue = Literal["NEW", "UNCHANGED", "RESOLVED", "REGRESSED"]
BuildAssessmentStatusValue = Literal["PASS", "WARN", "BLOCK", "ERROR"]


class BuildScannerAvailabilityPublic(BaseModel):
    scanner_id: str
    available: bool
    version: str | None = None
    reason_code: str | None = None

    model_config = ConfigDict(extra="forbid")


class BuildLocalDirectorySelectionPublic(BaseModel):
    selected: bool
    path: str | None = None
    name: str | None = None

    model_config = ConfigDict(extra="forbid")


class BuildSourceBindingRequest(BaseModel):
    target_type: BuildTargetTypeValue
    source_locator: str = Field(min_length=1, max_length=4096)
    source_ref: str | None = Field(default=None, max_length=255)
    reason: str = Field(min_length=3, max_length=2000)

    model_config = ConfigDict(extra="forbid")

    @field_validator("source_locator", "source_ref", "reason")
    @classmethod
    def normalize_binding_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            raise ValueError("value must not be empty.")
        return normalized


class BuildSourceBindingPublic(BaseModel):
    id: str
    server_id: int
    target_type: BuildTargetTypeValue
    source_locator: str
    source_ref: str | None = None
    created_by: str | None = None
    updated_by: str | None = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True, extra="forbid")


class BuildTargetRequest(BaseModel):
    target_type: BuildTargetTypeValue
    display_name: str = Field(min_length=1, max_length=255)
    source_locator: str = Field(min_length=1, max_length=4096)
    source_revision: str | None = Field(default=None, max_length=255)
    linked_server_id: int | None = Field(default=None, ge=1)

    model_config = ConfigDict(extra="forbid")

    @field_validator("display_name", "source_locator", "source_revision")
    @classmethod
    def normalize_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            raise ValueError("value must not be empty.")
        return normalized


class BuildEvidenceDraftRequest(BaseModel):
    draft_revision_id: str = Field(min_length=36, max_length=36)
    mode: Literal["DISABLED", "ALLOW_WARN", "REQUIRE_PASS"] = "REQUIRE_PASS"
    max_evidence_age_hours: int = Field(default=168, ge=1, le=8760)
    reason: str = Field(min_length=3, max_length=2000)

    model_config = ConfigDict(extra="forbid")

    @field_validator("draft_revision_id", "reason")
    @classmethod
    def normalize_evidence_text(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("value must not be empty.")
        return normalized


class BuildLocalScanRequest(BaseModel):
    display_name: str = Field(min_length=1, max_length=255)
    source_locator: str = Field(min_length=1, max_length=4096)
    linked_server_id: int | None = Field(default=None, ge=1)
    reason: str = Field(
        default="Admin requested Build Security scan.",
        min_length=3,
        max_length=2000,
    )

    model_config = ConfigDict(extra="forbid")

    @field_validator("display_name", "source_locator", "reason")
    @classmethod
    def normalize_local_scan_text(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("value must not be empty.")
        return normalized


class BuildGitScanRequest(BaseModel):
    display_name: str = Field(min_length=1, max_length=255)
    repository_url: str = Field(min_length=1, max_length=2048)
    source_ref: str = Field(default="HEAD", min_length=1, max_length=255)
    linked_server_id: int | None = Field(default=None, ge=1)
    reason: str = Field(
        default="Admin requested Build Security scan.",
        min_length=3,
        max_length=2000,
    )

    model_config = ConfigDict(extra="forbid")

    @field_validator("display_name", "repository_url", "source_ref", "reason")
    @classmethod
    def normalize_git_scan_text(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("value must not be empty.")
        return normalized


class BuildInventoryScanRequest(BaseModel):
    reason: str = Field(
        default="Admin requested Build Security scan from Inventory source binding.",
        min_length=3,
        max_length=2000,
    )

    model_config = ConfigDict(extra="forbid")

    @field_validator("reason")
    @classmethod
    def normalize_inventory_scan_reason(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("value must not be empty.")
        return normalized


class BuildScanSourcePublic(BaseModel):
    scan_id: str
    target_type: BuildTargetTypeValue
    source_locator: str
    source_revision: str | None = None
    linked_server_id: int | None = None

    model_config = ConfigDict(extra="forbid")


class BuildScanSummaryPublic(BaseModel):
    id: str
    target_type: BuildTargetTypeValue
    display_name: str
    source_revision: str | None = None
    source_fingerprint: str | None = None
    linked_server_id: int | None = None
    status: BuildScanStatusValue
    requested_by: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    failure_code: str | None = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True, extra="forbid")


class BuildScannerRunPublic(BaseModel):
    id: str
    build_scan_id: str
    scanner_id: str
    scanner_version: str | None = None
    required: bool
    status: ScannerRunStatusValue
    finding_count: int = Field(ge=0)
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error_code: str | None = None

    model_config = ConfigDict(from_attributes=True, extra="forbid")


class BuildFindingPublic(BaseModel):
    id: str
    build_scan_id: str
    scanner_run_id: str
    scanner_id: str
    rule_id: str
    category: str
    severity: FindingSeverityValue
    confidence: FindingConfidenceValue
    finding_state: FindingStateValue
    fingerprint: str = Field(min_length=64, max_length=64)
    title: str
    description: str | None = None
    remediation: str | None = None
    file_path: str | None = None
    line_start: int | None = Field(default=None, ge=1)
    line_end: int | None = Field(default=None, ge=1)
    column_start: int | None = Field(default=None, ge=1)
    column_end: int | None = Field(default=None, ge=1)
    vulnerability_id: str | None = None
    package_name: str | None = None
    package_version: str | None = None
    fixed_version: str | None = None
    references: list[str] = Field(default_factory=list, max_length=50)
    safe_metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime

    model_config = ConfigDict(from_attributes=True, extra="forbid")


class BuildAssessmentPublic(BaseModel):
    id: str
    build_scan_id: str
    status: BuildAssessmentStatusValue
    policy_version: str
    required_scanners_complete: bool
    reason_codes: list[str] = Field(default_factory=list, max_length=100)
    summary: str | None = None
    critical_count: int = Field(ge=0)
    high_count: int = Field(ge=0)
    medium_count: int = Field(ge=0)
    low_count: int = Field(ge=0)
    info_count: int = Field(ge=0)
    created_at: datetime

    model_config = ConfigDict(from_attributes=True, extra="forbid")


class BuildScanDetailPublic(BaseModel):
    scan: BuildScanSummaryPublic
    scanner_runs: list[BuildScannerRunPublic] = Field(default_factory=list, max_length=50)
    findings: list[BuildFindingPublic] = Field(default_factory=list, max_length=500)
    finding_total: int = Field(ge=0)
    findings_truncated: bool
    assessment: BuildAssessmentPublic | None = None

    model_config = ConfigDict(extra="forbid")
