from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


def _uuid() -> str:
    return str(uuid4())


class BuildSourceBinding(Base):
    __tablename__ = "build_source_bindings"
    __table_args__ = (
        UniqueConstraint("server_id", name="uq_build_source_binding_server"),
        Index("ix_build_source_bindings_type", "target_type"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    server_id: Mapped[int] = mapped_column(
        ForeignKey("mcp_servers.id"),
        nullable=False,
        index=True,
    )
    target_type: Mapped[str] = mapped_column(String(32), nullable=False)
    source_locator: Mapped[str] = mapped_column(Text, nullable=False)
    source_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(36), nullable=True)
    updated_by: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )


class BuildScanRun(Base):
    __tablename__ = "build_scan_runs"
    __table_args__ = (
        Index("ix_build_scan_runs_status_created", "status", "created_at"),
        Index("ix_build_scan_runs_server_created", "linked_server_id", "created_at"),
        Index("ix_build_scan_runs_source_fingerprint", "source_fingerprint"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    target_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    source_locator: Mapped[str] = mapped_column(Text, nullable=False)
    source_revision: Mapped[str | None] = mapped_column(String(255), nullable=True)
    source_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    linked_server_id: Mapped[int | None] = mapped_column(
        ForeignKey("mcp_servers.id"),
        nullable=True,
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="PENDING")
    requested_by: Mapped[str | None] = mapped_column(String(36), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    failure_code: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)


class BuildScannerRun(Base):
    __tablename__ = "build_scanner_runs"
    __table_args__ = (
        UniqueConstraint(
            "build_scan_id",
            "scanner_id",
            name="uq_build_scanner_run_scan_scanner",
        ),
        Index("ix_build_scanner_runs_scan_status", "build_scan_id", "status"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    build_scan_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("build_scan_runs.id"),
        nullable=False,
        index=True,
    )
    scanner_id: Mapped[str] = mapped_column(String(64), nullable=False)
    scanner_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="PENDING")
    finding_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    error_code: Mapped[str | None] = mapped_column(String(128), nullable=True)


class BuildFinding(Base):
    __tablename__ = "build_findings"
    __table_args__ = (
        UniqueConstraint(
            "build_scan_id",
            "fingerprint",
            name="uq_build_finding_scan_fingerprint",
        ),
        Index("ix_build_findings_scan_severity", "build_scan_id", "severity"),
        Index("ix_build_findings_fingerprint", "fingerprint"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    build_scan_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("build_scan_runs.id"),
        nullable=False,
        index=True,
    )
    scanner_run_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("build_scanner_runs.id"),
        nullable=False,
        index=True,
    )
    scanner_id: Mapped[str] = mapped_column(String(64), nullable=False)
    rule_id: Mapped[str] = mapped_column(String(255), nullable=False)
    category: Mapped[str] = mapped_column(String(128), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    confidence: Mapped[str] = mapped_column(String(16), nullable=False)
    finding_state: Mapped[str] = mapped_column(String(16), nullable=False, default="NEW")
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    file_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    line_start: Mapped[int | None] = mapped_column(Integer, nullable=True)
    line_end: Mapped[int | None] = mapped_column(Integer, nullable=True)
    column_start: Mapped[int | None] = mapped_column(Integer, nullable=True)
    column_end: Mapped[int | None] = mapped_column(Integer, nullable=True)
    vulnerability_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    package_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    package_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    fixed_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    references: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    safe_metadata: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)


class BuildAssessment(Base):
    __tablename__ = "build_assessments"
    __table_args__ = (
        Index("ix_build_assessments_status_created", "status", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    build_scan_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("build_scan_runs.id"),
        nullable=False,
        unique=True,
        index=True,
    )
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    policy_version: Mapped[str] = mapped_column(String(64), nullable=False)
    required_scanners_complete: Mapped[bool] = mapped_column(Boolean, nullable=False)
    reason_codes: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    critical_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    high_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    medium_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    low_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    info_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
