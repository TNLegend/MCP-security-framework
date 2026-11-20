"""Deploy Security cloud inventory and scan evidence.

These tables contain observations only, never AWS credentials, access keys, tokens,
document content or mutable production cloud configuration.
"""
from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import (
    Boolean, DateTime, ForeignKey, Index, Integer, JSON, String, Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


def new_id() -> str:
    return str(uuid4())


class CloudEnvironment(Base):
    __tablename__ = "cloud_environments"
    __table_args__ = (
        UniqueConstraint("name", name="uq_cloud_environment_name"),
        Index("ix_cloud_environment_account", "account_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    provider: Mapped[str] = mapped_column(String(16), default="AWS", nullable=False)
    account_id: Mapped[str | None] = mapped_column(String(12), nullable=True)
    regions: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    services: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=lambda: ["EC2", "S3", "IAM"])
    # Profile is a local SDK credential reference. No secrets are persisted.
    credential_mode: Mapped[str] = mapped_column(String(24), nullable=False)
    profile_name: Mapped[str | None] = mapped_column(String(64), nullable=True)
    role_arn: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    status: Mapped[str] = mapped_column(String(24), default="UNVERIFIED", nullable=False)
    last_error_code: Mapped[str | None] = mapped_column(String(80), nullable=True)
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_by: Mapped[str] = mapped_column(String(36), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)


class CloudScan(Base):
    __tablename__ = "cloud_scans"
    __table_args__ = (
        Index("ix_cloud_scan_environment_created", "environment_id", "created_at"),
        Index("ix_cloud_scan_status_created", "status", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    environment_id: Mapped[str | None] = mapped_column(ForeignKey("cloud_environments.id"), nullable=True)
    kind: Mapped[str] = mapped_column(String(30), default="AWS_BASELINE", nullable=False)
    status: Mapped[str] = mapped_column(String(24), default="QUEUED", nullable=False)
    requested_by: Mapped[str] = mapped_column(String(36), nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    error_code: Mapped[str | None] = mapped_column(String(80), nullable=True)
    resource_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    finding_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    unknown_checks: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    source_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    source_file_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    scanner_version: Mapped[str] = mapped_column(String(40), nullable=False, default="boto3-baseline-v1")


class CloudResource(Base):
    __tablename__ = "cloud_resources"
    __table_args__ = (
        UniqueConstraint("scan_id", "resource_arn", name="uq_cloud_resource_scan_arn"),
        Index("ix_cloud_resource_type", "environment_id", "resource_type"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    scan_id: Mapped[str] = mapped_column(ForeignKey("cloud_scans.id"), nullable=False)
    environment_id: Mapped[str | None] = mapped_column(ForeignKey("cloud_environments.id"), nullable=True)
    resource_type: Mapped[str] = mapped_column(String(48), nullable=False)
    resource_arn: Mapped[str] = mapped_column(String(512), nullable=False)
    region: Mapped[str] = mapped_column(String(32), nullable=False)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    safe_attributes: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)


class CloudFinding(Base):
    __tablename__ = "cloud_findings"
    __table_args__ = (
        UniqueConstraint("scan_id", "fingerprint", name="uq_cloud_finding_scan_fingerprint"),
        Index("ix_cloud_finding_scan_severity", "scan_id", "severity"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    scan_id: Mapped[str] = mapped_column(ForeignKey("cloud_scans.id"), nullable=False)
    resource_id: Mapped[str | None] = mapped_column(ForeignKey("cloud_resources.id"), nullable=True)
    rule_id: Mapped[str] = mapped_column(String(96), nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    result: Mapped[str] = mapped_column(String(24), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)


class CloudEvidence(Base):
    __tablename__ = "cloud_evidence"
    __table_args__ = (Index("ix_cloud_evidence_scan", "scan_id"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    scan_id: Mapped[str] = mapped_column(ForeignKey("cloud_scans.id"), nullable=False)
    resource_id: Mapped[str | None] = mapped_column(ForeignKey("cloud_resources.id"), nullable=True)
    rule_id: Mapped[str] = mapped_column(String(96), nullable=False)
    outcome: Mapped[str] = mapped_column(String(24), nullable=False)
    evidence_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    safe_summary: Mapped[dict] = mapped_column(JSON, nullable=False)
    checked_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)


class CloudIAMComparison(Base):
    __tablename__ = "cloud_iam_comparisons"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    scan_id: Mapped[str] = mapped_column(ForeignKey("cloud_scans.id"), nullable=False, index=True)
    mcp_server_id: Mapped[int | None] = mapped_column(ForeignKey("mcp_servers.id"), nullable=True)
    role_arn: Mapped[str | None] = mapped_column(String(512), nullable=True)
    status: Mapped[str] = mapped_column(String(24), default="NOT_EVALUATED", nullable=False)
    expected_actions: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    observed_actions: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    tool_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    expected_resource_arn: Mapped[str | None] = mapped_column(String(512), nullable=True)
    policy_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    signed_revision: Mapped[int | None] = mapped_column(Integer, nullable=True)
    identity_permission_status: Mapped[str | None] = mapped_column(String(48), nullable=True)
    effective_permission_status: Mapped[str | None] = mapped_column(String(48), nullable=True)


class CloudScanEvent(Base):
    __tablename__ = "cloud_scan_events"
    __table_args__ = (Index("ix_cloud_scan_event_scan", "scan_id", "created_at"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    scan_id: Mapped[str] = mapped_column(ForeignKey("cloud_scans.id"), nullable=False)
    event_type: Mapped[str] = mapped_column(String(48), nullable=False)
    message_code: Mapped[str] = mapped_column(String(96), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)


class CloudIAMMapping(Base):
    """Versioned admin-reviewed mapping bound to a signed published MCP revision.

    No runtime IAM mutations or cloud secrets are stored. Editing an approved
    mapping requires creating a new draft with its own approval digest.
    """
    __tablename__ = "cloud_iam_mappings"
    __table_args__ = (
        Index("ix_cloud_iam_mapping_environment", "environment_id", "mcp_server_id"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    environment_id: Mapped[str] = mapped_column(ForeignKey("cloud_environments.id"), nullable=False)
    mcp_server_id: Mapped[int] = mapped_column(ForeignKey("mcp_servers.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    configuration: Mapped[dict] = mapped_column(JSON, nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="DRAFT")
    signed_revision: Mapped[int] = mapped_column(Integer, nullable=False)
    signed_content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    approval_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_by: Mapped[str] = mapped_column(String(36), nullable=False)
    approved_by: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
