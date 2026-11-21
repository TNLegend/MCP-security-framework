from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class ToolObservedVersion(Base):
    __tablename__ = "tool_observed_versions"
    __table_args__ = (
        UniqueConstraint("tool_id", "fingerprint", name="uq_tool_version_fingerprint"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    tool_id: Mapped[int] = mapped_column(ForeignKey("mcp_tools.id"), nullable=False)
    server_ref: Mapped[str] = mapped_column(String(512), nullable=False)
    tool_name: Mapped[str] = mapped_column(String(255), nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(50), default="observed", nullable=False)
    snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    profile_snapshot: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    profile_revision: Mapped[str] = mapped_column(String(255), default="unknown", nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class ToolAnalysis(Base):
    __tablename__ = "tool_analyses"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    tool_id: Mapped[int] = mapped_column(ForeignKey("mcp_tools.id"), nullable=False)
    version_id: Mapped[int] = mapped_column(
        ForeignKey("tool_observed_versions.id"),
        nullable=False,
    )
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    analysis_context_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    analysis_status: Mapped[str] = mapped_column(String(50), nullable=False)
    # TA-01: enumerated quarantine cause; NULL when not QUARANTINED or historical.
    status_reason: Mapped[str | None] = mapped_column(String(64), nullable=True)
    risk_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    risk_level: Mapped[str] = mapped_column(String(50), default="unknown", nullable=False)
    semantic_flagged: Mapped[str] = mapped_column(String(5), default="false", nullable=False)
    deterministic_critical_finding: Mapped[str] = mapped_column(
        String(5),
        default="false",
        nullable=False,
    )
    consistency_status: Mapped[str] = mapped_column(
        String(50),
        default="unknown",
        nullable=False,
    )
    drift_status: Mapped[str] = mapped_column(String(50), default="NONE", nullable=False)
    review_status: Mapped[str] = mapped_column(
        String(50),
        default="REVIEW_REQUIRED",
        nullable=False,
    )
    semantic_scores: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    consistency_result: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    drift_result: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    model_versions: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    analyzer_revision: Mapped[str] = mapped_column(String(100), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class ToolAnalysisFinding(Base):
    __tablename__ = "tool_analysis_findings"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    analysis_id: Mapped[int] = mapped_column(ForeignKey("tool_analyses.id"), nullable=False)
    code: Mapped[str] = mapped_column(String(128), nullable=False)
    category: Mapped[str] = mapped_column(String(128), nullable=False)
    source: Mapped[str] = mapped_column(String(50), nullable=False)
    severity: Mapped[str] = mapped_column(String(50), nullable=False)
    confidence: Mapped[int] = mapped_column(Integer, nullable=False)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    recommendation: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class ToolApprovedBaseline(Base):
    __tablename__ = "tool_approved_baselines"
    __table_args__ = (
        UniqueConstraint("tool_id", name="uq_tool_approved_baseline_tool"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    tool_id: Mapped[int] = mapped_column(ForeignKey("mcp_tools.id"), nullable=False)
    version_id: Mapped[int] = mapped_column(
        ForeignKey("tool_observed_versions.id"),
        nullable=False,
    )
    analysis_id: Mapped[int] = mapped_column(ForeignKey("tool_analyses.id"), nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    analysis_context_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    approval_source: Mapped[str] = mapped_column(
        String(32), default="ADMIN", nullable=False
    )
    reviewer: Mapped[str] = mapped_column(String(255), nullable=False)
    justification: Mapped[str] = mapped_column(Text, nullable=False)
    analyzer_revision: Mapped[str] = mapped_column(String(100), nullable=False)
    model_versions: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    approved_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class ToolHumanReview(Base):
    __tablename__ = "tool_human_reviews"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    tool_id: Mapped[int] = mapped_column(ForeignKey("mcp_tools.id"), nullable=False)
    version_id: Mapped[int] = mapped_column(
        ForeignKey("tool_observed_versions.id"),
        nullable=False,
    )
    analysis_id: Mapped[int] = mapped_column(ForeignKey("tool_analyses.id"), nullable=False)
    action: Mapped[str] = mapped_column(String(50), nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    reviewer: Mapped[str] = mapped_column(String(255), nullable=False)
    justification: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class ToolProtocolObservation(Base):
    __tablename__ = "tool_protocol_observations"
    __table_args__ = (
        UniqueConstraint(
            "tool_id",
            "upstream_protocol_profile_id",
            "tool_fingerprint",
            name="uq_tool_protocol_observation_profile_fingerprint",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    tool_id: Mapped[int] = mapped_column(ForeignKey("mcp_tools.id"), nullable=False)
    server_ref: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    upstream_protocol_profile_id: Mapped[str] = mapped_column(
        String(100), nullable=False, index=True
    )
    protocol_era: Mapped[str] = mapped_column(String(50), default="legacy", nullable=False)
    protocol_version: Mapped[str] = mapped_column(
        String(50), default="2025-11-25", nullable=False
    )
    transport_kind: Mapped[str] = mapped_column(
        String(50), default="legacy_streamable_http", nullable=False
    )
    tool_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    canonical_tool_definition: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    tool_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    analysis_state: Mapped[str] = mapped_column(String(50), nullable=False)
    analysis_id: Mapped[int | None] = mapped_column(
        ForeignKey("tool_analyses.id"), nullable=True
    )
    observed_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class ToolObservationReviewApproval(Base):
    __tablename__ = "tool_observation_review_approvals"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    observation_id: Mapped[int] = mapped_column(
        ForeignKey("tool_protocol_observations.id"), nullable=False, index=True
    )
    tool_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    contract_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    evidence_bundle_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    evidence_bundle: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    admin_id: Mapped[str] = mapped_column(String(255), nullable=False)
    revision_id: Mapped[str] = mapped_column(String(64), nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    approved_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
