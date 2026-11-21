from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class RuntimeCall(Base):
    __tablename__ = "runtime_calls"
    # Old (unpaired) events retain NULL in both columns. Paired new events
    # have at most one durable record for each operation transition.
    __table_args__ = (
        UniqueConstraint("operation_id", "event_phase", name="uq_runtime_call_operation_phase"),
    )

    operation_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    event_phase: Mapped[str | None] = mapped_column(String(12), nullable=True)
    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    agent_id: Mapped[str] = mapped_column(String(255), nullable=False)
    session_id: Mapped[str] = mapped_column(String(255), nullable=False)
    server_id: Mapped[int | None] = mapped_column(
        ForeignKey("mcp_servers.id"),
        nullable=True,
    )
    tool_name: Mapped[str] = mapped_column(String(255), nullable=False)
    # Immutable fingerprint the Proxy actually authorized before dispatch.
    tool_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    arguments_summary: Mapped[dict[str, Any] | str | None] = mapped_column(
        JSON,
        nullable=True,
    )
    status: Mapped[str] = mapped_column(String(50), nullable=False)
    decision: Mapped[str | None] = mapped_column(String(50), nullable=True)
    rule_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    decision_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    explanation: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    policy_revision: Mapped[str | None] = mapped_column(String(96), nullable=True)
    opa_decision: Mapped[str | None] = mapped_column(String(24), nullable=True)
    opa_rule_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    opa_policy_revision: Mapped[str | None] = mapped_column(String(96), nullable=True)
    opa_explanation: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    guard_explanation: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    decision_basis: Mapped[str | None] = mapped_column(String(40), nullable=True)
    dispatch_state: Mapped[str | None] = mapped_column(String(40), nullable=True)
    severity: Mapped[str | None] = mapped_column(String(50), nullable=True)
    # EM-01: the emergency deny that blocked this call (EMERGENCY basis only).
    emergency_deny_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    control_plane_revision_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    control_plane_revision_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    control_plane_content_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    client_protocol_profile_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    client_protocol_era: Mapped[str | None] = mapped_column(String(50), nullable=True)
    client_protocol_version: Mapped[str | None] = mapped_column(String(50), nullable=True)
    client_transport_kind: Mapped[str | None] = mapped_column(String(50), nullable=True)
    upstream_protocol_profile_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    upstream_protocol_era: Mapped[str | None] = mapped_column(String(50), nullable=True)
    upstream_protocol_version: Mapped[str | None] = mapped_column(String(50), nullable=True)
    upstream_transport_kind: Mapped[str | None] = mapped_column(String(50), nullable=True)
    executed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    execution_status: Mapped[str | None] = mapped_column(String(50), nullable=True)
    result_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    error_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    total_duration_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    policy_duration_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    upstream_duration_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    result_guard_duration_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
