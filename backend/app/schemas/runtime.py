from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class RuntimeCallCreate(BaseModel):
    # Optional solely for historical signed service log producers. New Proxy
    # events MUST carry both; never accept half a correlation pair.
    operation_id: str | None = Field(default=None, pattern=r"^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$")
    event_phase: Literal["intent", "outcome"] | None = None

    @model_validator(mode="after")
    def validate_correlation(self):
        if (self.operation_id is None) != (self.event_phase is None):
            raise ValueError("runtime_operation_phase_pair_required")
        if self.event_phase == "intent" and self.execution_status != "authorized_pending_execution":
            raise ValueError("runtime_intent_status_invalid")
        if self.event_phase == "outcome" and self.execution_status == "authorized_pending_execution":
            raise ValueError("runtime_outcome_status_invalid")
        return self

    agent_id: str
    session_id: str
    server_id: int | str | None = None
    tool_name: str
    tool_fingerprint: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    arguments_summary: dict[str, Any] | str | None = None
    status: str = "created"
    decision: str | None = None
    rule_id: str | None = None
    decision_reason: str | None = None
    severity: str | None = None
    control_plane_revision_id: str | None = None
    control_plane_revision_number: int | None = None
    control_plane_content_hash: str | None = None
    client_protocol_profile_id: str | None = None
    client_protocol_era: str | None = None
    client_protocol_version: str | None = None
    client_transport_kind: str | None = None
    upstream_protocol_profile_id: str | None = None
    upstream_protocol_era: str | None = None
    upstream_protocol_version: str | None = None
    upstream_transport_kind: str | None = None
    executed: bool = False
    execution_status: str | None = None
    result_summary: str | None = None
    error_summary: str | None = None
    total_duration_ms: float | None = None
    policy_duration_ms: float | None = None
    upstream_duration_ms: float | None = None
    result_guard_duration_ms: float | None = None


class RuntimeCallRead(BaseModel):
    operation_id: str | None = None
    event_phase: Literal["intent", "outcome"] | None = None
    id: int
    agent_id: str
    session_id: str
    server_id: int | None = None
    tool_name: str
    tool_fingerprint: str | None = None
    arguments_summary: dict[str, Any] | str | None = None
    status: str
    decision: str | None = None
    rule_id: str | None = None
    decision_reason: str | None = None
    severity: str | None = None
    control_plane_revision_id: str | None = None
    control_plane_revision_number: int | None = None
    control_plane_content_hash: str | None = None
    client_protocol_profile_id: str | None = None
    client_protocol_era: str | None = None
    client_protocol_version: str | None = None
    client_transport_kind: str | None = None
    upstream_protocol_profile_id: str | None = None
    upstream_protocol_era: str | None = None
    upstream_protocol_version: str | None = None
    upstream_transport_kind: str | None = None
    executed: bool = False
    execution_status: str | None = None
    result_summary: str | None = None
    error_summary: str | None = None
    total_duration_ms: float | None = None
    policy_duration_ms: float | None = None
    upstream_duration_ms: float | None = None
    result_guard_duration_ms: float | None = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class RuntimeCallSummary(BaseModel):
    total: int
    allowed: int
    blocked: int
    executed: int
    skipped: int
    errors: int


class RuntimeCallPage(BaseModel):
    items: list[RuntimeCallRead]
    next_cursor: str | None = None
    has_more: bool = False
    summary: RuntimeCallSummary
