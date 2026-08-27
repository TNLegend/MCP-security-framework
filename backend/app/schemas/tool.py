from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict


class MCPToolCreate(BaseModel):
    server_id: int
    name: str
    title: str | None = None
    description: str | None = None
    icons: list[dict[str, Any]] | None = None
    input_schema: dict[str, Any] | None = None
    output_schema: dict[str, Any] | None = None
    annotations: dict[str, Any] | None = None
    execution: dict[str, Any] | None = None
    raw_tool_definition: dict[str, Any] | None = None

    model_config = ConfigDict(extra="forbid")


class MCPToolRead(MCPToolCreate):
    risk_score: int = 0
    sensitivity: str = "low"
    description_risk_score: int = 0
    policy_status: str = "not_reviewed"
    is_sensitive: bool = False
    last_analyzed_at: datetime | None = None
    current_fingerprint: str | None = None
    approved_fingerprint: str | None = None
    approved_fingerprint_match: bool = False
    analysis_status: str = "PENDING_ANALYSIS"
    risk_level: str = "unknown"
    semantic_flagged: bool = False
    deterministic_critical_finding: bool = False
    consistency_status: str = "unknown"
    drift_status: str = "NONE"
    review_status: str = "REVIEW_REQUIRED"
    analyzer_revision: str | None = None
    status: str = "active"
    id: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True, extra="forbid")
