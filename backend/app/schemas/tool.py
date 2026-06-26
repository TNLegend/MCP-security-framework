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
    risk_score: int = 0
    sensitivity: str = "low"
    description_risk_score: int = 0
    policy_status: str = "not_reviewed"
    is_sensitive: bool = False
    last_analyzed_at: datetime | None = None
    status: str = "active"


class MCPToolRead(MCPToolCreate):
    id: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
