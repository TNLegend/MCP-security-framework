from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict


class RuntimeCallCreate(BaseModel):
    agent_id: str
    session_id: str
    server_id: int | str | None = None
    tool_name: str
    arguments_summary: dict[str, Any] | str | None = None
    status: str = "created"
    decision: str | None = None
    rule_id: str | None = None
    decision_reason: str | None = None
    severity: str | None = None
    executed: bool = False
    execution_status: str | None = None
    result_summary: str | None = None
    error_summary: str | None = None


class RuntimeCallRead(BaseModel):
    id: int
    agent_id: str
    session_id: str
    server_id: int | None = None
    tool_name: str
    arguments_summary: dict[str, Any] | str | None = None
    status: str
    decision: str | None = None
    rule_id: str | None = None
    decision_reason: str | None = None
    severity: str | None = None
    executed: bool = False
    execution_status: str | None = None
    result_summary: str | None = None
    error_summary: str | None = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
