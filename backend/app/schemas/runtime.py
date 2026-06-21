from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict


class RuntimeCallCreate(BaseModel):
    agent_id: str
    session_id: str
    server_id: int | str | None = None
    tool_name: str
    arguments_summary: dict[str, Any] | None = None
    status: str


class RuntimeCallRead(BaseModel):
    id: int
    agent_id: str
    session_id: str
    server_id: int | None = None
    tool_name: str
    arguments_summary: dict[str, Any] | None = None
    status: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
