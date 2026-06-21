from datetime import datetime

from pydantic import BaseModel, ConfigDict


class MCPToolCreate(BaseModel):
    server_id: int
    name: str
    description: str | None = None
    risk_score: int = 0
    status: str = "active"


class MCPToolRead(MCPToolCreate):
    id: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
