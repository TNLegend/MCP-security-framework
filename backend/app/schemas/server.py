from datetime import datetime

from pydantic import BaseModel, ConfigDict


class MCPServerCreate(BaseModel):
    name: str
    server_type: str
    endpoint: str
    status: str = "active"


class MCPServerRead(MCPServerCreate):
    id: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
