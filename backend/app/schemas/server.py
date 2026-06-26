from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict


class MCPServerCreate(BaseModel):
    name: str = "unknown-mcp-server"
    server_type: str = "mcp"
    endpoint: str
    status: str = "active"
    protocol_version: str | None = None
    server_info_name: str | None = None
    server_info_title: str | None = None
    server_info_version: str | None = None
    server_info_description: str | None = None
    server_info_icons: list[dict[str, Any]] | None = None
    server_info_website_url: str | None = None
    capabilities: dict[str, Any] | None = None
    instructions: str | None = None
    transport: str = "streamable_http"
    raw_initialize_result: dict[str, Any] | None = None
    trust_status: str = "unknown"
    security_status: str = "not_analyzed"
    last_seen_at: datetime | None = None
    last_scan_at: datetime | None = None
    notes: str | None = None


class MCPServerRead(MCPServerCreate):
    id: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
