from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, model_validator

from common.upstream_auth import (
    AUTH_MODE_NONE,
    UpstreamAuthError,
    validate_upstream_auth_config,
)


class MCPServerBase(BaseModel):
    name: str = "unknown-mcp-server"
    server_type: str = "mcp"
    endpoint: str
    auth_mode: str = AUTH_MODE_NONE
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
    detected_protocol_era: str | None = None
    supported_protocol_versions: list[str] | None = None
    preferred_protocol_version: str | None = None
    negotiated_protocol_version: str | None = None
    protocol_transport_kind: str | None = None
    protocol_verdict_expires_at: datetime | None = None
    supported_protocol_profiles: list[str] | None = None
    preferred_upstream_profile: str | None = None
    last_protocol_probe_at: datetime | None = None
    protocol_probe_status: str | None = None
    protocol_probe_error: str | None = None
    trust_status: str = "unknown"
    security_status: str = "not_analyzed"
    last_seen_at: datetime | None = None
    last_scan_at: datetime | None = None
    notes: str | None = None


class MCPServerCreate(MCPServerBase):
    credential_ref: str | None = None

    @model_validator(mode="after")
    def validate_upstream_auth(self) -> "MCPServerCreate":
        try:
            self.auth_mode, self.credential_ref = validate_upstream_auth_config(
                self.auth_mode,
                self.credential_ref,
            )
        except UpstreamAuthError as exc:
            raise ValueError(str(exc)) from exc
        return self


class MCPServerRead(MCPServerBase):
    id: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class MCPServerInternalRead(MCPServerRead):
    credential_ref: str | None = None
