from typing import Any, Literal
from uuid import UUID
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from common.mcp_endpoint import MCPEndpointValidationError, validate_mcp_endpoint
from common.upstream_auth import (
    AUTH_MODE_NONE,
    UpstreamAuthError,
    validate_upstream_auth_config,
)


class DiscoveredMCPServer(BaseModel):
    endpoint: str
    transport: str = "streamable_http"
    protocol_version: str | None = None
    detected_protocol_era: str | None = None
    supported_protocol_versions: list[str] | None = None
    preferred_protocol_version: str | None = None
    negotiated_protocol_version: str | None = None
    protocol_transport_kind: str | None = None
    protocol_verdict_expires_at: datetime | None = None
    server_info_name: str | None = None
    server_info_title: str | None = None
    server_info_version: str | None = None
    server_info_description: str | None = None
    server_info_icons: list[dict[str, Any]] | None = None
    server_info_website_url: str | None = None
    capabilities: dict[str, Any] | None = None
    instructions: str | None = None
    raw_initialize_result: dict[str, Any] | None = None
    supported_protocol_profiles: list[str] | None = None
    preferred_upstream_profile: str | None = None
    protocol_probe_status: str | None = None
    protocol_probe_error: str | None = None
    auth_mode: str = AUTH_MODE_NONE
    credential_ref: str | None = None

    @model_validator(mode="after")
    def validate_upstream_auth(self) -> "DiscoveredMCPServer":
        try:
            self.auth_mode, self.credential_ref = validate_upstream_auth_config(
                self.auth_mode,
                self.credential_ref,
            )
        except UpstreamAuthError as exc:
            raise ValueError(str(exc)) from exc
        return self


class DiscoveredMCPTool(BaseModel):
    name: str
    title: str | None = None
    description: str | None = None
    icons: list[dict[str, Any]] | None = None
    input_schema: dict[str, Any] | None = None
    output_schema: dict[str, Any] | None = None
    annotations: dict[str, Any] | None = None
    execution: dict[str, Any] | None = None
    raw_tool_definition: dict[str, Any] | None = None
    upstream_protocol_profile_id: str | None = None


class DiscoveryImportPayload(BaseModel):
    server: DiscoveredMCPServer
    tools: list[DiscoveredMCPTool] = []
    generation_id: str | None = None
    reserved_profile_id: str | None = Field(default=None, max_length=100)
    # The signed reservation records the caller's requested protocol hint;
    # tools/list may negotiate a different supported version.
    reserved_protocol_version: str | None = Field(default=None, max_length=50)

    @field_validator("generation_id")
    @classmethod
    def validate_generation_id(cls, value: str | None) -> str | None:
        if value is not None:
            UUID(value)
        return value


class DiscoveryReservationRequest(BaseModel):
    endpoint: str = Field(min_length=8, max_length=2048)
    transport: Literal["streamable_http", "sse"] = "streamable_http"
    protocol_version: str | None = Field(default=None, max_length=50)
    auth_mode: str = AUTH_MODE_NONE
    credential_ref: str | None = Field(default=None, max_length=128)
    profile_id: str | None = Field(default=None, max_length=100)

    model_config = ConfigDict(extra="forbid")

    @model_validator(mode="after")
    def validate_auth(self) -> "DiscoveryReservationRequest":
        try:
            self.auth_mode, self.credential_ref = validate_upstream_auth_config(
                self.auth_mode, self.credential_ref
            )
        except UpstreamAuthError as exc:
            raise ValueError(str(exc)) from exc
        return self

    @field_validator("endpoint")
    @classmethod
    def validate_endpoint(cls, value: str) -> str:
        try:
            validate_mcp_endpoint(value, resolve_dns=False)
        except MCPEndpointValidationError as exc:
            raise ValueError(str(exc)) from exc
        return value


class DiscoveryRequest(BaseModel):
    endpoint: str = Field(min_length=8, max_length=2048)
    protocol_version: str = Field(default="2025-11-25", min_length=4, max_length=32)
    auth_mode: str = AUTH_MODE_NONE
    credential_ref: str | None = Field(default=None, max_length=128)

    model_config = ConfigDict(extra="forbid")

    @field_validator("endpoint")
    @classmethod
    def validate_endpoint(cls, value: str) -> str:
        normalized = value.strip()
        try:
            validate_mcp_endpoint(normalized, resolve_dns=False)
        except MCPEndpointValidationError as exc:
            raise ValueError(str(exc)) from exc
        return normalized

    @model_validator(mode="after")
    def validate_upstream_auth(self) -> "DiscoveryRequest":
        try:
            self.auth_mode, self.credential_ref = validate_upstream_auth_config(
                self.auth_mode,
                self.credential_ref,
            )
        except UpstreamAuthError as exc:
            raise ValueError(str(exc)) from exc
        return self
