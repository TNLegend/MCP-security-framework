from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator

from common.mcp_endpoint import MCPEndpointValidationError, validate_mcp_endpoint
from common.upstream_oauth import UpstreamOAuthError, normalize_requested_scopes


class OAuthMCPRegistrationRequest(BaseModel):
    endpoint: str = Field(min_length=8, max_length=2048)
    protocol_version: str = Field(default="2025-11-25", min_length=4, max_length=32)
    client_id: str | None = Field(default=None, max_length=2048)
    requested_scopes: str = Field(default="", max_length=2048)
    client_secret: str | None = Field(default=None, max_length=4096)

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

    @field_validator("client_id")
    @classmethod
    def validate_client_id(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if any(character.isspace() or ord(character) < 32 for character in value):
            raise ValueError("upstream_oauth_client_id_invalid")
        return value

    @field_validator("requested_scopes")
    @classmethod
    def validate_scopes(cls, value: str) -> str:
        try:
            normalize_requested_scopes(value)
        except UpstreamOAuthError as exc:
            raise ValueError(str(exc)) from exc
        return value

    @field_validator("client_secret")
    @classmethod
    def validate_client_secret(cls, value: str | None) -> str | None:
        if value is not None and (not value.strip() or any(ord(character) < 32 for character in value)):
            raise ValueError("upstream_oauth_client_secret_invalid")
        return value


class OAuthConnectionStartResponse(BaseModel):
    authorization_url: str
    expires_at: str


class OAuthConnectionStatus(BaseModel):
    server_id: int
    oauth_status: str
