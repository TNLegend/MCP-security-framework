from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from common.mcp_endpoint import MCPEndpointValidationError, validate_mcp_endpoint
from common.upstream_oauth import UpstreamOAuthError, normalize_requested_scopes


class OAuthMCPRegistrationRequest(BaseModel):
    endpoint: str = Field(min_length=8, max_length=2048)
    protocol_version: str = Field(default="2025-11-25", min_length=4, max_length=32)
    client_id: str | None = Field(default=None, max_length=2048)
    requested_scopes: str = Field(default="", max_length=2048)
    client_secret: str | None = Field(default=None, max_length=4096)
    expected_authorization_server: str | None = Field(default=None, max_length=2048)

    model_config = ConfigDict(extra="forbid")

    @model_validator(mode="after")
    def require_authority_binding_for_pre_registered_secret(self):
        if self.client_secret and not self.expected_authorization_server:
            raise ValueError("upstream_oauth_expected_issuer_required_for_client_secret")
        return self

    @field_validator("expected_authorization_server")
    @classmethod
    def validate_expected_authorization_server(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        try:
            endpoint = validate_mcp_endpoint(normalized, resolve_dns=False)
        except MCPEndpointValidationError as exc:
            raise ValueError("upstream_oauth_expected_issuer_invalid") from exc
        if (
            endpoint.parsed.scheme != "https"
            and endpoint.hostname not in {"localhost", "127.0.0.1", "::1"}
        ):
            raise ValueError("upstream_oauth_expected_issuer_https_required")
        return normalized

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
