from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator

from app.services.subject_authorization import SubjectAuthorizationDocument
from proxy.identity_binding import IdentityBindingDocument
from proxy.resource_registry import ResourceScopeDocument
from proxy.tool_security_profiles import ToolSecurityProfileDocument


ControlPlaneRole = Literal["ADMIN", "VIEWER"]
ConfigRevisionStatus = Literal["DRAFT", "PUBLISHED", "ARCHIVED"]
PolicySeverity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]


class ControlPlaneUserPublic(BaseModel):
    id: str
    username: str
    role: ControlPlaneRole
    enabled: bool
    display_name: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None
    last_login_at: datetime | None = None

    model_config = ConfigDict(from_attributes=True)


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=4096)

    model_config = ConfigDict(extra="forbid")


class LoginResponse(BaseModel):
    user: ControlPlaneUserPublic
    csrf_token: str
    expires_at: datetime


class CreateControlPlaneUserRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=8, max_length=4096)
    role: ControlPlaneRole
    display_name: str | None = Field(default=None, max_length=255)
    enabled: bool = True

    model_config = ConfigDict(extra="forbid")

    @field_validator("username")
    @classmethod
    def validate_username(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("username must not be empty.")
        if any(character.isspace() for character in normalized):
            raise ValueError("username must not contain whitespace.")
        return normalized


class PatchControlPlaneUserRequest(BaseModel):
    role: ControlPlaneRole | None = None
    display_name: str | None = Field(default=None, max_length=255)

    model_config = ConfigDict(extra="forbid")


class ResetPasswordRequest(BaseModel):
    new_password: str = Field(min_length=8, max_length=4096)
    reason: str = Field(min_length=3, max_length=1000)

    model_config = ConfigDict(extra="forbid")


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=4096)
    new_password: str = Field(min_length=8, max_length=4096)

    model_config = ConfigDict(extra="forbid")


class ReasonRequest(BaseModel):
    reason: str = Field(min_length=3, max_length=1000)

    model_config = ConfigDict(extra="forbid")


class PolicyRuleSettings(BaseModel):
    enabled: StrictBool
    severity: PolicySeverity

    model_config = ConfigDict(extra="forbid")


class PolicySettings(BaseModel):
    rules: dict[str, PolicyRuleSettings] = Field(default_factory=dict)

    model_config = ConfigDict(extra="forbid")


class ControlPlaneConfigContent(BaseModel):
    schema_version: Literal[1] = 1
    identity_bindings: IdentityBindingDocument
    agent_authorizations: SubjectAuthorizationDocument
    tool_security_profiles: ToolSecurityProfileDocument
    resource_scopes: ResourceScopeDocument
    policy_settings: PolicySettings = Field(default_factory=PolicySettings)

    model_config = ConfigDict(extra="forbid")


class ConfigRevisionPatchRequest(BaseModel):
    content: ControlPlaneConfigContent
    change_summary: str = Field(min_length=3, max_length=2000)

    model_config = ConfigDict(extra="forbid")


class ConfigRevisionActionRequest(BaseModel):
    change_summary: str = Field(min_length=3, max_length=2000)

    model_config = ConfigDict(extra="forbid")


class ConfigRevisionPublic(BaseModel):
    id: str
    revision_number: int
    status: ConfigRevisionStatus
    schema_version: int
    content: ControlPlaneConfigContent
    content_hash: str
    created_by: str | None = None
    created_at: datetime
    updated_at: datetime
    published_by: str | None = None
    published_at: datetime | None = None
    parent_revision_id: str | None = None
    change_summary: str | None = None

    model_config = ConfigDict(from_attributes=True)


class ToolReviewRequest(BaseModel):
    fingerprint: str = Field(min_length=64, max_length=64)
    justification: str = Field(min_length=8, max_length=2000)

    model_config = ConfigDict(extra="forbid")
