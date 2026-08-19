from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator, model_validator

from app.services.subject_authorization import SubjectAuthorizationDocument
from proxy.identity_binding import IdentityBindingDocument
from proxy.resource_registry import ResourceScopeDocument
from proxy.tool_security_profiles import ToolSecurityProfileDocument
from proxy.tool_security_v2 import (
    AdapterResolution,
    AuthorityResourceScope,
    ToolObservationApproval,
    ToolSecurityContract,
)


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


class AuthorityContext(BaseModel):
    separator: Literal["/", ".", ":"] = "/"
    case_sensitive: StrictBool = True
    max_depth: int = Field(default=32, ge=1, le=128, strict=True)
    filesystem_path_mode: Literal["RELATIVE_ROOTED", "ABSOLUTE"] = "RELATIVE_ROOTED"

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class ControlPlaneConfigContent(BaseModel):
    schema_version: Literal[1, 2] = 1
    identity_bindings: IdentityBindingDocument
    agent_authorizations: SubjectAuthorizationDocument
    tool_security_profiles: ToolSecurityProfileDocument | None = None
    resource_scopes: ResourceScopeDocument | None = None
    policy_settings: PolicySettings = Field(default_factory=PolicySettings)
    supported_schema_profile: Literal["supported-json-schema-v1"] | None = None
    capability_catalog_version: Literal["1"] | None = None
    resource_type_registry_version: Literal["1"] | None = None
    tool_security_contracts: tuple[ToolSecurityContract, ...] | None = None
    authority_resource_scopes: tuple[AuthorityResourceScope, ...] | None = None
    adapter_resolutions: tuple[AdapterResolution, ...] | None = None
    tool_observation_approvals: tuple[ToolObservationApproval, ...] | None = None
    authority_contexts: dict[str, AuthorityContext] | None = None

    model_config = ConfigDict(extra="forbid")

    @model_validator(mode="after")
    def validate_schema_generation(self) -> "ControlPlaneConfigContent":
        v2_fields: dict[str, Any] = {
            "supported_schema_profile": self.supported_schema_profile,
            "capability_catalog_version": self.capability_catalog_version,
            "resource_type_registry_version": self.resource_type_registry_version,
            "tool_security_contracts": self.tool_security_contracts,
            "authority_resource_scopes": self.authority_resource_scopes,
            "adapter_resolutions": self.adapter_resolutions,
            "tool_observation_approvals": self.tool_observation_approvals,
            "authority_contexts": self.authority_contexts,
        }
        if self.schema_version == 1:
            if self.tool_security_profiles is None or self.resource_scopes is None:
                raise ValueError("schema v1 requires legacy administrative documents.")
            if any(value is not None for value in v2_fields.values()):
                raise ValueError("schema v1 must not contain v2 security model fields.")
            return self

        if self.tool_security_profiles is not None or self.resource_scopes is not None:
            raise ValueError("schema v2 must not use legacy runtime security documents.")
        missing = [name for name, value in v2_fields.items() if value is None]
        if missing:
            raise ValueError(f"schema v2 is missing required fields: {','.join(missing)}")
        return self


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
    previous_revision_hash: str | None = None
    signature: str | None = None
    signature_key_id: str | None = None
    signature_algorithm: str | None = None
    signature_version: str | None = None

    model_config = ConfigDict(from_attributes=True)


class ToolReviewRequest(BaseModel):
    fingerprint: str = Field(min_length=64, max_length=64)
    justification: str = Field(min_length=8, max_length=2000)

    model_config = ConfigDict(extra="forbid")


class EmergencyDenyCreateRequest(BaseModel):
    target_type: Literal[
        "global",
        "agent_id",
        "framework_session_id",
        "server_ref",
        "server_tool",
    ]
    target_value: str | None = Field(default=None, min_length=1, max_length=512)
    target_secondary_value: str | None = Field(default=None, min_length=1, max_length=255)
    reason: str = Field(min_length=8, max_length=2000)
    expires_at: datetime

    model_config = ConfigDict(extra="forbid")

    @model_validator(mode="after")
    def validate_target(self) -> "EmergencyDenyCreateRequest":
        if self.target_type == "global":
            if self.target_value is not None or self.target_secondary_value is not None:
                raise ValueError("global deny must not contain target values.")
        elif self.target_type == "server_tool":
            if not self.target_value or not self.target_secondary_value:
                raise ValueError("server_tool deny requires server and tool values.")
        elif not self.target_value or self.target_secondary_value is not None:
            raise ValueError("deny target requires exactly one target value.")
        if self.expires_at.replace(tzinfo=None) <= datetime.utcnow():
            raise ValueError("emergency deny expiration must be in the future.")
        return self


class EmergencyDenyPublic(BaseModel):
    id: str
    target_type: str
    target_value: str | None
    target_secondary_value: str | None
    reason: str
    created_by: str
    created_at: datetime
    expires_at: datetime

    model_config = ConfigDict(from_attributes=True)
