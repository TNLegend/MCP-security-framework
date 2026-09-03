from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator, model_validator

from app.services.subject_authorization import SubjectAuthorizationDocument
from proxy.identity_binding import IdentityBindingDocument
from proxy.security_packs import SecurityPackInstallation, SecurityPackManifest
from proxy.tool_security_v2 import (
    AdapterResolution,
    AuthorityResourceScope,
    ToolObservationApproval,
    ToolSecurityContract,
)


ControlPlaneRole = Literal["ADMIN", "VIEWER"]
ConfigRevisionStatus = Literal["DRAFT", "PUBLISHED", "ARCHIVED"]
PolicySeverity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
SUPPORTED_POLICY_SETTING_RULES = {"tool_analysis_required"}


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

    @model_validator(mode="after")
    def validate_supported_rules(self) -> "PolicySettings":
        unsupported = set(self.rules) - SUPPORTED_POLICY_SETTING_RULES
        if unsupported:
            raise ValueError("policy_settings contains unsupported rule settings.")
        tool_analysis = self.rules.get("tool_analysis_required")
        if tool_analysis is not None and not tool_analysis.enabled:
            raise ValueError("tool_analysis_required is mandatory and cannot be disabled.")
        return self


BuildSecurityGateMode = Literal["DISABLED", "ALLOW_WARN", "REQUIRE_PASS"]
BuildSecurityAssessmentStatus = Literal["PASS", "WARN", "BLOCK", "ERROR"]


class BuildSecurityEvidenceReference(BaseModel):
    server_ref: str = Field(min_length=1, max_length=1024)
    scan_id: str = Field(min_length=36, max_length=36)
    source_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_revision: str | None = Field(default=None, max_length=255)
    assessment_status: BuildSecurityAssessmentStatus
    assessment_policy_version: str = Field(min_length=1, max_length=128)
    required_scanners_complete: StrictBool
    completed_at: datetime

    model_config = ConfigDict(extra="forbid", frozen=True)

    @field_validator("server_ref", "scan_id", "source_revision", "assessment_policy_version")
    @classmethod
    def normalize_build_evidence_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            raise ValueError("Build Security evidence text values must not be empty.")
        return normalized

    @field_validator("completed_at")
    @classmethod
    def normalize_completed_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)


class BuildSecuritySettings(BaseModel):
    mode: BuildSecurityGateMode = "DISABLED"
    max_evidence_age_hours: int = Field(default=168, ge=1, le=8760, strict=True)
    evidence: tuple[BuildSecurityEvidenceReference, ...] = Field(
        default_factory=tuple,
        max_length=1000,
    )

    model_config = ConfigDict(extra="forbid", frozen=True)

    @model_validator(mode="after")
    def validate_build_evidence_uniqueness(self) -> "BuildSecuritySettings":
        server_refs = [item.server_ref for item in self.evidence]
        if len(server_refs) != len(set(server_refs)):
            raise ValueError("Build Security evidence must be unique per server_ref.")
        scan_ids = [item.scan_id for item in self.evidence]
        if len(scan_ids) != len(set(scan_ids)):
            raise ValueError("Build Security scan references must be unique.")
        return self


class AuthorityContext(BaseModel):
    separator: Literal["/", ".", ":"] = "/"
    case_sensitive: StrictBool = True
    max_depth: int = Field(default=32, ge=1, le=128, strict=True)
    filesystem_path_mode: Literal["RELATIVE_ROOTED", "ABSOLUTE"] = "RELATIVE_ROOTED"

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class ControlPlaneConfigContent(BaseModel):
    schema_version: Literal[2] = 2
    identity_bindings: IdentityBindingDocument
    agent_authorizations: SubjectAuthorizationDocument
    policy_settings: PolicySettings = Field(default_factory=PolicySettings)
    build_security: BuildSecuritySettings = Field(default_factory=BuildSecuritySettings)
    supported_schema_profile: Literal["supported-json-schema-v1"] = "supported-json-schema-v1"
    capability_catalog_version: Literal["2"] = "2"
    resource_type_registry_version: Literal["2"] = "2"
    security_packs: tuple[SecurityPackManifest, ...] = ()
    security_pack_installations: tuple[SecurityPackInstallation, ...] = ()
    tool_security_contracts: tuple[ToolSecurityContract, ...] = ()
    authority_resource_scopes: tuple[AuthorityResourceScope, ...] = ()
    adapter_resolutions: tuple[AdapterResolution, ...] = ()
    tool_observation_approvals: tuple[ToolObservationApproval, ...] = ()
    authority_contexts: dict[str, AuthorityContext] = Field(default_factory=dict)

    model_config = ConfigDict(extra="forbid")


def empty_latest_configuration() -> ControlPlaneConfigContent:
    return ControlPlaneConfigContent(
        identity_bindings=IdentityBindingDocument(
            revision="identity-bindings-1",
            bindings=[],
        ),
        agent_authorizations=SubjectAuthorizationDocument(
            revision="subject-authorizations-1",
            subjects={},
        ),
        policy_settings=PolicySettings(
            rules={
                "tool_analysis_required": PolicyRuleSettings(
                    enabled=True,
                    severity="HIGH",
                )
            }
        ),
    )


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
