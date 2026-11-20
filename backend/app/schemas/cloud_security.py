"""Validated public API shapes for Deploy Security. No secret fields."""
from __future__ import annotations
import re
from datetime import datetime
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

AWS_REGION = re.compile(r"^(af|ap|ca|cn|eu|il|me|mx|sa|us|us-gov)-[a-z]+(?:-[a-z]+)?-\d$")
AWS_PROFILE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
AWS_ROLE = re.compile(r"^arn:aws(?:-us-gov|-cn)?:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]{1,200}$")


class EnvironmentCreate(BaseModel):
    name: str = Field(min_length=3, max_length=128)
    regions: list[str] = Field(min_length=1, max_length=3)
    services: list[Literal["EC2", "S3", "IAM"]] = Field(default_factory=lambda: ["EC2", "S3", "IAM"], min_length=1, max_length=3)
    credential_mode: Literal["SDK_DEFAULT", "NAMED_PROFILE"] = "SDK_DEFAULT"
    profile_name: str | None = None
    role_arn: str | None = None
    model_config = ConfigDict(extra="forbid")

    @field_validator("name")
    @classmethod
    def valid_name(cls, v: str) -> str:
        v=v.strip()
        if not v or any(ord(c)<32 for c in v):
            raise ValueError("invalid_environment_name")
        return v

    @field_validator("regions")
    @classmethod
    def valid_regions(cls, v: list[str]) -> list[str]:
        if len(v)!=len(set(v)) or any(not AWS_REGION.fullmatch(x) for x in v):
            raise ValueError("invalid_aws_regions")
        return v

    @field_validator("services")
    @classmethod
    def unique_services(cls, value: list[str]) -> list[str]:
        if len(set(value)) != len(value):
            raise ValueError("duplicate_aws_service")
        return value

    @field_validator("profile_name")
    @classmethod
    def valid_profile(cls, v: str | None) -> str | None:
        if v is not None and not AWS_PROFILE.fullmatch(v):
            raise ValueError("invalid_aws_profile_name")
        return v

    @field_validator("role_arn")
    @classmethod
    def valid_role(cls, v: str | None) -> str | None:
        if v is not None and not AWS_ROLE.fullmatch(v):
            raise ValueError("invalid_aws_role_arn")
        return v

    @model_validator(mode="after")
    def check_auth(self):
        if self.credential_mode=="NAMED_PROFILE" and not self.profile_name:
            raise ValueError("profile_name_required")
        if self.credential_mode=="SDK_DEFAULT" and self.profile_name is not None:
            raise ValueError("profile_not_allowed_for_default_chain")
        return self


class EnvironmentPublic(BaseModel):
    id: str
    name: str
    provider: str
    account_id: str | None
    regions: list[str]
    services: list[str]
    credential_mode: str
    profile_name: str | None
    role_arn: str | None
    status: str
    last_error_code: str | None
    last_checked_at: datetime | None
    created_at: datetime
    model_config=ConfigDict(from_attributes=True, extra="forbid")


class ConnectionTestPublic(BaseModel):
    status: Literal["CONNECTED"]
    account_id: str
    caller_type: str
    regions: list[str]


class ScanPublic(BaseModel):
    id: str
    environment_id: str | None
    kind: str
    status: str
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    error_code: str | None
    resource_count: int
    finding_count: int
    unknown_checks: int
    scanner_version: str
    source_fingerprint: str | None = None
    source_file_count: int = 0
    model_config=ConfigDict(from_attributes=True, extra="forbid")


class ResourcePublic(BaseModel):
    id: str
    resource_type: str
    resource_arn: str
    region: str
    display_name: str
    safe_attributes: dict
    model_config=ConfigDict(from_attributes=True, extra="forbid")


class FindingPublic(BaseModel):
    id: str
    resource_id: str | None
    rule_id: str
    fingerprint: str
    severity: str
    result: str
    title: str
    description: str
    remediation: str | None
    model_config=ConfigDict(from_attributes=True, extra="forbid")


class EvidencePublic(BaseModel):
    id: str
    resource_id: str | None
    rule_id: str
    outcome: str
    evidence_sha256: str
    safe_summary: dict
    checked_at: datetime
    model_config=ConfigDict(from_attributes=True, extra="forbid")


class ScanEventPublic(BaseModel):
    id: str
    event_type: str
    message_code: str
    created_at: datetime
    model_config=ConfigDict(from_attributes=True, extra="forbid")


class ScanDetailPublic(BaseModel):
    scan: ScanPublic
    resources: list[ResourcePublic]
    findings: list[FindingPublic]
    evidence: list[EvidencePublic]
    events: list[ScanEventPublic]

class IAMMappingIdentity(BaseModel):
    kind: Literal["EC2", "ECS", "LAMBDA", "EKS_POD_IDENTITY"]
    region: str | None = Field(default=None, pattern=AWS_REGION.pattern)
    instance_id: str | None = Field(default=None, max_length=19)
    cluster: str | None = Field(default=None, max_length=100)
    task: str | None = Field(default=None, max_length=255)
    function_name: str | None = Field(default=None, max_length=64)
    namespace: str | None = Field(default=None, max_length=63)
    service_account: str | None = Field(default=None, max_length=63)
    association_id: str | None = Field(default=None, max_length=64)
    model_config = ConfigDict(extra="forbid")

    @model_validator(mode="after")
    def valid_workload(self):
        required = {
            "EC2": ("instance_id",),
            "ECS": ("cluster", "task"),
            "LAMBDA": ("function_name",),
            "EKS_POD_IDENTITY": ("cluster", "namespace", "service_account", "association_id"),
        }[self.kind]
        values = {field: getattr(self, field) for field in (
            "instance_id", "cluster", "task", "function_name", "namespace",
            "service_account", "association_id")}
        if any(bool(values[key]) != (key in required) for key in values):
            raise ValueError("iam_mapping_identity_fields_invalid")
        patterns = {
            "instance_id": r"i-[0-9a-f]{8}(?:[0-9a-f]{9})?",
            "cluster": r"[A-Za-z0-9_-]{1,100}",
            "task": r"[A-Za-z0-9_:/-]{1,255}",
            "function_name": r"[A-Za-z0-9_-]{1,64}",
            "namespace": r"[a-z0-9]([-a-z0-9]*[a-z0-9])?",
            "service_account": r"[a-z0-9]([-a-z0-9]*[a-z0-9])?",
            "association_id": r"a-[a-z0-9]{12,40}",
        }
        if any(values[k] is not None and not re.fullmatch(patterns[k], values[k])
               for k in values):
            raise ValueError("iam_mapping_identity_format_invalid")
        return self


class IAMMappingEntry(BaseModel):
    tool_name: str = Field(min_length=1, max_length=128,
                           pattern=r"^[A-Za-z0-9_.-]+$")
    effect_id: str = Field(min_length=1, max_length=160,
                           pattern=r"^[A-Za-z0-9_.-]+$")
    scope_id: str = Field(min_length=1, max_length=160,
                          pattern=r"^[A-Za-z0-9_.-]+$")
    action: str = Field(min_length=3, max_length=120,
                        pattern=r"^[a-z0-9]+:[A-Za-z0-9]+$")
    resource_template: str = Field(min_length=12, max_length=512)
    model_config = ConfigDict(extra="forbid")


class IAMMappingCreate(BaseModel):
    name: str = Field(min_length=3, max_length=128)
    mcp_server_id: int = Field(gt=0, le=1000000)
    identity: IAMMappingIdentity
    entries: list[IAMMappingEntry] = Field(min_length=1, max_length=100)
    model_config = ConfigDict(extra="forbid")

    @field_validator("name")
    @classmethod
    def valid_mapping_name(cls, value: str) -> str:
        name = value.strip()
        if len(name)<3 or any(ord(ch)<32 for ch in name):
            raise ValueError("invalid_iam_mapping_name")
        return name

    @model_validator(mode="after")
    def no_duplicate_mapping(self):
        ids = [(e.tool_name, e.effect_id, e.action, e.scope_id,
                e.resource_template) for e in self.entries]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate_iam_mcp_mapping")
        return self


class IAMMappingApprove(BaseModel):
    confirm: Literal[True]
    model_config = ConfigDict(extra="forbid")


class IAMMappingPublic(BaseModel):
    id: str
    environment_id: str
    mcp_server_id: int
    name: str
    configuration: dict
    status: str
    signed_revision: int
    signed_content_hash: str
    approval_digest: str | None
    created_by: str
    approved_by: str | None
    created_at: datetime
    approved_at: datetime | None
    model_config = ConfigDict(from_attributes=True, extra="forbid")


class IAMComparisonRequest(BaseModel):
    mapping_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    model_config = ConfigDict(extra="forbid")


class IAMComparisonPublic(BaseModel):
    id: str
    identity_permission_status: str | None
    effective_permission_status: str | None
    tool_name: str | None
    expected_resource_arn: str | None
    policy_digest: str | None
    signed_revision: int | None
    mcp_server_id: int | None
    role_arn: str | None
    status: str
    expected_actions: list[str]
    observed_actions: list[str]
    notes: str | None
    model_config = ConfigDict(from_attributes=True, extra="forbid")
