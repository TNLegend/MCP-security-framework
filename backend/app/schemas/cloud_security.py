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

class IAMComparisonRequest(BaseModel):
    mcp_server_id: int = Field(gt=0, le=1000000)
    instance_id: str = Field(pattern=r"^i-[0-9a-f]{8}(?:[0-9a-f]{9})?$")
    model_config = ConfigDict(extra="forbid")


class IAMComparisonPublic(BaseModel):
    id: str
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
