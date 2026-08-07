import re
from typing import Any, Annotated, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    field_validator,
    model_validator,
)


MAX_CANONICAL_RESOURCE_LENGTH = 4096
MAX_VALIDATION_ERROR_CODES = 20
MAX_VALIDATION_ERROR_CODE_LENGTH = 128
IDENTIFIER_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")


NonEmptyString = Annotated[str, Field(min_length=1)]
PositiveInt = Annotated[int, Field(gt=0)]
Score = Annotated[float, Field(ge=0.0, le=100.0, strict=True)]
CapabilityIdentifier = Annotated[str, Field(min_length=1, max_length=128)]
ScopeIdentifier = Annotated[str, Field(min_length=1, max_length=128)]
ValidationErrorCode = Annotated[
    str,
    Field(min_length=1, max_length=MAX_VALIDATION_ERROR_CODE_LENGTH),
]


class PolicyCapabilityGrant(BaseModel):
    capability: CapabilityIdentifier
    scopes: list[ScopeIdentifier] = Field(default_factory=list)

    model_config = ConfigDict(extra="forbid", frozen=True)

    @field_validator("capability")
    @classmethod
    def validate_capability(cls, value: str) -> str:
        return _validate_identifier(value, "capability")

    @field_validator("scopes")
    @classmethod
    def validate_scopes(cls, value: list[str]) -> list[str]:
        seen = set()
        for scope in value:
            _validate_identifier(scope, "scope")
            if scope in seen:
                raise ValueError("scope values must be unique per grant.")
            seen.add(scope)
        return value


class PolicySubject(BaseModel):
    agent_id: NonEmptyString
    identity_status: Literal["verified", "unverified"] = "unverified"
    identity_issuer: str = "unknown"
    identity_binding_revision: str = "unknown"
    session_status: str = "unknown"
    session_reference: str = "unknown"
    role: str = "unknown"
    authorization_status: Literal["resolved", "unknown"] = "unknown"
    authorization_revision: str = "unknown"
    grants: list[PolicyCapabilityGrant] = Field(default_factory=list)
    # Compatibility/observability only; not authoritative for enforcement.
    allowed_capabilities: list[str] = Field(default_factory=list)
    # Compatibility/observability only; not authoritative for enforcement.
    allowed_scopes: list[str] = Field(default_factory=list)

    model_config = ConfigDict(extra="forbid")

    @field_validator("agent_id")
    @classmethod
    def validate_agent_id(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("agent_id must not be empty.")
        return value

    @field_validator("role")
    @classmethod
    def validate_role(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("role must not be empty.")
        return value

    @field_validator("identity_issuer")
    @classmethod
    def validate_identity_issuer(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("identity_issuer must not be empty.")
        return value

    @field_validator("identity_binding_revision")
    @classmethod
    def validate_identity_binding_revision(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("identity_binding_revision must not be empty.")
        return value

    @field_validator("session_status")
    @classmethod
    def validate_session_status(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("session_status must not be empty.")
        return value

    @field_validator("session_reference")
    @classmethod
    def validate_session_reference(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("session_reference must not be empty.")
        return value

    @field_validator("authorization_revision")
    @classmethod
    def validate_authorization_revision(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("authorization_revision must not be empty.")
        return value

    @model_validator(mode="after")
    def validate_authorization_consistency(self) -> "PolicySubject":
        if self.identity_status == "verified":
            if not self.identity_issuer.strip():
                raise ValueError("verified identities require an identity issuer.")
            if not self.identity_binding_revision.strip():
                raise ValueError(
                    "verified identities require an identity binding revision."
                )

        if self.identity_status == "unverified":
            if self.authorization_status == "resolved":
                raise ValueError(
                    "unverified identities cannot have resolved authorization."
                )
            if self.grants:
                raise ValueError("unverified identities must not include grants.")

        if self.authorization_status == "unknown" and self.grants:
            raise ValueError("unknown subjects must not include grants.")

        if (
            self.authorization_status == "resolved"
            and not self.authorization_revision.strip()
        ):
            raise ValueError("resolved subjects require an authorization revision.")

        capabilities = [grant.capability for grant in self.grants]
        if len(capabilities) != len(set(capabilities)):
            raise ValueError("grant capabilities must be unique per subject.")

        return self


class PolicyServerContext(BaseModel):
    id: PositiveInt
    endpoint: NonEmptyString
    server_ref: str = "unknown"
    known: StrictBool = True
    trusted: StrictBool = True
    trust_status: str = "unknown"
    security_status: str | None = None

    model_config = ConfigDict(extra="forbid")

    @field_validator("endpoint")
    @classmethod
    def validate_endpoint(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("endpoint must not be empty.")
        return value

    @field_validator("server_ref")
    @classmethod
    def validate_server_ref(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("server_ref must not be empty.")
        return value


class PolicyToolContext(BaseModel):
    id: PositiveInt
    name: NonEmptyString
    profile_status: str = "unknown"
    profile_revision: str = "unknown"
    risk_score: Score = 0.0
    sensitivity: str = "unknown"
    capabilities: list[str] = Field(default_factory=list)
    admission_status: str = "unknown"
    description_risk_score: Score = 0.0
    capability_mismatch: StrictBool = False
    drift_status: str = "unknown"
    analysis_status: str = "missing"
    current_fingerprint: str | None = None
    approved_fingerprint_match: StrictBool = False
    risk_level: str = "unknown"
    semantic_flagged: StrictBool = False
    deterministic_critical_finding: StrictBool = False
    consistency_status: str = "unknown"
    review_status: str = "missing"
    analyzer_revision: str = "unknown"

    model_config = ConfigDict(extra="forbid")

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("name must not be empty.")
        return value

    @field_validator("profile_status")
    @classmethod
    def validate_profile_status(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("profile_status must not be empty.")
        return value

    @field_validator("profile_revision")
    @classmethod
    def validate_profile_revision(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("profile_revision must not be empty.")
        return value

    @field_validator("analysis_status", "risk_level", "consistency_status", "drift_status", "review_status", "analyzer_revision")
    @classmethod
    def validate_analysis_fact(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("analysis facts must not be empty.")
        return value


class PolicyRequestContext(BaseModel):
    operation: str = "unknown"
    resource_adapter: str = "unknown"
    resource_type: str = "unknown"
    resource_scope: str = "unknown"
    required_capability: CapabilityIdentifier
    canonical_resource: Annotated[
        str | None,
        Field(max_length=MAX_CANONICAL_RESOURCE_LENGTH),
    ] = None
    arguments: dict[str, Any] = Field(default_factory=dict)
    arguments_valid: StrictBool
    validation_error_codes: list[ValidationErrorCode] = Field(
        default_factory=list,
        max_length=MAX_VALIDATION_ERROR_CODES,
    )
    resource_sensitivity: str = "unknown"
    resource_resolution_status: str = "unknown"
    resource_flags: list[ValidationErrorCode] = Field(default_factory=list)
    resource_registry_revision: str = "unknown"
    tool_profile_revision: str = "unknown"
    operation_allowed_on_scope: StrictBool = False
    estimated_output_size_mb: Annotated[float, Field(ge=0.0, strict=True)] = 0.001

    model_config = ConfigDict(extra="forbid")

    @model_validator(mode="after")
    def validate_argument_consistency(self) -> "PolicyRequestContext":
        if self.arguments_valid and self.validation_error_codes:
            raise ValueError(
                "validation_error_codes must be empty when arguments_valid is true."
            )

        if not self.arguments_valid and not self.validation_error_codes:
            raise ValueError(
                "validation_error_codes must not be empty when arguments_valid is false."
            )

        if not self.arguments_valid and self.canonical_resource is not None:
            raise ValueError(
                "canonical_resource must be null when arguments_valid is false."
            )

        if self.canonical_resource is not None and not self.arguments_valid:
            raise ValueError(
                "canonical_resource requires arguments_valid to be true."
            )

        return self

    @field_validator("required_capability")
    @classmethod
    def validate_required_capability(cls, value: str) -> str:
        return _validate_identifier(value, "required_capability")


class PolicyRuntimeContext(BaseModel):
    environment: str = "local"
    session_id: NonEmptyString

    model_config = ConfigDict(extra="forbid")

    @field_validator("session_id")
    @classmethod
    def validate_session_id(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("session_id must not be empty.")
        return value


class RuntimePolicyInput(BaseModel):
    subject: PolicySubject
    server: PolicyServerContext
    tool: PolicyToolContext
    request: PolicyRequestContext
    runtime: PolicyRuntimeContext

    model_config = ConfigDict(extra="forbid")


def _validate_identifier(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must not be empty.")
    if not IDENTIFIER_PATTERN.fullmatch(value):
        raise ValueError(f"{field_name} has invalid format.")
    return value
