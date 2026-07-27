from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool

from app.schemas.policy_decision import (
    PolicyEffect,
    PolicyObligationType,
    PolicySeverity,
)


class PolicyShadowStatus(str, Enum):
    MATCH = "match"
    MISMATCH = "mismatch"
    ERROR = "error"


class PolicyShadowMismatchField(str, Enum):
    EFFECT = "effect"
    OBLIGATIONS = "obligations"
    RULE_IDS = "rule_ids"
    SEVERITY = "severity"


class PolicyShadowMismatchRisk(str, Enum):
    NONE = "none"
    DANGEROUS = "dangerous"
    CONSERVATIVE = "conservative"
    BEHAVIORAL = "behavioral"
    UNKNOWN = "unknown"


class PolicyShadowComparison(BaseModel):
    status: PolicyShadowStatus
    match: StrictBool | None
    mismatch_fields: list[PolicyShadowMismatchField] = Field(default_factory=list)
    mismatch_risk: PolicyShadowMismatchRisk
    authoritative_engine: Literal["legacy_yaml"]
    shadow_engine: Literal["opa"]
    authoritative_effect: PolicyEffect
    shadow_effect: PolicyEffect | None
    authoritative_rule_ids: list[str] = Field(default_factory=list)
    shadow_rule_ids: list[str] = Field(default_factory=list)
    authoritative_obligations: list[PolicyObligationType] = Field(default_factory=list)
    shadow_obligations: list[PolicyObligationType] = Field(default_factory=list)
    authoritative_severity: PolicySeverity
    shadow_severity: PolicySeverity | None
    shadow_policy_revision: str | None
    error_code: str | None

    model_config = ConfigDict(extra="forbid")
