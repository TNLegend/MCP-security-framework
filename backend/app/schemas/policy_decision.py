from enum import Enum
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, model_validator


NonEmptyString = Annotated[str, Field(min_length=1)]


class PolicyEffect(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    DEFER = "DEFER"


class PolicySeverity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class PolicyObligationType(str, Enum):
    LOG = "LOG"
    WARN = "WARN"
    ALERT = "ALERT"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    LIMIT_OUTPUT = "LIMIT_OUTPUT"
    REDACT = "REDACT"
    RATE_LIMIT = "RATE_LIMIT"


class RuntimeDecision(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    WARN = "WARN"
    ASK_APPROVAL = "ASK_APPROVAL"
    LIMIT = "LIMIT"
    LOG_ONLY = "LOG_ONLY"


EXPECTED_EFFECT_BY_RUNTIME_DECISION = {
    RuntimeDecision.ALLOW: PolicyEffect.ALLOW,
    RuntimeDecision.BLOCK: PolicyEffect.DENY,
    RuntimeDecision.WARN: PolicyEffect.ALLOW,
    RuntimeDecision.ASK_APPROVAL: PolicyEffect.DEFER,
    RuntimeDecision.LIMIT: PolicyEffect.ALLOW,
    RuntimeDecision.LOG_ONLY: PolicyEffect.ALLOW,
}

REQUIRED_OBLIGATIONS_BY_RUNTIME_DECISION = {
    RuntimeDecision.ALLOW: {PolicyObligationType.LOG},
    RuntimeDecision.BLOCK: {PolicyObligationType.LOG, PolicyObligationType.ALERT},
    RuntimeDecision.WARN: {PolicyObligationType.WARN, PolicyObligationType.LOG},
    RuntimeDecision.ASK_APPROVAL: {
        PolicyObligationType.REQUIRE_APPROVAL,
        PolicyObligationType.LOG,
    },
    RuntimeDecision.LIMIT: {
        PolicyObligationType.LIMIT_OUTPUT,
        PolicyObligationType.LOG,
    },
    RuntimeDecision.LOG_ONLY: {PolicyObligationType.LOG},
}


class PolicyObligation(BaseModel):
    type: PolicyObligationType
    parameters: dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(extra="forbid")


class PolicyDecision(BaseModel):
    effect: PolicyEffect
    obligations: list[PolicyObligation] = Field(default_factory=list)
    rule_ids: list[NonEmptyString] = Field(min_length=1)
    reason: str = Field(min_length=1)
    severity: PolicySeverity
    evidence: dict[str, Any] = Field(default_factory=dict)
    recommended_action: str | None = None
    policy_revision: str = Field(min_length=1)
    decision: RuntimeDecision
    rule_id: str = Field(min_length=1)
    decision_id: str | None = None
    control_plane_revision_id: str | None = None
    control_plane_content_hash: str | None = None
    canonical_arguments_hash: str | None = None

    model_config = ConfigDict(extra="forbid")

    @model_validator(mode="after")
    def validate_decision_contract(self) -> "PolicyDecision":
        if self.rule_id not in self.rule_ids:
            raise ValueError("rule_id must be present in rule_ids.")

        obligation_types = [obligation.type for obligation in self.obligations]
        if len(obligation_types) != len(set(obligation_types)):
            raise ValueError("obligation types must be unique.")

        expected_effect = EXPECTED_EFFECT_BY_RUNTIME_DECISION[self.decision]
        if self.effect != expected_effect:
            raise ValueError("effect is not coherent with decision.")

        required_obligations = REQUIRED_OBLIGATIONS_BY_RUNTIME_DECISION[self.decision]
        if not required_obligations.issubset(set(obligation_types)):
            raise ValueError("decision is missing required obligations.")

        return self
