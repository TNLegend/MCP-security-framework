"""Bounded, closed-schema Runtime explanation admitted into audit storage.

Only codes and safe identifiers are accepted. Raw arguments, policy context,
resource names, credentials and exception messages are deliberately absent.
"""
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

RuntimeCheck = Literal[
    "IDENTITY_NOT_VERIFIED", "SESSION_NOT_ACTIVE",
    "SUBJECT_AUTHORIZATION_NOT_RESOLVED", "SERVER_NOT_TRUSTED",
    "ARGUMENTS_INVALID", "TOOL_ANALYSIS_NOT_APPROVED",
    "CRITICAL_DETERMINISTIC_FINDING", "REVIEW_NOT_APPROVED",
    "SENSITIVE_RESOURCE", "SIGNED_CONTRACT_BINDING_INVALID",
    "TOOL_APPROVAL_BINDING_INVALID", "NORMALIZED_REQUEST_INVALID",
    "EFFECT_SET_MISMATCH", "EFFECT_NOT_AUTHORIZED",
]
EffectCheck = Literal[
    "CAPABILITY_NOT_GRANTED", "CAPABILITY_NOT_ACTIVE_OR_UNKNOWN",
    "EFFECT_FACT_MISSING_OR_INCONSISTENT", "RESOURCE_CARDINALITY_EXCEEDED",
    "RESOURCE_BINDING_OR_SCOPE_UNAUTHORIZED",
]


class RuntimeFailedEffect(BaseModel):
    check: EffectCheck
    effect_id: str = Field(min_length=1, max_length=128, pattern=r"^[a-z0-9._-]+$")
    capability: str = Field(min_length=1, max_length=128, pattern=r"^[a-z0-9._-]+$")

    model_config = ConfigDict(extra="forbid")


class RuntimeExplanation(BaseModel):
    explanation_version: Literal[1]
    scope: Literal["runtime_security_model_v2"]
    failed_checks: list[RuntimeCheck] = Field(max_length=32)
    failed_effects: list[RuntimeFailedEffect] = Field(max_length=32)

    model_config = ConfigDict(extra="forbid")
