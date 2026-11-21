"""Bounded, closed-schema Runtime explanation admitted into audit storage.

Only codes and safe identifiers are accepted. Raw arguments, policy context,
resource names, credentials and exception messages are deliberately absent.
"""
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

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


class RuntimeGuardExplanation(BaseModel):
    """Minimal proof of which framework-owned guard emitted a refusal.

    Does not contain the request, remote output, matching secret or any raw
    external data. Phase is validated against the versioned catalog.
    """
    explanation_version: Literal[1]
    source: Literal["proxy_internal_guard"]
    rule_id: Literal[
        "canonical_arguments_changed_before_execution",
        "cross_call_data_exfiltration_guard",
        "human_review_hold_active",
        "unsafe_resource_guard",
        "unsafe_tool_result_blocked",
        "specialized_adapter_result_blocked",
        "invalid_tool_arguments_guard",
        "unsupported_mcp_protocol_profile",
        "trusted_identity_required",
        "request_preparation_error",
        "shared_taint_persistence_failed",
        "runtime_audit_unavailable",
        "policy_error",
        "inventory_error",
        "dispatch_admission_unavailable",
        "unsupported_policy_decision_for_security_model",
    ]
    phase: Literal["PRE_POLICY", "PRE_DISPATCH", "RESULT_GUARD", "FAIL_CLOSED"]
    model_config = ConfigDict(extra="forbid")

    @model_validator(mode="after")
    def known_guard_phase(self):
        from shared.explanation_catalog import RUNTIME_GUARDS
        info = RUNTIME_GUARDS.get(self.rule_id)
        if info is None or self.phase != info["phase"]:
            raise ValueError("runtime_guard_phase_mismatch")
        return self
