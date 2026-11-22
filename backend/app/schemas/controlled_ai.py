from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool


ControlledAIMode = Literal[
    "EXPLAIN",
    "RISK_SUMMARY",
    "SUGGEST_NEXT_STEP",
    "COMPARE_OPTIONS",
    "DRAFT_ONBOARDING",
]
ControlledAIRecommendedAction = Literal[
    "NO_CHANGE",
    "KEEP_BLOCKED",
    "HUMAN_REVIEW",
    "CREATE_CONTRACT_DRAFT",
    "CREATE_SECURITY_PACK_DRAFT",
    "REVIEW_ADAPTER",
    "REANALYZE",
]


class ControlledAIExpectedAnalysis(BaseModel):
    id: int = Field(gt=0)
    fingerprint: str = Field(min_length=64, max_length=64)
    context_hash: str | None = Field(default=None, min_length=64, max_length=64)
    analysis_status: str | None = Field(default=None, max_length=64)
    review_status: str | None = Field(default=None, max_length=64)

    model_config = ConfigDict(extra="forbid")


class ControlledAIAssistanceRequest(BaseModel):
    mode: ControlledAIMode
    question: str | None = Field(default=None, max_length=1000)
    draft_revision_id: str | None = Field(default=None, max_length=64)
    expected_analysis: ControlledAIExpectedAnalysis | None = None

    model_config = ConfigDict(extra="forbid")


class ControlledAIOptionPublic(BaseModel):
    id: str = Field(min_length=1, max_length=128)
    title: str = Field(min_length=1, max_length=256)
    reason: str = Field(min_length=1, max_length=1000)

    model_config = ConfigDict(extra="forbid")


class ControlledAIClaimPublic(BaseModel):
    type: str
    label: str
    value: str
    evidence_ref: str

    model_config = ConfigDict(extra="forbid")


class ControlledAIAssistancePublic(BaseModel):
    mode: ControlledAIMode
    provider: Literal["gemini", "groq"]
    fallback_used: StrictBool = False
    tool_id: int
    fingerprint: str = Field(min_length=64, max_length=64)
    analysis_id: int
    analysis_context_hash: str | None = Field(default=None, max_length=64)
    evidence_digest: str | None = Field(default=None, min_length=64, max_length=64)
    summary: str = Field(min_length=1, max_length=2500)
    # Compatibility field. Unverified provider prose is not returned by the service.
    ai_explanation: str | None = Field(default=None, max_length=1800)
    grounded_claims: tuple[ControlledAIClaimPublic, ...] = Field(default=(), max_length=12)
    risk_factors: tuple[str, ...] = Field(default=(), max_length=12)
    recommended_action: ControlledAIRecommendedAction
    rationale: str = Field(min_length=1, max_length=2500)
    evidence_refs: tuple[str, ...] = Field(default=(), max_length=32)
    template_options: tuple[ControlledAIOptionPublic, ...] = Field(default=(), max_length=8)
    adapter_options: tuple[ControlledAIOptionPublic, ...] = Field(default=(), max_length=8)
    draft_kind: Literal["NONE", "TEMPLATE_MAPPING", "SECURITY_PACK"] = "NONE"
    draft_preview: dict[str, Any] | None = None
    uncertainties: tuple[str, ...] = Field(default=(), max_length=12)
    confidence: float | None = Field(default=None, ge=0, le=1)
    non_authoritative: Literal[True] = True
    requires_human_review: Literal[True] = True
    can_mutate_runtime: Literal[False] = False

    model_config = ConfigDict(extra="forbid")
