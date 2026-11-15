"""Non-authoritative, provider-neutral preflight for future MCP auto-admission.

SHADOW ONLY: this module does NOT approve observations, publish revisions,
sign anything, grant capabilities, or change Gateway/Proxy admission.
The input data is caller-supplied and therefore cannot establish signature,
identity, provenance, or live authority. A positive result ONLY describes
candidate eligibility for a future separately authenticated workflow.
"""

from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Literal


@dataclass(frozen=True)
class ShadowDelegationBounds:
    """Bounds that a future *verified, signed* policy must provide.

    The mere construction of this value DOES NOT verify a signature.
    """

    policy_id: str
    enabled: bool
    server_refs: frozenset[str]
    protocol_profiles: frozenset[str]
    tool_names: frozenset[str]
    contract_hashes: frozenset[str]
    permitted_capabilities: frozenset[str]
    permitted_scopes: frozenset[str]
    analyzer_revisions: frozenset[str]
    model_artifact_digests: frozenset[str]
    expires_at: datetime
    max_observations: int
    observations_so_far: int


@dataclass(frozen=True)
class ShadowObservationEvidence:
    """Reported observations. All authority claims require external verification."""

    server_ref: str
    protocol_profile: str
    tool_name: str
    current_fingerprint: str
    observed_fingerprint: str
    contract_hash: str
    published_contract_hash: str
    analyzer_revision: str
    model_artifact_digest: str
    analysis_status: str
    review_status: str
    deterministic_critical_finding: bool
    semantic_risk_flagged: bool
    coverage_complete: bool
    unresolved_unknowns: tuple[str, ...]
    human_review_hold: bool
    emergency_deny: bool
    observation_stale: bool
    schema_compiled: bool
    evidence_frozen: bool
    pipeline_current: bool
    server_binding_verified: bool
    contract_published: bool
    necessary_capabilities: frozenset[str]
    subject_granted_capabilities: frozenset[str]
    necessary_scopes: frozenset[str]
    subject_granted_scopes: frozenset[str]


@dataclass(frozen=True)
class ShadowPreflightVerdict:
    status: Literal["SHADOW_CANDIDATE", "SHADOW_NOT_ELIGIBLE"]
    reasons: tuple[str, ...]
    policy_id: str
    creates_permissions: bool = False
    approves_observation: bool = False
    may_dispatch: bool = False
    authorization_verified: bool = False


def evaluate_shadow_auto_admission(
    bounds: ShadowDelegationBounds,
    evidence: ShadowObservationEvidence,
    *,
    now: datetime,
) -> ShadowPreflightVerdict:
    """Evaluate *diagnostic* conditions without treating caller data as trust.

    Even if all conditions are met, the result is never sufficient for
    observation approval, signed configuration publication or MCP dispatch.
    The future authority issuer MUST independently re-read live trusted state.
    """
    problems: list[str] = []

    def require(condition: bool, reason: str) -> None:
        if not condition:
            problems.append(reason)

    require(bool(bounds.policy_id.strip()), "policy_id_missing")
    require(bounds.enabled, "delegation_disabled")
    require(bool(bounds.server_refs), "server_scope_missing")
    require(bool(bounds.protocol_profiles), "protocol_scope_missing")
    require(bool(bounds.tool_names), "tool_scope_missing")
    require(bool(bounds.contract_hashes), "contract_scope_missing")
    require(bool(bounds.permitted_capabilities), "capability_scope_missing")
    require(bool(bounds.analyzer_revisions), "analyzer_revision_scope_missing")
    require(bool(bounds.model_artifact_digests), "model_version_scope_missing")
    require(
        now.tzinfo is not None and now.utcoffset() is not None,
        "current_time_not_timezone_aware",
    )
    require(
        bounds.expires_at.tzinfo is not None
        and bounds.expires_at.utcoffset() is not None,
        "delegation_expiry_not_timezone_aware",
    )
    if (
        now.tzinfo is not None
        and now.utcoffset() is not None
        and (bounds.expires_at.tzinfo is not None)
        and (bounds.expires_at.utcoffset() is not None)
    ):
        require(
            now.astimezone(timezone.utc) < bounds.expires_at.astimezone(timezone.utc),
            "delegation_expired",
        )
    require(
        bounds.max_observations > 0
        and 0 <= bounds.observations_so_far < bounds.max_observations,
        "admission_budget_exhausted",
    )
    require(evidence.server_ref in bounds.server_refs, "server_not_pre_authorized")
    require(
        evidence.protocol_profile in bounds.protocol_profiles,
        "protocol_profile_not_pre_authorized",
    )
    require(evidence.tool_name in bounds.tool_names, "tool_not_pre_authorized")
    require(
        evidence.contract_hash in bounds.contract_hashes, "contract_not_pre_authorized"
    )
    require(
        evidence.contract_hash == evidence.published_contract_hash,
        "contract_not_currently_published",
    )
    require(
        len(evidence.current_fingerprint) == 64
        and evidence.current_fingerprint == evidence.observed_fingerprint,
        "observation_fingerprint_mismatch",
    )
    require(
        evidence.analyzer_revision in bounds.analyzer_revisions,
        "analyzer_revision_untrusted",
    )
    require(
        evidence.model_artifact_digest in bounds.model_artifact_digests,
        "model_artifact_untrusted",
    )
    require(evidence.analysis_status == "APPROVED", "analysis_not_approved")
    require(evidence.review_status == "APPROVED", "review_not_approved")
    require(not evidence.deterministic_critical_finding, "critical_finding_present")
    require(not evidence.semantic_risk_flagged, "semantic_risk_present")
    require(evidence.coverage_complete, "analysis_coverage_incomplete")
    require(not evidence.unresolved_unknowns, "semantic_unknowns_unresolved")
    require(not evidence.human_review_hold, "human_review_hold")
    require(not evidence.emergency_deny, "emergency_deny_active")
    require(not evidence.observation_stale, "observation_stale")
    require(evidence.schema_compiled, "schema_not_compiled")
    require(evidence.evidence_frozen, "analysis_evidence_not_frozen")
    require(evidence.pipeline_current, "analyzer_pipeline_not_current")
    require(evidence.server_binding_verified, "server_identity_not_verified")
    require(evidence.contract_published, "contract_not_published")
    require(
        bool(evidence.necessary_capabilities)
        and evidence.necessary_capabilities <= bounds.permitted_capabilities,
        "contract_capabilities_outside_delegation",
    )
    require(
        evidence.necessary_capabilities <= evidence.subject_granted_capabilities,
        "subject_capabilities_insufficient",
    )
    require(
        evidence.necessary_scopes <= bounds.permitted_scopes,
        "resource_scope_outside_delegation",
    )
    require(
        evidence.necessary_scopes <= evidence.subject_granted_scopes,
        "subject_resource_scopes_insufficient",
    )
    return ShadowPreflightVerdict(
        status="SHADOW_NOT_ELIGIBLE" if problems else "SHADOW_CANDIDATE",
        reasons=tuple(problems),
        policy_id=bounds.policy_id,
    )
