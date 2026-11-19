"""V19 TDA: one locally pinned GLiNER/DeBERTa M4, no V1 path.

M1/M2/M3/M5 deterministic safety checks remain independent of M4
hypotheses. M6/M7 receive source-exact candidates but never infer permissions.
Unknown/unverified semantic behavior cannot approve a tool.
"""
from __future__ import annotations

import json
import re
from typing import Any

from app.services.tda.configuration import (
    FINDING_DECISION_BLOCK, FINDING_DECISION_REVIEW,
    STATUS_BLOCKED, STATUS_QUARANTINED, STATUS_REVIEW_REQUIRED,
)
from app.services.tda.types import SemanticResult, EmbeddingModel
from app.services.tda.findings import _deduplicate_findings, _finding, _finding_decision
from app.services.tda.detectors import deterministic_findings
from app.services.tda.m1_sources.capture import capture_context
from app.services.tda.m3_instructions.semantic_input import _semantic_input_with_coverage
from app.services.tda.m7_assessment.m4_advisory import interpret_m4_directives_advisory
from app.services.tda.m3_instructions.pipeline import run_m3, M2Input, M5Input
from app.services.tda.m2_structure.views import collect_derived_views
from app.services.tda.m3_instructions.contracts import shadow_error
from app.services.tda.m3_instructions.decision_adapter import with_shadow_m3_report
from app.services.tda.m3_instructions.neural_shadow import (
    enabled as m3_v3_shadow_enabled,
)
from app.services.tda.m3_instructions.neural_shadow_async import (
    submit_v3_neural_shadow,
)
from app.services.tda.m4_semantics.consumer_contract import project_m4_for_consumers
from app.services.tda.m6_comparison.consistency import (
    inspect_m4_operations_advisory, consistency_result_from_m4, consistency_result,
)
from app.services.tda.m6_comparison.drift import (
    drift_result, _drift_findings,
)
from app.services.tda.m7_assessment.reduction import (
    summarize_m4_evidence_advisory, explain_risk,
)
from app.services.tda.security_guards.extraction import extract_tool_semantic_facts as extract_deterministic_safety_facts


MODEL_COMBINED = "GLINER2.5_BASE_PASS10+DEBERTA_V3_SMALL_V2"
MODEL_GLINER = "GLINER2.5_BASE_PASS10"
MODEL_DEBERTA = "DEBERTA_V3_SMALL_V2"


def _sha_identity(value: Any, error: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ValueError(error)
    return value


def analyze_tool_version(
    *,
    tool_snapshot: dict[str, Any],
    profile_snapshot: dict[str, Any] | None,
    baseline_snapshot: dict[str, Any] | None = None,
    m4_report: dict[str, Any] | None = None,
    m4_identity: str | None = None,
    m4_pipeline_identity: str | None = None,
    embedding_model: EmbeddingModel | None = None,
) -> dict[str, Any]:
    """Consume a checked source-bound M4 report.

    This pure function validates content-digest shapes and exact source.
    The caller verifies pinned weight bytes, local source closure, worker
    generation and observed tool fingerprint before persistence. No owner
    cryptographic signature is required.
    """
    model_identity = _sha_identity(
        m4_identity, "M4_MODEL_CONTENT_SHA256_REQUIRED"
    )
    pipeline_identity = _sha_identity(
        m4_pipeline_identity, "M4_V2_CONTENT_SHA256_REQUIRED"
    )
    if not isinstance(m4_report, dict):
        raise ValueError("M4_V2_REPORT_REQUIRED_NO_LEGACY_FALLBACK")

    context = capture_context(tool_snapshot, profile_snapshot, baseline_snapshot)
    snapshot = json.loads(context.original.json_bytes)
    profile = (
        json.loads(context.profile_json)
        if context.profile_json is not None else None
    )
    baseline = (
        json.loads(context.baseline_json)
        if context.baseline_json is not None else None
    )

    checked = project_m4_for_consumers(
        m4_report, str(snapshot.get("description") or "")
    )
    m4_views = {
        "model_report": checked,
        "m3": interpret_m4_directives_advisory(checked["m3"]),
        "m6": inspect_m4_operations_advisory(checked["m6"]),
        "m7": summarize_m4_evidence_advisory(checked["m7"]),
        "m4_model_identity_sha256": model_identity,
        "analyzer_pipeline_sha256": pipeline_identity,
    }

    # M2/M3/M6/M7 deterministic security evidence is independent of M4.
    # Re-homed from the old semantic package to security_guards; not a
    # competing M4 neural predictor and never runtime authorization.
    guard_facts = extract_deterministic_safety_facts(snapshot)
    findings = deterministic_findings(snapshot, profile, semantic_facts=guard_facts)
    # Lot 2: independent shadow observation only. M2's decoded views and M5's
    # cross-tool resolutions have no attested V0 interface yet, so both are
    # explicitly NOT_EXPOSED / NOT_RESOLVED, never fabricated or promoted.
    try:
        m2_views, m2_limits = collect_derived_views(context)
        m3_shadow = run_m3(context, M2Input(
            status="M2_ATTESTED_VIEWS", decoded_views=m2_views,
            transforms_verified=True, limitations=m2_limits), M5Input())
    except Exception as exc:
        # Shadow failures are visible and cannot suppress legacy BLOCK/REVIEW.
        # No untrusted error text or secrets are emitted.
        m3_shadow = shadow_error(context, type(exc).__name__)

    # M6 retains its original capability/contract verification and E5-based
    # drift implementation. M4 hypotheses are attached advisory-only.
    existing_consistency = consistency_result(
        snapshot, profile, semantic_facts=guard_facts
    )
    advisory_consistency = consistency_result_from_m4(
        snapshot, profile, m4_views["m6"]
    )
    consistency = dict(existing_consistency)
    consistency["m4_advisory_operations"] = advisory_consistency["m4_advisory_operations"]
    consistency["m4_capabilities_verified"] = False
    consistency["m4_unresolved"] = True
    findings.extend(existing_consistency["findings"])
    findings.extend(advisory_consistency["findings"])
    if embedding_model is None:
        raise ValueError("M6_E5_EMBEDDING_REQUIRED")
    drift = drift_result(baseline, snapshot, embedding_model)
    findings.extend(_drift_findings(drift))

    _, coverage = _semantic_input_with_coverage(snapshot)
    coverage["complete"] = False
    reasons = coverage.setdefault("incomplete_reasons", [])
    for item in (
        "M4_MODEL_HYPOTHESES_NOT_VERIFIED_RUNTIME_BEHAVIOR",
        "M4_INDEPENDENT_BEHAVIORAL_QUALIFICATION_REQUIRED",
    ):
        if item not in reasons:
            reasons.append(item)
    model_coverage = m4_report.get("coverage")
    model_coverage = model_coverage if isinstance(model_coverage, dict) else {}
    coverage["token_budget"] = {
        "complete": model_coverage.get("source_tokens_covered") is True,
        "status": "M4_SOURCE_COVERAGE_REPORTED_NOT_BEHAVIOR_VERIFIED",
    }
    findings.append(_finding(
        "analysis_coverage_incomplete", "analysis_coverage", "metadata",
        "medium", 70,
        "Description analysis is a grounded model hypothesis, not observed behavior.",
        "Require independent runtime/contract evidence and explicit ADMIN review.",
        decision=FINDING_DECISION_REVIEW,
    ))
    findings = _deduplicate_findings(findings)

    blocked = any(
        _finding_decision(finding) == FINDING_DECISION_BLOCK
        for finding in findings
    )
    status = (
        STATUS_BLOCKED if blocked else
        STATUS_QUARANTINED if profile is None else
        STATUS_REVIEW_REQUIRED
    )
    review_status = STATUS_BLOCKED if blocked else STATUS_REVIEW_REQUIRED
    version = "pipeline-sha256:" + pipeline_identity
    model_result = SemanticResult(
        scores={}, best_category="m4_structured_events_not_a_risk_classifier",
        confidence=0.0, model_name=MODEL_COMBINED,
        model_version=version, flagged=False,
        coverage=coverage["token_budget"],
    )
    risk_evidence = explain_risk(
        findings, model_result, drift, coverage, m4_views["m7"]
    )
    risk_score = risk_evidence["risk_score"]
    risk_level = risk_evidence["risk_level"]
    shadow_effects = {
        "revision": "m4-structured-events-v19",
        "status": "MODEL_HYPOTHESES_UNVERIFIED",
        "shadow_only": True, "creates_permissions": False,
        "claims": m4_views["m6"]["semantic_operation_candidates"],
        "unresolved_semantic_reasons": list(guard_facts.unknown_reasons),
        "limitations": [
            "neural_metadata_not_runtime_behavior",
            "no_model_generated_permissions",
        ],
    }
    proposition_shadow = {
        "schema": "tool-propositions-v1",
        "status": "NOT_EVALUATED_IN_M4_NEURAL_PATH",
        "shadow_only": True, "creates_permissions": False,
        "propositions": [],
        "omissions": [{"reason": "legacy_m4_extractor_retired"}],
        "coverage": {
            "proposition_discovery": {
                "complete": None, "status": "NOT_EVALUATED"
            }
        },
    }
    legacy_result = {
        "analysis_status": status,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "semantic_flagged": False,
        "deterministic_critical_finding": blocked,
        "consistency_status": consistency["status"],
        "drift_status": drift.status,
        "review_status": review_status,
        "coverage": coverage,
        "shadow_effects": shadow_effects,
        "proposition_shadow": proposition_shadow,
        "semantic_scores": {
            "scores": {},
            "best_category": model_result.best_category,
            "confidence": 0.0,
            "threshold": None,
            "model_best_category": model_result.best_category,
            "model_flagged": False,
            "corroborated": False,
            "flagged": False,
            "abstained": True,
            # Sensitivity must NOT be reset to False by a missing M4 prediction.
            "facts": {
                **guard_facts.to_dict(),
                "source": "INDEPENDENT_DETERMINISTIC_SAFETY_GUARDS",
                "model_behavior_proven": False,
            },
            "unresolved_unknown_reasons": list(guard_facts.unknown_reasons),
            "raw_unknown_reasons": list(guard_facts.unknown_reasons),
            "contract_bounded_unknowns": [],
            "unknown_policy": "A_REQUIRE_REVIEW",
            "authorization_evidence": {
                "contract_present": profile is not None,
                "declared_contract_hash": (profile or {}).get("contract_hash"),
                "authority_verified_here": False,
                "note": "M4 cannot authorize capabilities or runtime execution.",
            },
            "coverage": coverage,
            "shadow_effects": shadow_effects,
            "proposition_shadow": proposition_shadow,
            "m4_structured_semantics": m4_views,
            "m7_risk_evidence": risk_evidence,
            "m4_asserted_authority": "NONE",
            "historic_deterministic_guard_still_active": True,
        },
        "consistency_result": consistency,
        "drift_result": {
            "status": drift.status, "changes": drift.changes,
            "similarity": drift.similarity,
        },
        "model_versions": {
            "semantic": {"name": MODEL_COMBINED, "version": version},
            "m4_gliner": {"name": MODEL_GLINER, "version": version},
            "m4_deberta": {"name": MODEL_DEBERTA, "version": version},
            "embedding": {
                "name": getattr(embedding_model, "model_name", "intfloat/multilingual-e5-small"),
                "version": getattr(embedding_model, "model_version", "test-unversioned"),
            },
        },
        "findings": findings,
    }
    result = with_shadow_m3_report(legacy_result, m3_shadow)
    # Neural SHADOW is a bounded, non-blocking, process-local research queue.
    # The initial report contains a PENDING ticket, never an inline verdict.
    # Worker failure, result expiry and queue overflow cannot change legacy
    # BLOCK/REVIEW decisions or grant access. Default OFF.
    if m3_v3_shadow_enabled():
        result["m3_report"]["neural_shadow"] = submit_v3_neural_shadow(context)
        result["m3_report"]["limitations"].append(
            "M3_PG2_V3_SHADOW_NOT_QUALIFIED_FOR_ENFORCEMENT"
        )
    return result
