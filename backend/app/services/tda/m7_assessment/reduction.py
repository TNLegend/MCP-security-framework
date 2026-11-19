from __future__ import annotations
from typing import Any
from hashlib import sha256
from app.services.tda.types import AnalysisFinding
from app.services.tda.types import DriftResult
from app.services.tda.types import SemanticResult
from app.services.tda.m6_comparison.drift import _drift_severity_score


def _risk_score(
    findings: list[AnalysisFinding], semantic_result: SemanticResult, drift: DriftResult
) -> int:
    severity_scores = {"low": 15, "medium": 35, "high": 70, "critical": 95}
    score = 0
    for finding in findings:
        score = max(score, severity_scores.get(finding.severity, 20))
    # Model-only hypotheses cannot increase deterministic risk; M4 is advisory.
    score = max(score, _drift_severity_score(drift.status))
    return min(100, score)


def _risk_level(score: int) -> str:
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 15:
        return "low"
    return "info"


def explain_risk(
    findings: list[AnalysisFinding],
    semantic_result: SemanticResult,
    drift: DriftResult,
    coverage: dict[str, Any],
    m4_advisory: dict[str, Any],
) -> dict[str, Any]:
    """Trace the deterministic MAX risk rule without claiming independence.

    This is an explanatory record, never an MCP allow/block/approval decision.
    """
    severity_scores = {"low": 15, "medium": 35, "high": 70, "critical": 95}
    drivers: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str]] = set()
    for finding in findings:
        evidence_summary = str(finding.evidence.get("summary") or "")
        summary_sha256 = sha256(evidence_summary.encode("utf-8")).hexdigest()
        key = (finding.code, finding.source, finding.severity, summary_sha256)
        if key in seen:
            continue
        seen.add(key)
        drivers.append({
            "source_type": "FINDING",
            "code": finding.code,
            "source_path": finding.source,
            "evidence_summary_sha256": summary_sha256,
            "severity": finding.severity,
            "contribution": severity_scores.get(finding.severity, 20),
        })
    drift_contribution = _drift_severity_score(drift.status)
    if drift_contribution:
        drivers.append({
            "source_type": "DRIFT",
            "status": drift.status,
            "contribution": drift_contribution,
        })
    drivers.sort(key=lambda row: (
        -row["contribution"], row["source_type"], row.get("code", ""),
        row.get("source_path", ""), row.get("severity", ""),
    ))
    score = _risk_score(findings, semantic_result, drift)
    if score != max((row["contribution"] for row in drivers), default=0):
        raise ValueError("M7_RISK_ATTRIBUTION_MISMATCH")
    reasons = coverage.get("incomplete_reasons") or []
    if not isinstance(reasons, list):
        reasons = ["COVERAGE_REASONS_MALFORMED"]
    unknown = sorted({value for value in reasons if isinstance(value, str)})
    return {
        "schema": "m7_deterministic_risk_evidence_v1",
        "risk_score": score,
        "risk_level": _risk_level(score),
        "contribution_rule": "MAX_NOT_SUM",
        "risk_drivers": drivers,
        "model_risk_authority": "NONE",
        "model_hypothesis_flagged": semantic_result.flagged,
        "corroboration_status": "NOT_ESTABLISHED",
        "conflict_status": "NOT_EVALUATED",
        "coverage": {
            "status": "COMPLETE" if coverage.get("complete") is True else "INCOMPLETE",
            "unknown_reasons": unknown,
            "not_evidence_of_safety": True,
        },
        "m4_advisory": {
            "events_seen": m4_advisory.get("events_seen"),
            "events_with_uncertainty": m4_advisory.get("events_with_uncertainty"),
            "independent_behavior_verified": False,
            "source_is_model_hypothesis": True,
        },
        "authorization_decision": "NOT_EVALUATED",
    }


def summarize_m4_evidence_advisory(view: dict[str, Any]) -> dict[str, Any]:
    if view.get("risk_or_approval_decision") != "NOT_EVALUATED":
        raise ValueError("M7_M4_UNEXPECTED_RISK_AUTHORITY")
    unresolved = view.get("events_with_uncertainty")
    count = view.get("events_seen")
    if not isinstance(unresolved, list) or type(count) is not int or count < 0:
        raise ValueError("M7_M4_INVALID_COVERAGE")
    if len(unresolved) > count:
        raise ValueError("M7_M4_IMPOSSIBLE_UNCERTAINTY_COUNT")
    return {
        "module": "M7", "mode": "ADVISORY",
        "events_seen": count,
        "events_with_uncertainty": len(unresolved),
        "unresolved_prediction_count": view.get("unresolved_prediction_count"),
        "source_token_coverage": view.get("source_token_coverage"),
        "confidence_is_calibrated": False,
        "independent_behavior_verified": False,
        "risk_decision": "NOT_EVALUATED",
        "approval_decision": "NOT_EVALUATED",
    }
