from __future__ import annotations
from app.services.tda.types import AnalysisFinding
from app.services.tda.types import DriftResult
from app.services.tda.types import SemanticResult
from app.services.tda.m6_comparison.drift import _drift_severity_score


def _risk_score(
    findings: list[AnalysisFinding], semantic_result: SemanticResult, drift: DriftResult
) -> int:
    import math

    severity_scores = {"low": 15, "medium": 35, "high": 70, "critical": 95}
    score = 0
    for finding in findings:
        score = max(score, severity_scores.get(finding.severity, 20))
    if semantic_result.flagged:
        score = max(40, score, int(math.ceil(semantic_result.confidence * 100)))
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
