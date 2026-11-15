from __future__ import annotations
from app.services.tda.types import AnalysisFinding
from app.services.tda.configuration import CRITICAL_DETERMINISTIC_CODES
from app.services.tda.configuration import FINDING_DECISION_BLOCK
from app.services.tda.configuration import FINDING_DECISION_INFO
from app.services.tda.configuration import FINDING_DECISION_REVIEW
from app.services.tda.serialization import _safe_excerpt


def _finding(
    code: str,
    category: str,
    source: str,
    severity: str,
    confidence: int,
    evidence: str,
    recommendation: str,
    *,
    decision: str = FINDING_DECISION_REVIEW,
) -> AnalysisFinding:
    if decision not in {
        FINDING_DECISION_BLOCK,
        FINDING_DECISION_REVIEW,
        FINDING_DECISION_INFO,
    }:
        raise ValueError("invalid finding decision")
    return AnalysisFinding(
        code=code,
        category=category,
        source=source,
        severity=severity,
        confidence=max(0, min(100, int(confidence))),
        evidence={"summary": _safe_excerpt(evidence), "decision": decision},
        recommendation=recommendation,
    )


def _finding_decision(finding: AnalysisFinding) -> str:
    decision = finding.evidence.get("decision")
    if decision in {
        FINDING_DECISION_BLOCK,
        FINDING_DECISION_REVIEW,
        FINDING_DECISION_INFO,
    }:
        return str(decision)
    if finding.code in CRITICAL_DETERMINISTIC_CODES:
        return FINDING_DECISION_BLOCK
    return FINDING_DECISION_REVIEW


def _deduplicate_findings(findings: list[AnalysisFinding]) -> list[AnalysisFinding]:
    unique: dict[tuple[str, str, str], AnalysisFinding] = {}
    for finding in findings:
        key = (finding.code, finding.source, str(finding.evidence.get("summary") or ""))
        unique.setdefault(key, finding)
    return list(unique.values())
