from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models.mcp_tool import MCPTool
from app.models.tool_analysis import (
    ToolAnalysis,
    ToolAnalysisFinding,
    ToolApprovedBaseline,
    ToolHumanReview,
    ToolObservedVersion,
)

router = APIRouter(prefix="/tool-analysis", tags=["Tool Analysis"])


@router.get("/tools/{tool_id}/status")
def tool_analysis_status(tool_id: int, db: Session = Depends(get_db)):
    tool = _tool_or_404(tool_id, db)
    return {
        "tool_id": tool.id,
        "name": tool.name,
        "analysis_status": tool.analysis_status,
        "current_fingerprint": tool.current_fingerprint,
        "approved_fingerprint": tool.approved_fingerprint,
        "approved_fingerprint_match": tool.approved_fingerprint_match,
        "risk_score": tool.risk_score,
        "risk_level": tool.risk_level,
        "semantic_flagged": tool.semantic_flagged,
        "deterministic_critical_finding": tool.deterministic_critical_finding,
        "consistency_status": tool.consistency_status,
        "drift_status": tool.drift_status,
        "review_status": tool.review_status,
        "analyzer_revision": tool.analyzer_revision,
        "last_analyzed_at": tool.last_analyzed_at,
    }


@router.get("/tools/{tool_id}/versions")
def tool_versions(tool_id: int, db: Session = Depends(get_db)):
    _tool_or_404(tool_id, db)
    versions = db.scalars(
        select(ToolObservedVersion)
        .where(ToolObservedVersion.tool_id == tool_id)
        .order_by(ToolObservedVersion.id.desc())
    ).all()
    return [
        {
            "id": version.id,
            "fingerprint": version.fingerprint,
            "status": version.status,
            "profile_revision": version.profile_revision,
            "first_seen_at": version.first_seen_at,
            "last_seen_at": version.last_seen_at,
            "snapshot": _safe_snapshot(version.snapshot),
            "profile_snapshot": version.profile_snapshot,
        }
        for version in versions
    ]


@router.get("/tools/{tool_id}/analyses")
def tool_analyses(tool_id: int, db: Session = Depends(get_db)):
    _tool_or_404(tool_id, db)
    analyses = db.scalars(
        select(ToolAnalysis)
        .where(ToolAnalysis.tool_id == tool_id)
        .order_by(ToolAnalysis.id.desc())
    ).all()
    return [_analysis_payload(analysis) for analysis in analyses]


@router.get("/tools/{tool_id}/findings")
def tool_findings(tool_id: int, db: Session = Depends(get_db)):
    _tool_or_404(tool_id, db)
    analysis_ids = [
        analysis.id
        for analysis in db.scalars(
            select(ToolAnalysis.id).where(ToolAnalysis.tool_id == tool_id)
        ).all()
    ]
    if not analysis_ids:
        return []
    findings = db.scalars(
        select(ToolAnalysisFinding)
        .where(ToolAnalysisFinding.analysis_id.in_(analysis_ids))
        .order_by(ToolAnalysisFinding.id.desc())
    ).all()
    return [_finding_payload(finding) for finding in findings]


@router.get("/tools/{tool_id}/baseline")
def tool_baseline(tool_id: int, db: Session = Depends(get_db)):
    _tool_or_404(tool_id, db)
    baseline = db.scalar(
        select(ToolApprovedBaseline).where(ToolApprovedBaseline.tool_id == tool_id)
    )
    if baseline is None:
        return None
    return {
        "id": baseline.id,
        "tool_id": baseline.tool_id,
        "version_id": baseline.version_id,
        "analysis_id": baseline.analysis_id,
        "fingerprint": baseline.fingerprint,
        "reviewer": baseline.reviewer,
        "justification": baseline.justification,
        "analyzer_revision": baseline.analyzer_revision,
        "model_versions": baseline.model_versions,
        "approved_at": baseline.approved_at,
    }


@router.get("/tools/{tool_id}/reviews")
def tool_reviews(tool_id: int, db: Session = Depends(get_db)):
    _tool_or_404(tool_id, db)
    reviews = db.scalars(
        select(ToolHumanReview)
        .where(ToolHumanReview.tool_id == tool_id)
        .order_by(ToolHumanReview.id.desc())
    ).all()
    return [
        {
            "id": review.id,
            "tool_id": review.tool_id,
            "version_id": review.version_id,
            "analysis_id": review.analysis_id,
            "action": review.action,
            "fingerprint": review.fingerprint,
            "reviewer": review.reviewer,
            "justification": review.justification,
            "created_at": review.created_at,
        }
        for review in reviews
    ]


@router.get("/tools/{tool_id}/diff")
def tool_diff(tool_id: int, db: Session = Depends(get_db)):
    latest = db.scalar(
        select(ToolAnalysis)
        .where(ToolAnalysis.tool_id == tool_id)
        .order_by(ToolAnalysis.id.desc())
    )
    if latest is None:
        return None
    return latest.drift_result


def _tool_or_404(tool_id: int, db: Session) -> MCPTool:
    tool = db.get(MCPTool, tool_id)
    if tool is None:
        raise HTTPException(status_code=404, detail="Tool not found")
    return tool


def _analysis_payload(analysis: ToolAnalysis) -> dict:
    return {
        "id": analysis.id,
        "tool_id": analysis.tool_id,
        "version_id": analysis.version_id,
        "fingerprint": analysis.fingerprint,
        "analysis_status": analysis.analysis_status,
        "risk_score": analysis.risk_score,
        "risk_level": analysis.risk_level,
        "semantic_flagged": analysis.semantic_flagged == "true",
        "deterministic_critical_finding": analysis.deterministic_critical_finding
        == "true",
        "consistency_status": analysis.consistency_status,
        "drift_status": analysis.drift_status,
        "review_status": analysis.review_status,
        "semantic_scores": analysis.semantic_scores,
        "consistency_result": analysis.consistency_result,
        "drift_result": analysis.drift_result,
        "model_versions": analysis.model_versions,
        "analyzer_revision": analysis.analyzer_revision,
        "created_at": analysis.created_at,
        "completed_at": analysis.completed_at,
    }


def _finding_payload(finding: ToolAnalysisFinding) -> dict:
    return {
        "id": finding.id,
        "analysis_id": finding.analysis_id,
        "code": finding.code,
        "category": finding.category,
        "source": finding.source,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "evidence": finding.evidence,
        "recommendation": finding.recommendation,
        "created_at": finding.created_at,
    }


def _safe_snapshot(snapshot: dict) -> dict:
    safe = dict(snapshot)
    safe.pop("raw_tool_definition", None)
    return safe
