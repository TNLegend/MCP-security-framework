from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.routes_tool_analysis import _analysis_payload, _finding_payload
from app.db.database import get_db
from app.models.tool_analysis import ToolAnalysis, ToolAnalysisFinding
from app.schemas.control_plane import ToolReviewRequest
from app.services.control_plane_audit import record_control_plane_audit
from app.services.control_plane_auth import (
    AuthenticatedControlPlaneUser,
    require_admin,
    require_authenticated_user,
)
from app.services.tool_analysis import ToolReviewService

router = APIRouter(
    prefix="/control-plane/tool-analysis",
    tags=["Control Plane Tool Analysis"],
)


@router.get("/analyses")
def list_analyses(
    _: AuthenticatedControlPlaneUser = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
):
    analyses = db.scalars(select(ToolAnalysis).order_by(ToolAnalysis.id.desc())).all()
    return [_analysis_payload(analysis) for analysis in analyses]


@router.get("/analyses/{analysis_id}")
def analysis_detail(
    analysis_id: int,
    _: AuthenticatedControlPlaneUser = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
):
    analysis = db.get(ToolAnalysis, analysis_id)
    if analysis is None:
        raise HTTPException(status_code=404, detail="Analysis not found")
    findings = db.scalars(
        select(ToolAnalysisFinding)
        .where(ToolAnalysisFinding.analysis_id == analysis_id)
        .order_by(ToolAnalysisFinding.id.asc())
    ).all()
    payload = _analysis_payload(analysis)
    payload["findings"] = [_finding_payload(finding) for finding in findings]
    return payload


@router.post("/tools/{tool_id}/approve")
def approve_tool(
    tool_id: int,
    payload: ToolReviewRequest,
    current: AuthenticatedControlPlaneUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    try:
        baseline = ToolReviewService().approve(
            db=db,
            tool_id=tool_id,
            fingerprint=payload.fingerprint,
            reviewer=current.user.username,
            justification=payload.justification,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    record_control_plane_audit(
        db,
        actor=current.user,
        action="TOOL_APPROVED",
        target_type="mcp_tool",
        target_id=str(tool_id),
        reason=payload.justification,
        after_json={
            "fingerprint": baseline.fingerprint,
            "analysis_id": baseline.analysis_id,
        },
    )
    db.commit()
    return {"ok": True, "fingerprint": baseline.fingerprint}


@router.post("/tools/{tool_id}/block")
def block_tool(
    tool_id: int,
    payload: ToolReviewRequest,
    current: AuthenticatedControlPlaneUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    try:
        review = ToolReviewService().block(
            db=db,
            tool_id=tool_id,
            fingerprint=payload.fingerprint,
            reviewer=current.user.username,
            justification=payload.justification,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    record_control_plane_audit(
        db,
        actor=current.user,
        action="TOOL_BLOCKED",
        target_type="mcp_tool",
        target_id=str(tool_id),
        reason=payload.justification,
        after_json={"fingerprint": review.fingerprint, "analysis_id": review.analysis_id},
    )
    db.commit()
    return {"ok": True, "fingerprint": review.fingerprint}
