from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.routes_tool_analysis import _analysis_payload, _finding_payload
from app.db.database import get_db
from app.models.mcp_tool import MCPTool
from app.models.tool_analysis import ToolAnalysis, ToolAnalysisFinding
from app.schemas.control_plane import ToolReviewRequest
from app.services.control_plane_audit import record_control_plane_audit
from app.services.control_plane_auth import (
    AuthenticatedControlPlaneUser,
    require_admin,
    require_authenticated_user,
)
from app.services.server_security_metadata import refresh_server_security_status
from app.services.tda_application.review_service import ToolReviewService
from app.services.tda.m3_instructions.neural_shadow_async import (
    lookup_v3_neural_shadow_job, async_shadow_queue_health,
    list_v3_neural_shadow_jobs_for_admin,
)

router = APIRouter(
    prefix="/control-plane/tool-analysis",
    tags=["Control Plane Tool Analysis"],
)


@router.get("/shadow/health")
def m3_v3_shadow_health(
    _: AuthenticatedControlPlaneUser = Depends(require_admin),
):
    """Admin-only; read-only research SHADOW status, never a policy action."""
    return {
        "mode": "SHADOW",
        "model": "PROMPT_GUARD_2_86M_V3",
        "authority": "NONE",
        "production_approved": False,
        "scope": "PROCESS_LOCAL_EPHEMERAL_ONLY",
        "worker": async_shadow_queue_health(),
    }


@router.get("/shadow/jobs")
def m3_v3_shadow_jobs(
    _: AuthenticatedControlPlaneUser = Depends(require_admin),
):
    """Admin-only, ephemeral research list; source text never returned."""
    return {
        "mode": "SHADOW",
        "authority": "NONE",
        "production_approved": False,
        "scope": "SAME_BACKEND_PROCESS_ONLY",
        "jobs": list_v3_neural_shadow_jobs_for_admin(),
    }


@router.get("/shadow/jobs/{job_id}")
def m3_v3_shadow_job_detail(
    job_id: str,
    source_sha256: str,
    _: AuthenticatedControlPlaneUser = Depends(require_admin),
):
    """Admin-only, source-bound lookup. No endpoint for public users."""
    import re
    if (re.fullmatch(r"[0-9a-f]{32}", job_id) is None
            or re.fullmatch(r"[0-9a-f]{64}", source_sha256) is None):
        raise HTTPException(status_code=404, detail="Shadow result unavailable")
    result = lookup_v3_neural_shadow_job(
        job_id, source_sha256=source_sha256,
    )
    if result is None:
        raise HTTPException(status_code=404, detail="Shadow result unavailable")
    return result


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
    tool = db.get(MCPTool, tool_id)
    if tool is not None:
        refresh_server_security_status(db, tool.server_id)
    record_control_plane_audit(
        db,
        actor=current.user,
        action="TOOL_ADMIN_ALLOWED",
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
    tool = db.get(MCPTool, tool_id)
    if tool is not None:
        refresh_server_security_status(db, tool.server_id)
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
