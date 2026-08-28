from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models.mcp_tool import MCPTool
from app.schemas.controlled_ai import (
    ControlledAIAssistancePublic,
    ControlledAIAssistanceRequest,
)
from app.services.control_plane_audit import record_control_plane_audit
from app.services.control_plane_auth import (
    AuthenticatedControlPlaneUser,
    require_admin,
)
from app.services.controlled_ai_assistance import (
    ControlledAIAssistanceError,
    generate_controlled_ai_assistance,
)


router = APIRouter(
    prefix="/control-plane/ai-assistance",
    tags=["Control Plane AI Assistance"],
)


@router.post(
    "/tools/{tool_id}",
    response_model=ControlledAIAssistancePublic,
)
def assist_tool_analysis(
    tool_id: int,
    payload: ControlledAIAssistanceRequest,
    request: Request,
    current: AuthenticatedControlPlaneUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    tool = db.get(MCPTool, tool_id)
    if tool is None or tool.status == "archived":
        raise HTTPException(status_code=404, detail="Tool not found")

    try:
        result = generate_controlled_ai_assistance(
            db,
            tool=tool,
            mode=payload.mode,
            question=payload.question,
            draft_revision_id=payload.draft_revision_id,
        )
    except ControlledAIAssistanceError as exc:
        record_control_plane_audit(
            db,
            actor=current.user,
            action="AI_ASSISTANCE_FAILED",
            target_type="mcp_tool",
            target_id=str(tool.id),
            source_ip=request.client.host if request.client else None,
            result="FAILED",
            metadata={
                "mode": payload.mode,
                "error_code": exc.code,
                "fingerprint": tool.current_fingerprint,
            },
        )
        db.commit()
        status_code = 409 if exc.code == "controlled_ai_current_analysis_required" else 503
        if exc.code in {
            "v2_draft_required",
            "controlled_ai_configuration_invalid",
            "controlled_ai_context_too_large",
            "controlled_ai_mode_unsupported",
            "controlled_ai_unknown_evidence_ref",
            "controlled_ai_unknown_template",
            "controlled_ai_unknown_adapter",
            "controlled_ai_contract_without_template",
            "controlled_ai_adapter_without_candidate",
        }:
            status_code = 400
        raise HTTPException(status_code=status_code, detail=exc.code) from exc

    record_control_plane_audit(
        db,
        actor=current.user,
        action="AI_ASSISTANCE_GENERATED",
        target_type="mcp_tool",
        target_id=str(tool.id),
        source_ip=request.client.host if request.client else None,
        after_json={
            "mode": result.mode,
            "provider": result.provider,
            "fallback_used": result.fallback_used,
            "fingerprint": result.fingerprint,
            "analysis_id": result.analysis_id,
            "recommended_action": result.recommended_action,
            "evidence_refs": result.evidence_refs,
            "template_ids": tuple(item.id for item in result.template_options),
            "adapter_ids": tuple(item.id for item in result.adapter_options),
            "draft_kind": result.draft_kind,
            "confidence": result.confidence,
            "non_authoritative": True,
            "can_mutate_runtime": False,
        },
        reason="Controlled AI advisory generated for explicit administrator review.",
    )
    db.commit()
    return result
