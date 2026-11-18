from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.routes_servers import list_servers_from_db
from app.api.routes_tools import list_tools_from_db
from app.db.database import get_db
from app.models.mcp_tool import MCPTool
from app.models.tool_analysis import ToolAnalysis, ToolHumanReview
from app.schemas.server import MCPServerInternalRead
from app.schemas.tool import MCPToolRead
from app.services.signed_service_request import (
    PERMISSION_EMERGENCY_DENY_CHECK,
    PERMISSION_RUNTIME_DISPATCH_ADMIT,
    PERMISSION_INTERNAL_INVENTORY_SERVERS_READ,
    PERMISSION_INTERNAL_INVENTORY_TOOLS_READ,
    VerifiedServiceRequest,
    require_internal_service_permission,
)
from app.services.emergency_deny import check_emergency_deny
from app.services.dispatch_admission import admit_mcp_dispatch
from proxy.tool_security_v2 import security_schema_projection

from app.services.tda.configuration import STATUS_ADMIN_ALLOWED, STATUS_APPROVED, STATUS_STALE
from app.services.tda_application.queries import latest_protocol_observation
from app.services.tda_application._integrity import PipelineIntegrityError

router = APIRouter(prefix="/internal", tags=["Internal Service APIs"])


class EmergencyDenyCheckRequest(BaseModel):
    agent_id: str = Field(min_length=1, max_length=128)
    framework_session_id: str = Field(min_length=1, max_length=255)
    server_ref: str = Field(min_length=1, max_length=512)
    tool_name: str = Field(min_length=1, max_length=255)

    model_config = ConfigDict(extra="forbid")


@router.get("/inventory/servers", response_model=list[MCPServerInternalRead])
def list_internal_inventory_servers(
    _: VerifiedServiceRequest = Depends(
        require_internal_service_permission(PERMISSION_INTERNAL_INVENTORY_SERVERS_READ)
    ),
    db: Session = Depends(get_db),
):
    return list_servers_from_db(db)


@router.get("/inventory/tools", response_model=list[MCPToolRead])
def list_internal_inventory_tools(
    _: VerifiedServiceRequest = Depends(
        require_internal_service_permission(PERMISSION_INTERNAL_INVENTORY_TOOLS_READ)
    ),
    db: Session = Depends(get_db),
):
    return list_tools_from_db(db)


@router.get("/inventory/tool-observation")
def get_internal_inventory_tool_observation(
    server_id: int = Query(gt=0),
    tool_name: str = Query(min_length=1, max_length=255),
    upstream_protocol_profile_id: str = Query(min_length=1, max_length=100),
    _: VerifiedServiceRequest = Depends(
        require_internal_service_permission(PERMISSION_INTERNAL_INVENTORY_TOOLS_READ)
    ),
    db: Session = Depends(get_db),
):
    if db.get_bind().dialect.name == "postgresql":
        from sqlalchemy import text
        from app.services.control_plane_config import CONFIG_REVISION_LOCK_KEY
        from app.services.dispatch_admission import lock_emergency_dispatch_authority
        db.execute(text("SELECT pg_advisory_xact_lock(:key)"),{"key":CONFIG_REVISION_LOCK_KEY})
        lock_emergency_dispatch_authority(db,require_postgresql=True)
    tool = db.scalar(
        select(MCPTool).execution_options(populate_existing=True).where(
            MCPTool.server_id == server_id,
            MCPTool.name == tool_name,
        )
    )
    if tool is None:
        return None
    observation = latest_protocol_observation(
        db,
        tool_id=tool.id,
        upstream_protocol_profile_id=upstream_protocol_profile_id,
    )
    if observation is None:
        return None
    db.refresh(observation)
    # Human holds are tool/fingerprint-wide. A profile-specific observation
    # must not bypass an ADMIN block recorded against another profile.
    latest_review = db.scalar(
        select(ToolHumanReview).execution_options(populate_existing=True)
        .where(
            ToolHumanReview.tool_id == tool.id,
            ToolHumanReview.fingerprint == observation.tool_fingerprint,
        )
        .order_by(ToolHumanReview.id.desc())
        .limit(1)
    )
    tool_wide_review_hold = bool(
        latest_review is not None
        and latest_review.action in {"block", "keep_review_required"}
    )
    analysis = db.get(ToolAnalysis, observation.analysis_id, populate_existing=True) if observation.analysis_id else None
    definition = observation.canonical_tool_definition
    # Exposure is bound to this observation; shared metadata is not a fallback.
    if not isinstance(definition, dict):
        return None
    if definition.get("tool_name") != tool.name:
        return None
    description = definition.get("description", "")
    if not isinstance(description, str):
        return None
    analysis_status = (
        STATUS_STALE
        if observation.analysis_state == STATUS_STALE
        else (analysis.analysis_status if analysis is not None else observation.analysis_state)
    )
    review_status = (
        STATUS_STALE
        if observation.analysis_state == STATUS_STALE
        else (analysis.review_status if analysis is not None else "missing")
    )
    approved_match = (
        analysis_status in {STATUS_APPROVED, STATUS_ADMIN_ALLOWED}
        and analysis is not None and analysis.tool_id==tool.id
        and analysis.fingerprint==observation.tool_fingerprint
        and review_status in {STATUS_APPROVED, STATUS_ADMIN_ALLOWED}
        and observation.analysis_state != STATUS_STALE
        and not tool_wide_review_hold
    )
    if approved_match:
        from app.services.tda_application.authority import (
            assert_current, verified_observation_token,
        )
        try:
            # One current SHA-256 identity check for this decision.
            # Preserve active-generation fencing and exact evidence checks.
            token = verified_observation_token(analysis)
            assert_current(db, token)
            from app.services.tda_application.authority import (
                assert_analysis_generation_current,
            )
            assert_analysis_generation_current(db, analysis.id, token)
            from app.services.published_configuration import PublishedConfigurationProvider
            from app.models.tool_analysis import ToolObservationReviewApproval
            from app.services.tda_application.observation_approval import evidence_bundle_for_observation
            from common.canonical_json import sha256_canonical_json
            snapshot=PublishedConfigurationProvider(db).load_active_snapshot(fresh=True)
            approval=snapshot.get_tool_observation_approval(server_ref=observation.server_ref,
                upstream_protocol_profile_id=observation.upstream_protocol_profile_id,
                tool_fingerprint=observation.tool_fingerprint)
            contract=snapshot.get_tool_security_contract(server_ref=observation.server_ref,tool_name=observation.tool_name)
            if approval.tool_observation_id!=observation.id or approval.contract_hash!=contract.contract_hash:
                return None
            live=db.scalar(select(ToolObservationReviewApproval.id).where(
                ToolObservationReviewApproval.observation_id==observation.id,
                ToolObservationReviewApproval.revision_id==approval.revision_id,
                ToolObservationReviewApproval.evidence_bundle_hash==approval.evidence_bundle_hash,
                ToolObservationReviewApproval.active.is_(True)))
            if live is None or sha256_canonical_json(evidence_bundle_for_observation(db,observation))!=approval.evidence_bundle_hash:
                return None
        except (ValueError, PipelineIntegrityError):
            # Changed analyzer source invalidates previous observation approval.
            # Reject exposure rather than returning HTTP 500 or trusting old data.
            return None
    return {
        "id": tool.id,
        "server_id": tool.server_id,
        "name": tool.name,
        "title": tool.title,
        "description": description,
        "icons": tool.icons,
        "input_schema": security_schema_projection(
            definition.get("input_schema") or {}
        ),
        "output_schema": definition.get("output_schema") or {},
        "annotations": definition.get("annotations") or {},
        "execution": definition.get("execution") or {},
        # Profile-specific routing hints must come from that profile's
        # observed immutable definition, never the shared MCPTool metadata.
        "raw_tool_definition": {
            "name": tool.name,
            "description": description,
            "inputSchema": definition.get("input_schema") or {},
            "outputSchema": definition.get("output_schema") or {},
            "annotations": definition.get("annotations") or {},
            "execution": definition.get("execution") or {},
        },
        "risk_score": analysis.risk_score if analysis is not None else tool.risk_score,
        "sensitivity": tool.sensitivity,
        "description_risk_score": tool.description_risk_score,
        "policy_status": analysis_status,
        "is_sensitive": tool.is_sensitive,
        "last_analyzed_at": (
            (analysis.completed_at or analysis.created_at)
            if analysis is not None
            else tool.last_analyzed_at
        ),
        "current_fingerprint": observation.tool_fingerprint,
        "approved_fingerprint": observation.tool_fingerprint if approved_match else None,
        "approved_fingerprint_match": approved_match,
        "analysis_status": analysis_status,
        "tool_wide_review_hold": tool_wide_review_hold,
        "risk_level": analysis.risk_level if analysis is not None else tool.risk_level,
        "semantic_flagged": (
            analysis.semantic_flagged == "true"
            if analysis is not None
            else tool.semantic_flagged
        ),
        "deterministic_critical_finding": (
            analysis.deterministic_critical_finding == "true"
            if analysis is not None
            else tool.deterministic_critical_finding
        ),
        "consistency_status": (
            analysis.consistency_status if analysis is not None else tool.consistency_status
        ),
        "drift_status": analysis.drift_status if analysis is not None else tool.drift_status,
        "review_status": review_status,
        "analyzer_revision": (
            analysis.analyzer_revision if analysis is not None else tool.analyzer_revision
        ),
        "status": analysis_status,
        "created_at": tool.created_at,
        "upstream_protocol_profile_id": observation.upstream_protocol_profile_id,
        "tool_protocol_observation_id": observation.id,
        "tool_observation_last_seen_at": observation.last_seen_at,
    }


class DispatchAdmissionRequest(EmergencyDenyCheckRequest):
    operation_id: str = Field(
        pattern=r"^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$"
    )


@router.post("/emergency-deny/admit")
def admit_internal_mcp_dispatch(
    payload: DispatchAdmissionRequest,
    _: VerifiedServiceRequest = Depends(
        require_internal_service_permission(PERMISSION_RUNTIME_DISPATCH_ADMIT)
    ),
    db: Session = Depends(get_db),
):
    context = payload.model_dump(exclude={"operation_id"})
    try:
        result = admit_mcp_dispatch(
            db, operation_id=payload.operation_id, context=context,
        )
        db.commit()
    except Exception:
        db.rollback()
        raise
    return result


@router.post("/emergency-deny/check")
def check_internal_emergency_deny(
    payload: EmergencyDenyCheckRequest,
    _: VerifiedServiceRequest = Depends(
        require_internal_service_permission(PERMISSION_EMERGENCY_DENY_CHECK)
    ),
    db: Session = Depends(get_db),
):
    deny_id = check_emergency_deny(db, **payload.model_dump())
    return {"blocked": deny_id is not None, "deny_id": deny_id}
