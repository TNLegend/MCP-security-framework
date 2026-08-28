from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.routes_servers import list_servers_from_db
from app.api.routes_tools import list_tools_from_db
from app.db.database import get_db
from app.models.mcp_tool import MCPTool
from app.models.tool_analysis import ToolAnalysis
from app.schemas.server import MCPServerInternalRead
from app.schemas.tool import MCPToolRead
from app.services.signed_service_request import (
    PERMISSION_EMERGENCY_DENY_CHECK,
    PERMISSION_INTERNAL_INVENTORY_SERVERS_READ,
    PERMISSION_INTERNAL_INVENTORY_TOOLS_READ,
    VerifiedServiceRequest,
    require_internal_service_permission,
)
from app.services.emergency_deny import check_emergency_deny
from proxy.tool_security_v2 import security_schema_projection

from app.services.tool_analysis import (
    STATUS_ADMIN_ALLOWED,
    STATUS_APPROVED,
    STATUS_STALE,
    latest_protocol_observation,
)

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
    tool = db.scalar(
        select(MCPTool).where(
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
    analysis = db.get(ToolAnalysis, observation.analysis_id) if observation.analysis_id else None
    definition = observation.canonical_tool_definition or {}
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
        and review_status in {STATUS_APPROVED, STATUS_ADMIN_ALLOWED}
        and observation.analysis_state != STATUS_STALE
    )
    return {
        "id": tool.id,
        "server_id": tool.server_id,
        "name": tool.name,
        "title": tool.title,
        "description": definition.get("description") or tool.description,
        "icons": tool.icons,
        "input_schema": security_schema_projection(
            definition.get("input_schema") or {}
        ),
        "output_schema": definition.get("output_schema") or {},
        "annotations": definition.get("annotations") or {},
        "execution": definition.get("execution") or {},
        "raw_tool_definition": tool.raw_tool_definition,
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
