from __future__ import annotations
from app.services.tda.configuration import STATUS_ADMIN_ALLOWED
from app.services.tda.configuration import STATUS_APPROVED
from app.services.tda.configuration import STATUS_STALE
from app.services.tda.m5_context.identity import normalize_description
from typing import Any
from app.models.mcp_tool import MCPTool
from sqlalchemy.orm import Session
from app.models.tool_analysis import ToolAnalysis
from app.models.tool_analysis import ToolApprovedBaseline
from app.models.tool_analysis import ToolProtocolObservation


def tool_snapshot_from_model(tool: MCPTool) -> dict[str, Any]:
    return {
        "name": tool.name,
        "title": tool.title,
        "description": normalize_description(tool.description),
        "input_schema": tool.input_schema or {},
        "output_schema": tool.output_schema or {},
        "annotations": tool.annotations or {},
        "execution": tool.execution or {},
    }


def latest_analysis_for_tool(db: Session, tool_id: int) -> ToolAnalysis | None:
    from app.models.tool_analysis import ToolAnalysis
    from sqlalchemy import select

    return db.scalar(
        select(ToolAnalysis)
        .where(ToolAnalysis.tool_id == tool_id)
        .order_by(ToolAnalysis.id.desc())
    )


def baseline_for_tool(db: Session, tool_id: int) -> ToolApprovedBaseline | None:
    from app.models.tool_analysis import ToolApprovedBaseline
    from sqlalchemy import select

    return db.scalar(
        select(ToolApprovedBaseline).where(ToolApprovedBaseline.tool_id == tool_id)
    )


def latest_protocol_observation(
    db: Session,
    *,
    tool_id: int,
    upstream_protocol_profile_id: str,
    fingerprint: str | None = None,
) -> ToolProtocolObservation | None:
    from app.models.tool_analysis import ToolProtocolObservation
    from sqlalchemy import select

    query = select(ToolProtocolObservation).where(
        ToolProtocolObservation.tool_id == tool_id,
        ToolProtocolObservation.upstream_protocol_profile_id
        == upstream_protocol_profile_id,
    )
    if fingerprint is not None:
        query = query.where(ToolProtocolObservation.tool_fingerprint == fingerprint)
    return db.scalar(
        query.order_by(
            ToolProtocolObservation.last_seen_at.desc(),
            ToolProtocolObservation.id.desc(),
        )
    )


def approved_protocol_observation_exists(
    db: Session, *, tool_id: int, upstream_protocol_profile_id: str, fingerprint: str
) -> bool:
    from app.models.tool_analysis import ToolAnalysis

    observation = latest_protocol_observation(
        db,
        tool_id=tool_id,
        upstream_protocol_profile_id=upstream_protocol_profile_id,
        fingerprint=fingerprint,
    )
    if observation is None or observation.analysis_id is None:
        return False
    analysis = db.get(ToolAnalysis, observation.analysis_id)
    return (
        analysis is not None
        and analysis.analysis_status in {STATUS_APPROVED, STATUS_ADMIN_ALLOWED}
        and (analysis.review_status in {STATUS_APPROVED, STATUS_ADMIN_ALLOWED})
        and (observation.analysis_state != STATUS_STALE)
    )
