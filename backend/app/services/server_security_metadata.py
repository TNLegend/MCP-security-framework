from __future__ import annotations

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.mcp_server import MCPServer
from app.models.mcp_tool import MCPTool


def compute_server_security_status(statuses: list[str]) -> str:
    observed = [status for status in statuses if status]
    if any(status == "BLOCKED" for status in observed):
        return "blocked"
    if any(status == "ANALYSIS_FAILED" for status in observed):
        return "analysis_failed"
    if any(status in {"REVIEW_REQUIRED", "QUARANTINED"} for status in observed):
        return "review_required"
    if any(status == "PENDING_ANALYSIS" for status in observed):
        return "pending_analysis"
    if observed and all(status in {"APPROVED", "ADMIN_ALLOWED"} for status in observed):
        return "approved"
    return "pending_analysis"


def refresh_server_security_status(
    db: Session,
    server_id: int,
    *,
    scanned_at: datetime | None = None,
) -> str:
    server = db.get(MCPServer, server_id)
    if server is None:
        raise ValueError("server is missing.")

    statuses = list(
        db.scalars(select(MCPTool.analysis_status).where(MCPTool.server_id == server_id)).all()
    )
    server.security_status = compute_server_security_status(statuses)
    if scanned_at is not None:
        server.last_scan_at = scanned_at
    return server.security_status
