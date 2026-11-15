from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models.mcp_tool import MCPTool
from app.services.control_plane_audit import record_control_plane_audit
from app.schemas.tool import MCPToolCreate, MCPToolRead
from app.services.control_plane_auth import (
    AuthenticatedControlPlaneUser,
    require_admin,
    require_authenticated_user,
)

router = APIRouter(prefix="/tools", tags=["MCP Tools"])


@router.get("", response_model=list[MCPToolRead])
def list_tools(
    _: AuthenticatedControlPlaneUser = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
):
    return list_tools_from_db(db)


@router.post("", response_model=MCPToolRead)
def create_tool(
    tool: MCPToolCreate,
    current: AuthenticatedControlPlaneUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    db_tool = MCPTool(**tool.model_dump())
    try:
        db.add(db_tool)
        db.flush()
        record_control_plane_audit(
            db,
            actor=current.user,
            action="MCP_TOOL_CREATED",
            target_type="mcp_tool",
            target_id=str(db_tool.id),
            after_json={"server_id": db_tool.server_id, "tool_name": db_tool.name},
        )
        db.commit()
    except Exception:
        db.rollback()
        raise
    db.refresh(db_tool)
    return db_tool


def list_tools_from_db(db: Session) -> list[MCPTool]:
    return db.scalars(select(MCPTool).order_by(MCPTool.id)).all()
