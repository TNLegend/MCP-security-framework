from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models.mcp_tool import MCPTool
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
    _: AuthenticatedControlPlaneUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    db_tool = MCPTool(**tool.model_dump())
    db.add(db_tool)
    db.commit()
    db.refresh(db_tool)
    return db_tool


def list_tools_from_db(db: Session) -> list[MCPTool]:
    return db.scalars(select(MCPTool).order_by(MCPTool.id)).all()
