from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models.mcp_server import MCPServer
from app.schemas.server import MCPServerCreate, MCPServerRead
from app.services.control_plane_auth import (
    AuthenticatedControlPlaneUser,
    require_admin,
    require_authenticated_user,
)

router = APIRouter(prefix="/servers", tags=["MCP Servers"])


@router.get("", response_model=list[MCPServerRead])
def list_servers(
    _: AuthenticatedControlPlaneUser = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
):
    return list_servers_from_db(db)


@router.post("", response_model=MCPServerRead)
def create_server(
    server: MCPServerCreate,
    _: AuthenticatedControlPlaneUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    db_server = MCPServer(**server.model_dump())
    db.add(db_server)
    db.commit()
    db.refresh(db_server)
    return db_server


def list_servers_from_db(db: Session) -> list[MCPServer]:
    return db.scalars(select(MCPServer).order_by(MCPServer.id)).all()
