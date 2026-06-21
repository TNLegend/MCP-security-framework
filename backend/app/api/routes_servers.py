from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models.mcp_server import MCPServer
from app.schemas.server import MCPServerCreate, MCPServerRead

router = APIRouter(prefix="/servers", tags=["MCP Servers"])


@router.get("", response_model=list[MCPServerRead])
def list_servers(db: Session = Depends(get_db)):
    return db.scalars(select(MCPServer).order_by(MCPServer.id)).all()


@router.post("", response_model=MCPServerRead)
def create_server(server: MCPServerCreate, db: Session = Depends(get_db)):
    db_server = MCPServer(**server.model_dump())
    db.add(db_server)
    db.commit()
    db.refresh(db_server)
    return db_server
