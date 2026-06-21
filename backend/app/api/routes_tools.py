from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models.mcp_tool import MCPTool
from app.schemas.tool import MCPToolCreate, MCPToolRead

router = APIRouter(prefix="/tools", tags=["MCP Tools"])


@router.get("", response_model=list[MCPToolRead])
def list_tools(db: Session = Depends(get_db)):
    return db.scalars(select(MCPTool).order_by(MCPTool.id)).all()


@router.post("", response_model=MCPToolRead)
def create_tool(tool: MCPToolCreate, db: Session = Depends(get_db)):
    db_tool = MCPTool(**tool.model_dump())
    db.add(db_tool)
    db.commit()
    db.refresh(db_tool)
    return db_tool
