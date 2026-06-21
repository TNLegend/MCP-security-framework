from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models.mcp_server import MCPServer
from app.models.runtime_call import RuntimeCall
from app.schemas.decision import PolicyDecisionRead
from app.schemas.runtime import RuntimeCallCreate, RuntimeCallRead
from app.services.policy_engine import evaluate_policy

router = APIRouter(prefix="/runtime", tags=["Runtime"])


def resolve_server_id(server_id: int | str | None, db: Session) -> int | None:
    if server_id is None:
        return None

    if isinstance(server_id, int):
        return server_id

    if server_id.isdigit():
        return int(server_id)

    db_server = db.scalar(select(MCPServer).where(MCPServer.name == server_id))
    if db_server is None:
        raise HTTPException(status_code=404, detail="MCP server not found")

    return db_server.id


@router.get("/logs", response_model=list[RuntimeCallRead])
def list_runtime_logs(db: Session = Depends(get_db)):
    return db.scalars(select(RuntimeCall).order_by(RuntimeCall.id)).all()


@router.post("/logs", response_model=RuntimeCallRead)
def create_runtime_log(log: RuntimeCallCreate, db: Session = Depends(get_db)):
    log_data = log.model_dump()
    log_data["server_id"] = resolve_server_id(log.server_id, db)

    db_log = RuntimeCall(**log_data)
    db.add(db_log)
    db.commit()
    db.refresh(db_log)
    return db_log


@router.post("/decision", response_model=PolicyDecisionRead)
def evaluate_runtime_decision(context: dict):
    return evaluate_policy(context)
