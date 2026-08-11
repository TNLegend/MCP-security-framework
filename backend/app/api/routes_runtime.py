from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models.mcp_server import MCPServer
from app.models.runtime_call import RuntimeCall
from app.schemas.policy_decision import PolicyDecision
from app.schemas.policy_context import RuntimePolicyInput
from app.schemas.runtime import RuntimeCallCreate, RuntimeCallRead
from app.services.control_plane_auth import AuthenticatedControlPlaneUser, require_authenticated_user
from app.services.policy_runtime import evaluate_runtime_policy
from app.services.signed_service_request import (
    PERMISSION_RUNTIME_LOGS_WRITE,
    VerifiedServiceRequest,
    require_internal_service_permission,
)

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
def list_runtime_logs(
    _: AuthenticatedControlPlaneUser = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
):
    return db.scalars(select(RuntimeCall).order_by(RuntimeCall.id)).all()


@router.post("/logs", response_model=RuntimeCallRead)
def create_runtime_log(
    log: RuntimeCallCreate,
    _: VerifiedServiceRequest = Depends(
        require_internal_service_permission(PERMISSION_RUNTIME_LOGS_WRITE)
    ),
    db: Session = Depends(get_db),
):
    log_data = log.model_dump()
    log_data["server_id"] = resolve_server_id(log.server_id, db)

    db_log = RuntimeCall(**log_data)
    db.add(db_log)
    db.commit()
    db.refresh(db_log)
    return db_log


@router.post("/decision", response_model=PolicyDecision)
def evaluate_runtime_decision(
    context: RuntimePolicyInput,
    x_mcp_identity_assertion: str | None = Header(
        default=None,
        alias="X-MCP-Identity-Assertion",
    ),
    db: Session = Depends(get_db),
) -> PolicyDecision:
    return evaluate_runtime_policy(
        context=context.model_dump(mode="json"),
        identity_assertion=x_mcp_identity_assertion,
        db=db,
    )
