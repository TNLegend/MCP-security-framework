import base64
from datetime import datetime

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models.mcp_server import MCPServer
from app.models.runtime_call import RuntimeCall
from app.schemas.policy_decision import PolicyDecision
from app.schemas.policy_context import RuntimePolicyInput
from app.schemas.runtime import RuntimeCallCreate, RuntimeCallPage, RuntimeCallRead, RuntimeCallSummary
from app.services.control_plane_auth import AuthenticatedControlPlaneUser, require_authenticated_user
from app.services.policy_runtime import evaluate_runtime_policy
from app.services.runtime_operations import maybe_auto_cleanup_runtime_logs
from app.services.signed_service_request import (
    PERMISSION_RUNTIME_LOGS_WRITE,
    VerifiedServiceRequest,
    require_internal_service_permission,
)

router = APIRouter(prefix="/runtime", tags=["Runtime"])

RUNTIME_ERROR_STATUSES = (
    "tool_error",
    "protocol_error",
    "http_error",
    "policy_error",
    "inventory_error",
)


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


@router.get("/logs", response_model=RuntimeCallPage)
def list_runtime_logs(
    limit: int = Query(default=50, ge=1, le=100),
    cursor: str | None = Query(default=None, max_length=64),
    decision: str | None = Query(default=None, max_length=50),
    server_id: int | None = Query(default=None, gt=0),
    tool_name: str | None = Query(default=None, max_length=255),
    agent_id: str | None = Query(default=None, max_length=255),
    protocol_profile_id: str | None = Query(default=None, max_length=100),
    from_time: datetime | None = Query(default=None, alias="from"),
    to_time: datetime | None = Query(default=None, alias="to"),
    search: str | None = Query(default=None, max_length=255),
    _: AuthenticatedControlPlaneUser = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
) -> RuntimeCallPage:
    filters = _runtime_log_filters(
        decision=decision,
        server_id=server_id,
        tool_name=tool_name,
        agent_id=agent_id,
        protocol_profile_id=protocol_profile_id,
        from_time=from_time,
        to_time=to_time,
        search=search,
    )
    cursor_id = _decode_runtime_log_cursor(cursor) if cursor else None
    page_filters = list(filters)
    if cursor_id is not None:
        page_filters.append(RuntimeCall.id < cursor_id)

    rows = db.scalars(
        select(RuntimeCall)
        .where(*page_filters)
        .order_by(RuntimeCall.id.desc())
        .limit(limit + 1)
    ).all()
    has_more = len(rows) > limit
    items = list(rows[:limit])
    next_cursor = _encode_runtime_log_cursor(items[-1].id) if has_more and items else None

    summary_row = db.execute(
        select(
            func.count(RuntimeCall.id),
            func.count(RuntimeCall.id).filter(RuntimeCall.decision == "ALLOW"),
            func.count(RuntimeCall.id).filter(RuntimeCall.decision == "BLOCK"),
            func.count(RuntimeCall.id).filter(RuntimeCall.executed.is_(True)),
            func.count(RuntimeCall.id).filter(
                or_(RuntimeCall.executed.is_(False), RuntimeCall.execution_status == "skipped")
            ),
            func.count(RuntimeCall.id).filter(
                RuntimeCall.execution_status.in_(RUNTIME_ERROR_STATUSES)
            ),
        ).where(*filters)
    ).one()
    return RuntimeCallPage(
        items=items,
        next_cursor=next_cursor,
        has_more=has_more,
        summary=RuntimeCallSummary(
            total=summary_row[0],
            allowed=summary_row[1],
            blocked=summary_row[2],
            executed=summary_row[3],
            skipped=summary_row[4],
            errors=summary_row[5],
        ),
    )


def _runtime_log_filters(
    *,
    decision: str | None,
    server_id: int | None,
    tool_name: str | None,
    agent_id: str | None,
    protocol_profile_id: str | None,
    from_time: datetime | None,
    to_time: datetime | None,
    search: str | None,
) -> list:
    filters = []
    if decision:
        filters.append(RuntimeCall.decision == decision.strip().upper())
    if server_id is not None:
        filters.append(RuntimeCall.server_id == server_id)
    if tool_name and tool_name.strip():
        filters.append(RuntimeCall.tool_name == tool_name.strip())
    if agent_id and agent_id.strip():
        filters.append(RuntimeCall.agent_id == agent_id.strip())
    if protocol_profile_id and protocol_profile_id.strip():
        profile_id = protocol_profile_id.strip()
        filters.append(
            or_(
                RuntimeCall.client_protocol_profile_id == profile_id,
                RuntimeCall.upstream_protocol_profile_id == profile_id,
            )
        )
    if from_time is not None:
        filters.append(RuntimeCall.created_at >= from_time.replace(tzinfo=None))
    if to_time is not None:
        filters.append(RuntimeCall.created_at <= to_time.replace(tzinfo=None))
    if search and search.strip():
        term = f"%{search.strip()}%"
        filters.append(
            or_(
                RuntimeCall.tool_name.ilike(term),
                RuntimeCall.agent_id.ilike(term),
                RuntimeCall.decision_reason.ilike(term),
                RuntimeCall.rule_id.ilike(term),
            )
        )
    return filters


def _encode_runtime_log_cursor(runtime_call_id: int) -> str:
    return base64.urlsafe_b64encode(str(runtime_call_id).encode("ascii")).decode("ascii").rstrip("=")


def _decode_runtime_log_cursor(cursor: str) -> int:
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        value = base64.b64decode(padded, altchars=b"-_", validate=True).decode("ascii")
        runtime_call_id = int(value)
    except (ValueError, UnicodeError) as exc:
        raise HTTPException(status_code=400, detail="invalid_runtime_log_cursor") from exc
    if runtime_call_id <= 0:
        raise HTTPException(status_code=400, detail="invalid_runtime_log_cursor")
    return runtime_call_id


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
    maintenance = maybe_auto_cleanup_runtime_logs(
        db,
        runtime_log_id=db_log.id,
    )
    if maintenance is not None and maintenance.deleted > 0:
        db.commit()
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
