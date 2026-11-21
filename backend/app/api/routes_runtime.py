import base64
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Path
from sqlalchemy import and_, func, or_, select
from sqlalchemy.exc import IntegrityError
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
from app.services.runtime_outcome_taxonomy import RUNTIME_OUTCOME_BUCKETS, runtime_outcome_bucket_expression
from app.services.signed_service_request import (
    PERMISSION_RUNTIME_LOGS_WRITE,
    VerifiedServiceRequest,
    require_internal_service_permission,
)

router = APIRouter(prefix="/runtime", tags=["Runtime"])

from app.services.runtime_operations import RUNTIME_ERROR_STATUSES


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

    bucket = runtime_outcome_bucket_expression()
    summary_row = db.execute(
        select(
            func.count(RuntimeCall.id),
            func.count(RuntimeCall.id).filter(RuntimeCall.decision == "ALLOW"),
            func.count(RuntimeCall.id).filter(RuntimeCall.decision == "BLOCK"),
            func.count(RuntimeCall.id).filter(RuntimeCall.executed.is_(True)),
            func.count(RuntimeCall.id).filter(
                or_(
                    RuntimeCall.execution_status == "skipped",
                    and_(
                        RuntimeCall.executed.is_(False),
                        RuntimeCall.decision == "BLOCK",
                    ),
                )
            ),
            func.count(RuntimeCall.id).filter(
                RuntimeCall.execution_status.in_(RUNTIME_ERROR_STATUSES)
            ),
            *(
                func.count(RuntimeCall.id).filter(bucket == name)
                for name in RUNTIME_OUTCOME_BUCKETS
            ),
        ).where(
            *filters,
            or_(
                RuntimeCall.execution_status.is_(None),
                RuntimeCall.execution_status != "authorized_pending_execution",
            ),
        )
    ).one()
    # The same SQL statement counts both total and the mutually exclusive
    # outcome categories, so concurrent inserts cannot skew their sums.
    disjoint_counts = {
        name: int(summary_row[6 + index] or 0)
        for index, name in enumerate(RUNTIME_OUTCOME_BUCKETS)
    }

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
            outcome_states=disjoint_counts,
        ),
    )


@router.get("/logs/operations/{operation_id}", response_model=list[RuntimeCallRead])
def read_runtime_operation_events(
    operation_id: str = Path(
        pattern=r"^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$"
    ),
    _: AuthenticatedControlPlaneUser = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
):
    """Read only recorded phases for one operation, without running the tool.

    Unrecorded phases remain absent, not assumed to have succeeded. Legacy
    events with no operation ID cannot be correlated retrospectively.
    """
    return db.scalars(
        select(RuntimeCall)
        .where(RuntimeCall.operation_id == operation_id)
        .order_by(RuntimeCall.created_at.asc(), RuntimeCall.id.asc())
        .limit(3)
    ).all()


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
        filters.append(RuntimeCall.created_at >= from_time.astimezone(timezone.utc).replace(tzinfo=None))
    if to_time is not None:
        filters.append(RuntimeCall.created_at <= to_time.astimezone(timezone.utc).replace(tzinfo=None))
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
    # Serialize terminal outcome persistence with dispatch admission. A
    # completed pre-dispatch failure must never be followed by a late tools/call
    # admission under the same operation_id.
    if log.operation_id and log.event_phase == "outcome":
        from app.services.dispatch_admission import lock_emergency_dispatch_authority
        lock_emergency_dispatch_authority(db)
    db.add(db_log)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        # A repeat after a lost HTTP response must not create a duplicate.
        # A mismatching retry under the same ID/phase is a conflict, never an
        # opportunity to overwrite the original evidence.
        if not log.operation_id or not log.event_phase:
            raise
        existing = db.scalar(
            select(RuntimeCall).where(
                RuntimeCall.operation_id == log.operation_id,
                RuntimeCall.event_phase == log.event_phase,
            )
        )
        if existing is None:
            raise
        if any(getattr(existing, name) != value for name, value in log_data.items()):
            raise HTTPException(status_code=409, detail="runtime_operation_phase_conflict")
        return existing
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
