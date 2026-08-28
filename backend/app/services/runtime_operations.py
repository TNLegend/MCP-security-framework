from __future__ import annotations

from datetime import datetime, timedelta
from statistics import fmean
from typing import Iterable

from sqlalchemy import delete, exists, func, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.database import engine
from app.models.control_plane import ControlPlaneAuditEvent
from app.models.policy_decision import PolicyDecision
from app.models.runtime_call import RuntimeCall
from app.schemas.operations import (
    DatabasePoolStats,
    LatencyStats,
    OperationsSummary,
    OperationsWindow,
    ProcessLogPolicy,
    RuntimeCleanupResult,
    RuntimeStorageStats,
)
from app.services.local_runtime_manager import LocalRuntimeManager


RUNTIME_ERROR_STATUSES = {
    "tool_error",
    "protocol_error",
    "http_error",
    "policy_error",
    "inventory_error",
    "client_initialization_error",
    "upstream_auth_error",
}


def operations_summary(db: Session) -> OperationsSummary:
    now = datetime.utcnow()
    window_minutes = settings.operations_metrics_window_minutes
    window_start = now - timedelta(minutes=window_minutes)
    total, allowed, blocked, errors, executed, result_blocked = db.execute(
        select(
            func.count(RuntimeCall.id),
            func.count(RuntimeCall.id).filter(RuntimeCall.decision == "ALLOW"),
            func.count(RuntimeCall.id).filter(RuntimeCall.decision == "BLOCK"),
            func.count(RuntimeCall.id).filter(
                RuntimeCall.execution_status.in_(RUNTIME_ERROR_STATUSES)
            ),
            func.count(RuntimeCall.id).filter(RuntimeCall.executed.is_(True)),
            func.count(RuntimeCall.id).filter(
                RuntimeCall.execution_status == "result_blocked"
            ),
        ).where(RuntimeCall.created_at >= window_start)
    ).one()
    total = int(total or 0)
    allowed = int(allowed or 0)
    blocked = int(blocked or 0)
    errors = int(errors or 0)
    executed = int(executed or 0)
    result_blocked = int(result_blocked or 0)

    rows = db.scalars(
        select(RuntimeCall)
        .where(RuntimeCall.created_at >= window_start)
        .order_by(RuntimeCall.id.desc())
        .limit(10_000)
    ).all()

    runtime_status = LocalRuntimeManager().status(
        db=db,
        backend_current_process=True,
    )
    identity = LocalRuntimeManager().identity_provider_status()
    components = runtime_status.as_dict(include_ownership=False)
    component_payload = {
        "backend": components["backend"],
        "database": components["database"],
        "opa": components["opa"],
        "gateway": components["gateway"],
        "identity_provider": identity.as_dict(),
    }
    for value in component_payload.values():
        value.pop("managed_by_framework", None)
    ready = all(
        item.get("status") == "healthy"
        for item in component_payload.values()
    )

    total_rows, oldest_at, newest_at = db.execute(
        select(
            func.count(RuntimeCall.id),
            func.min(RuntimeCall.created_at),
            func.max(RuntimeCall.created_at),
        )
    ).one()

    return OperationsSummary(
        generated_at=now,
        ready=ready,
        components=component_payload,
        window=OperationsWindow(
            window_minutes=window_minutes,
            total_calls=total,
            allowed=allowed,
            blocked=blocked,
            errors=errors,
            executed=executed,
            result_blocked=result_blocked,
            calls_per_minute=round(total / max(window_minutes, 1), 3),
            error_rate=round(errors / total, 6) if total else 0.0,
            total_latency=_latency(row.total_duration_ms for row in rows),
            policy_latency=_latency(row.policy_duration_ms for row in rows),
            upstream_latency=_latency(row.upstream_duration_ms for row in rows),
            result_guard_latency=_latency(row.result_guard_duration_ms for row in rows),
        ),
        database_pool=_pool_stats(),
        runtime_storage=RuntimeStorageStats(
            total_rows=int(total_rows or 0),
            oldest_at=oldest_at,
            newest_at=newest_at,
            retention_days=settings.runtime_log_retention_days,
            max_rows=settings.runtime_log_max_rows,
            cleanup_batch_size=settings.runtime_log_cleanup_batch_size,
            auto_cleanup_interval_rows=settings.runtime_log_auto_cleanup_interval_rows,
        ),
        process_logs=ProcessLogPolicy(
            max_bytes=settings.local_runtime_log_max_bytes,
            backup_count=settings.local_runtime_log_backup_count,
        ),
    )


def cleanup_runtime_logs(
    db: Session,
    *,
    dry_run: bool,
) -> RuntimeCleanupResult:
    now = datetime.utcnow()
    cutoff = now - timedelta(days=settings.runtime_log_retention_days)
    total_before = int(
        db.scalar(select(func.count(RuntimeCall.id))) or 0
    )
    unreferenced = ~exists(
        select(PolicyDecision.id).where(
            PolicyDecision.runtime_call_id == RuntimeCall.id
        )
    )
    eligible_expired = int(
        db.scalar(
            select(func.count(RuntimeCall.id)).where(
                RuntimeCall.created_at < cutoff,
                unreferenced,
            )
        )
        or 0
    )
    eligible_over_limit = max(0, total_before - settings.runtime_log_max_rows)

    batch = settings.runtime_log_cleanup_batch_size
    target_deletions = min(
        batch,
        max(eligible_expired, eligible_over_limit),
    )
    selected: list[int] = list(
        db.scalars(
            select(RuntimeCall.id)
            .where(RuntimeCall.created_at < cutoff, unreferenced)
            .order_by(RuntimeCall.id.asc())
            .limit(target_deletions)
        ).all()
    )
    capacity = target_deletions - len(selected)
    if capacity > 0 and eligible_over_limit > 0:
        query = (
            select(RuntimeCall.id)
            .where(unreferenced)
            .order_by(RuntimeCall.id.asc())
            .limit(min(capacity, eligible_over_limit))
        )
        if selected:
            query = query.where(RuntimeCall.id.not_in(selected))
        selected.extend(db.scalars(query).all())

    selected = list(dict.fromkeys(int(value) for value in selected))[:batch]
    deleted = 0
    if not dry_run and selected:
        result = db.execute(delete(RuntimeCall).where(RuntimeCall.id.in_(selected)))
        deleted = int(result.rowcount or 0)
        db.flush()

    total_after = total_before - deleted
    return RuntimeCleanupResult(
        dry_run=dry_run,
        cutoff=cutoff,
        total_before=total_before,
        eligible_expired=eligible_expired,
        eligible_over_limit=eligible_over_limit,
        planned=len(selected),
        deleted=deleted,
        total_after=total_after,
    )




def maybe_auto_cleanup_runtime_logs(
    db: Session,
    *,
    runtime_log_id: int,
) -> RuntimeCleanupResult | None:
    interval = settings.runtime_log_auto_cleanup_interval_rows
    if runtime_log_id <= 0 or runtime_log_id % interval != 0:
        return None
    result = cleanup_runtime_logs(db, dry_run=False)
    if result.deleted <= 0:
        return result
    db.add(
        ControlPlaneAuditEvent(
            actor_user_id=None,
            actor_username_snapshot="system",
            actor_role_snapshot="SYSTEM",
            action="RUNTIME_LOG_RETENTION_AUTO_APPLIED",
            target_type="runtime_logs",
            target_id="retention",
            after_json=result.model_dump(mode="json"),
            reason="Automatic bounded runtime log retention maintenance.",
            result="SUCCESS",
        )
    )
    db.flush()
    return result


def _latency(values: Iterable[float | None]) -> LatencyStats:
    cleaned = sorted(
        float(value)
        for value in values
        if isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0
    )
    if not cleaned:
        return LatencyStats()
    return LatencyStats(
        samples=len(cleaned),
        avg_ms=round(fmean(cleaned), 3),
        p50_ms=_percentile(cleaned, 0.50),
        p95_ms=_percentile(cleaned, 0.95),
        p99_ms=_percentile(cleaned, 0.99),
        max_ms=round(cleaned[-1], 3),
    )


def _percentile(values: list[float], quantile: float) -> float:
    if not values:
        raise ValueError("percentile_requires_values")
    if len(values) == 1:
        return round(values[0], 3)
    position = (len(values) - 1) * quantile
    lower = int(position)
    upper = min(lower + 1, len(values) - 1)
    fraction = position - lower
    value = values[lower] + (values[upper] - values[lower]) * fraction
    return round(value, 3)


def _pool_stats() -> DatabasePoolStats:
    pool = engine.pool
    return DatabasePoolStats(
        pool_size=_safe_pool_metric(pool, "size"),
        checked_out=_safe_pool_metric(pool, "checkedout"),
        checked_in=_safe_pool_metric(pool, "checkedin"),
        overflow=_normalized_overflow(pool),
        configured_pool_size=settings.database_pool_size,
        configured_max_overflow=settings.database_max_overflow,
        pool_timeout_seconds=settings.database_pool_timeout_seconds,
        pool_recycle_seconds=settings.database_pool_recycle_seconds,
    )




def _normalized_overflow(pool) -> int | None:
    value = _safe_pool_metric(pool, "overflow")
    if value is None:
        return None
    return max(0, value)


def _safe_pool_metric(pool, name: str) -> int | None:
    method = getattr(pool, name, None)
    if not callable(method):
        return None
    try:
        return int(method())
    except Exception:
        return None
