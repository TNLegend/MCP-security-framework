from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class LatencyStats(BaseModel):
    samples: int = 0
    avg_ms: float | None = None
    p50_ms: float | None = None
    p95_ms: float | None = None
    p99_ms: float | None = None
    max_ms: float | None = None


class OperationsWindow(BaseModel):
    window_minutes: int
    total_calls: int
    allowed: int
    blocked: int
    errors: int
    executed: int
    result_blocked: int
    calls_per_minute: float
    error_rate: float
    total_latency: LatencyStats
    policy_latency: LatencyStats
    upstream_latency: LatencyStats
    result_guard_latency: LatencyStats


class DatabasePoolStats(BaseModel):
    pool_size: int | None = None
    checked_out: int | None = None
    checked_in: int | None = None
    overflow: int | None = None
    configured_pool_size: int
    configured_max_overflow: int
    pool_timeout_seconds: float
    pool_recycle_seconds: int


class RuntimeStorageStats(BaseModel):
    # Intent events past grace with no outcome. Execution state is unknown,
    # not automatically failed or safe to retry.
    unresolved_intents: int = 0
    intent_grace_seconds: int = 120
    total_rows: int
    oldest_at: datetime | None = None
    newest_at: datetime | None = None
    retention_days: int
    max_rows: int
    cleanup_batch_size: int
    auto_cleanup_interval_rows: int


class ProcessLogPolicy(BaseModel):
    max_bytes: int
    backup_count: int


class OperationsSummary(BaseModel):
    generated_at: datetime
    ready: bool
    components: dict[str, dict[str, Any]]
    window: OperationsWindow
    database_pool: DatabasePoolStats
    runtime_storage: RuntimeStorageStats
    process_logs: ProcessLogPolicy


class RuntimeOperationReconciliation(BaseModel):
    operation_id: str
    state: Literal[
        "INTENT_ADMISSION_MISSING",
        "ADMITTED_OUTCOME_MISSING",
        "RECORDED_UNCERTAIN_OUTCOME",
        "OUTCOME_RECORDED",
    ]
    intent_recorded: bool
    admission_recorded: bool
    outcome_recorded: bool
    execution_status: str | None
    effect_possible: bool
    retry_unsafe: bool
    manual_reconciliation_required: bool


class RuntimeCleanupRequest(BaseModel):
    dry_run: bool = True
    reason: str = Field(default="Routine runtime log retention maintenance.", min_length=10, max_length=500)

    model_config = ConfigDict(extra="forbid")


class RuntimeCleanupResult(BaseModel):
    dry_run: bool
    cutoff: datetime
    total_before: int
    eligible_expired: int
    eligible_over_limit: int
    planned: int
    deleted: int
    total_after: int
