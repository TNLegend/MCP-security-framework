"""Read-only crash reconciliation for durable MCP call phases.

Do not replay upstream effects, alter rows, or infer a remote no-op from a
missing response. Historic (pre-admission) intents remain conservative.
"""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.control_plane import ControlPlaneAuditEvent
from app.models.runtime_call import RuntimeCall
from app.schemas.operations import RuntimeOperationReconciliation


def runtime_operation_reconciliation(
    db: Session, *, operation_id: str,
) -> RuntimeOperationReconciliation | None:
    intent = db.scalar(
        select(RuntimeCall)
        .where(
            RuntimeCall.operation_id == operation_id,
            RuntimeCall.event_phase == "intent",
        )
    )
    outcome = db.scalar(
        select(RuntimeCall)
        .where(
            RuntimeCall.operation_id == operation_id,
            RuntimeCall.event_phase == "outcome",
        )
    )
    if intent is None and outcome is None:
        return None

    admitted = db.scalar(
        select(ControlPlaneAuditEvent.id).where(
            ControlPlaneAuditEvent.action == "RUNTIME_DISPATCH_ADMITTED",
            ControlPlaneAuditEvent.target_type == "runtime_operation",
            ControlPlaneAuditEvent.target_id == operation_id,
        ).limit(1)
    ) is not None

    if outcome is not None:
        # Even a recorded outcome can explicitly be 'upstream_outcome_unknown'.
        uncertain = outcome.execution_status in {
            "upstream_outcome_unknown",
            "audit_completion_failed",
        } or (
            admitted and outcome.execution_status in {
                "http_error", "protocol_error",
            }
        )
        return RuntimeOperationReconciliation(
            operation_id=operation_id,
            state="RECORDED_UNCERTAIN_OUTCOME" if uncertain else "OUTCOME_RECORDED",
            intent_recorded=intent is not None,
            admission_recorded=admitted,
            outcome_recorded=True,
            execution_status=outcome.execution_status,
            effect_possible=uncertain or admitted or bool(outcome.executed),
            retry_unsafe=True,
            manual_reconciliation_required=uncertain,
        )

    # The audit marker is committed before the built-in client sends tools/call.
    # A missing outcome after admission is potentially irreversible; a missing
    # admission still warrants investigation of legacy/instrumentation paths.
    return RuntimeOperationReconciliation(
        operation_id=operation_id,
        state=(
            "ADMITTED_OUTCOME_MISSING" if admitted else
            "INTENT_ADMISSION_MISSING"
        ),
        intent_recorded=True,
        admission_recorded=admitted,
        outcome_recorded=False,
        execution_status=None,
        effect_possible=True,  # conservative for both current/legacy producers
        retry_unsafe=True,
        manual_reconciliation_required=True,
    )
