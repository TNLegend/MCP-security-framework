"""Disjoint, evidence-aware categorization of recorded Runtime outcomes.

This categorizes *outcome rows* only: an intent is neither an executed call
nor a confirmed failure. An old event with no dispatch evidence is never
reinterpreted as confirmed non-execution.
"""
from sqlalchemy import case, or_

from app.models.runtime_call import RuntimeCall

RUNTIME_OUTCOME_BUCKETS = (
    "sent_uncertain",
    "response_withheld",
    "execution_recorded",
    "confirmed_not_sent",
    "legacy_or_unclassified",
)


def runtime_outcome_bucket_expression():
    """One category per persisted outcome row; precedence is deliberate."""
    return case(
        (
            or_(
                RuntimeCall.execution_status == "upstream_outcome_unknown",
                RuntimeCall.dispatch_state == "SENT_OUTCOME_UNKNOWN",
            ),
            "sent_uncertain",
        ),
        (RuntimeCall.execution_status == "result_blocked", "response_withheld"),
        (RuntimeCall.executed.is_(True), "execution_recorded"),
        (RuntimeCall.dispatch_state == "NOT_SENT", "confirmed_not_sent"),
        else_="legacy_or_unclassified",
    )
