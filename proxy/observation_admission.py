"""Shared live review predicate; listing never grants dispatch authority."""
from typing import Any

ADMISSIBLE_REVIEW_STATES=frozenset({'APPROVED','ADMIN_ALLOWED'})

def live_review_admissible(tool: dict[str,Any]) -> bool:
    return (tool.get('analysis_status') in ADMISSIBLE_REVIEW_STATES
        and tool.get('review_status') in ADMISSIBLE_REVIEW_STATES
        and tool.get('tool_wide_review_hold') is not True)
