"""Compatibility adapter: shadow report cannot alter V0 decisions or old output."""
from __future__ import annotations
from typing import Any

from app.services.tda.m3_instructions.contracts import M3Report


def with_shadow_m3_report(
    legacy_result: dict[str, Any], report: M3Report
) -> dict[str, Any]:
    if not isinstance(legacy_result, dict) or not isinstance(report, M3Report):
        raise ValueError("M3_SHADOW_RESULT_AND_REPORT_REQUIRED")
    if "m3_report" in legacy_result:
        raise ValueError("M3_ALREADY_ATTACHED")
    if (report.mode != "SHADOW"
            or report.authority != "AT_MOST_REVIEW_ADVISORY"
            or report.coverage_complete is not None):
        raise ValueError("M3_SHADOW_CANNOT_SET_SECURITY_POLICY")
    result = dict(legacy_result)
    result["m3_report"] = report.to_dict()
    return result
