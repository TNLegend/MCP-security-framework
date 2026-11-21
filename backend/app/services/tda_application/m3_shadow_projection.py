"""TA-02: bounded, persisted projection of the M3 SHADOW instruction report.

The M3 report is ADVISORY ONLY (mode SHADOW, authority AT_MOST_REVIEW_ADVISORY).
This projection never changes analysis_status, review_status or any runtime
decision. It keeps the facts an operator needs and nothing that could leak
the analysed text: no source excerpts, offsets or model internals.
An unavailable report is persisted explicitly as unavailable, never guessed.
"""
from __future__ import annotations

from typing import Any

PROJECTION_VERSION = "m3-shadow-projection-v1"
MAX_SIGNALS = 32
MAX_LIMITATIONS = 32
_SAFE = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-./:#$")


def _code(value: Any, limit: int = 128) -> str | None:
    if not isinstance(value, str) or not value or len(value) > limit:
        return None
    return value if set(value) <= _SAFE else None


def _count(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def unavailable(reason: str) -> dict[str, Any]:
    return {
        "projection_version": PROJECTION_VERSION,
        "available": False,
        "unavailable_reason": reason,
        "mode": "SHADOW",
        "authority": "AT_MOST_REVIEW_ADVISORY",
        "security_decision_changes": "NONE",
    }


def project_m3_report(report: Any) -> dict[str, Any]:
    if not isinstance(report, dict):
        return unavailable("M3_REPORT_NOT_PRODUCED")
    # Refuse anything that claims authority: the contract forbids it upstream.
    if report.get("mode") != "SHADOW" or report.get("authority") != "AT_MOST_REVIEW_ADVISORY":
        return unavailable("M3_REPORT_AUTHORITY_INVALID")
    coverage = report.get("coverage") if isinstance(report.get("coverage"), dict) else {}
    execution = coverage.get("execution") if isinstance(coverage.get("execution"), dict) else {}
    domain = coverage.get("supported_domain") if isinstance(coverage.get("supported_domain"), dict) else {}
    result = coverage.get("result") if isinstance(coverage.get("result"), dict) else {}

    signals = []
    for kind in ("directives", "raw_signals"):
        for item in report.get(kind) or []:
            if not isinstance(item, dict) or len(signals) >= MAX_SIGNALS:
                continue
            signals.append({
                "kind": "DIRECTIVE" if kind == "directives" else "RAW_SIGNAL",
                "rule_id": _code(item.get("rule_id")),
                "field_pointer": _code(item.get("pointer"), 256),
                "view_id": _code(item.get("view_id")),
                "evidence_level": _code(item.get("support")),
                "source_bound": item.get("source_proof") is not None,
            })
    total_signals = len(report.get("directives") or []) + len(report.get("raw_signals") or [])
    limitations = [
        code for code in (_code(v) for v in (report.get("limitations") or [])[:MAX_LIMITATIONS])
        if code is not None
    ]
    neural = report.get("neural_shadow")
    return {
        "projection_version": PROJECTION_VERSION,
        "available": True,
        "schema": _code(report.get("schema")),
        "mode": "SHADOW",
        "authority": "AT_MOST_REVIEW_ADVISORY",
        "security_decision_changes": "NONE",
        "scope": {
            "execution_status": _code(execution.get("status")),
            "inspected_fields": _count(execution.get("inspected_rows")),
            "omitted_fields": _count(execution.get("omitted_rows")),
            "error_fields": _count(execution.get("error_rows")),
            "supported_domain": _code(domain.get("status")),
            "language_coverage": _code(coverage.get("language_coverage")),
            "semantic_complete": False,
        },
        "result_status": _code(result.get("status")),
        "clean_verdict": False,
        "signal_count": total_signals,
        "signals": signals,
        "signals_truncated": total_signals > len(signals),
        "neural_shadow_status": (
            _code(neural.get("status")) if isinstance(neural, dict) else None
        ),
        "limitations": limitations,
    }
