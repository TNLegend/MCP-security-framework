"""M7-owned projection of M4 model hypotheses for downstream consumers.

No model may establish an M3 directive, authorization, or MCP tool permission.
M3 deterministic instruction analysis remains independent from M4 and M7.
"""
from __future__ import annotations

from typing import Any


def interpret_m4_directives_advisory(view: dict[str, Any]) -> dict[str, Any]:
    if view.get("instruction_verdict") != "NOT_EVALUATED":
        raise ValueError("M3_M4_UNEXPECTED_INSTRUCTION_AUTHORITY")
    rows = view.get("advisory_directives")
    if not isinstance(rows, list):
        raise ValueError("M3_M4_DIRECTIVES_NOT_LIST")
    directives = []
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("event_id"), str):
            raise ValueError("M3_M4_INVALID_DIRECTIVE")
        if not isinstance(row.get("uncertainty_reasons"), list):
            raise ValueError("M3_M4_UNCERTAINTY_MISSING")
        directives.append({
            "event_id": row["event_id"],
            "text_evidence": row.get("predicate"),
            "proposed_actor": row.get("actor", "UNKNOWN"),
            "proposed_force": row.get("directive_force", "UNKNOWN"),
            "uncertainty_reasons": list(row["uncertainty_reasons"]),
            "source_is_model_hypothesis": True,
        })
    return {
        "mode": "ADVISORY",
        "module": "M3",
        "model_directives": directives,
        "prompt_injection_verdict": "NOT_EVALUATED",
        "existing_instruction_checks_unchanged": True,
    }
