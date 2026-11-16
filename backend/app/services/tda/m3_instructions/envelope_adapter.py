"""Design-only M3 module-envelope projection.

Source-owning caller must supply acquisition/catalog identity; never fabricate
server authority. Unlocated legacy raw signals cannot satisfy the Gate3B
evidence_id requirement and are NOT silently promoted into module observations.
"""
from __future__ import annotations
from typing import Any

from app.services.tda.m1_sources.capture import AnalysisContext
from app.services.tda.m3_instructions.contracts import M3Report


def design_envelope(
    report: M3Report, context: AnalysisContext,
    *, source_context: dict[str, Any],
    analyzer_identity: dict[str, Any],
) -> dict[str, Any]:
    if report.mode != "SHADOW" or report.authority != "AT_MOST_REVIEW_ADVISORY":
        raise ValueError("M3_DESIGN_ADAPTER_SHADOW_ONLY")
    if (report.context_id != context.context_id
            or report.source_sha256 != context.original.sha256):
        raise ValueError("M3_DESIGN_SOURCE_MISMATCH")
    if source_context.get("canonical_original_sha256") != context.canonical_original_sha256:
        raise ValueError("M3_DESIGN_SOURCE_PROVENANCE_REQUIRED")
    # Do not infer required registration/authority IDs from untrusted names.
    for field in ("acquisition_id", "snapshot_id", "registration_id",
                  "tool_name", "protocol_profile_id"):
        if not isinstance(source_context.get(field), str) or not source_context[field]:
            raise ValueError("M3_DESIGN_IDENTITY_REQUIRED_" + field.upper())
    if analyzer_identity.get("model_identity") is not None:
        # No M3 neural component selected in Lot 2.
        raise ValueError("M3_DESIGN_NO_MODEL_IN_SHADOW")
    entries = []
    omissions = []
    for row in report.rows:
        if not row.pointer.startswith("/"):
            continue
        scanned = row.status == "INSPECTED"
        entries.append({
            "path": row.pointer, "state": "SCANNED" if scanned else "NOT_ANALYZED",
            "reason": None if scanned else row.detail or "NOT_ANALYZED",
        })
        if not scanned:
            omissions.append({
                "path": row.pointer, "reason": row.detail or "NOT_ANALYZED",
            })
    return {
        "schema_version": "1.0.1-closure-design",
        "module_id": "M3", "mode": "SHADOW", "authority": "NON_AUTHORITATIVE",
        "source_context": dict(source_context),
        "analyzer_identity": dict(analyzer_identity),
        "analysis_status": "PARTIAL",
        "coverage": {
            "scope": ["M3_LOT2_RAW_VALUE_LEXICAL_SHADOW"],
            "complete": False, "semantic_complete": False,
            "entries": entries, "omissions": omissions,
        },
        # No verifiable match spans in V0 lexical results. KEY proofs remain
        # internal to M3 until the shared envelope validator is extended.
        "evidence": [],
        "observations": [{
            "id": "M3:lot2:unresolved-evidence",
            "kind": "INFORMATION_LIMIT", "support": "UNRESOLVED",
            "status": "INCOMPLETE", "evidence_ids": [], "dependency_ids": [],
            "scope": "RAW_LEGACY_FINDINGS", "reason": "NOT_ANALYZED",
            "method_id": "M3_SHADOW_CONTRACT", "method_version": report.version,
        }],
        "result": {"directives": [], "raw_signals": []},
        "limitations": list(dict.fromkeys([
            "M3_INTERNAL_SIGNALS_NOT_EXPORTED_WITHOUT_EXACT_EVIDENCE",
            *report.limitations,
        ])),
    }
