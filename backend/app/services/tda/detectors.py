from __future__ import annotations
from app.services.tda.m7_assessment.cross_checks import _schema_findings, _contextual_security_review_findings
from app.services.tda.m2_structure.schema_checks import (
    schema_header_findings,
    schema_parameter_findings,
)
from app.services.tda.schema_traversal import iter_schema_fields
from app.services.tda.serialization import _safe_json
from app.services.tda.types import AnalysisFinding
from app.services.tda.security_guards.facts import ToolSemanticFacts
from app.services.tda.text import _annotation_text
from app.services.tda.findings import _deduplicate_findings
from app.services.tda.m3_instructions.detectors import _text_findings
from app.services.tda.m6_comparison.consistency import capabilities_from_profile
from app.services.tda.security_guards.extraction import extract_tool_semantic_facts as extract_safety_metadata_facts
from app.services.tda.configuration import FINDING_DECISION_REVIEW
from app.services.tda.configuration import SEMANTIC_CORROBORATION_PATTERNS
from app.services.tda.findings import _finding
from app.services.tda.security_guards.risk_support import _semantic_fact_support
from app.services.tda.m3_instructions.semantic_input import _semantic_text
from app.services.tda.linguistic_context import operational_pattern_search
from app.services.tda.claim_context import poisoning_signals, metadata_texts
from app.services.tda.m3_instructions.authority_relation import (
    extract_priority_relations,
)
from app.services.tda.security_guards.transfer_relation import positive_external_transfers
from typing import Any


def deterministic_findings(
    tool_snapshot: dict[str, Any],
    profile_snapshot: dict[str, Any] | None,
    *,
    semantic_facts: ToolSemanticFacts | None = None,
) -> list[AnalysisFinding]:
    findings: list[AnalysisFinding] = []
    facts = semantic_facts or extract_safety_metadata_facts(tool_snapshot)
    profile_capabilities = capabilities_from_profile(profile_snapshot or {})
    text_sources = {
        "description": tool_snapshot.get("description") or "",
        "annotation": _annotation_text(tool_snapshot.get("annotations") or {}),
        "execution": _annotation_text(tool_snapshot.get("execution") or {}),
    }
    for source, text in text_sources.items():
        findings.extend(_text_findings(source, text))
    schema = tool_snapshot.get("input_schema") or {}
    output_schema = tool_snapshot.get("output_schema") or {}
    findings.extend(
        _schema_findings(schema, "input_schema", profile_capabilities, facts)
    )
    findings.extend(
        _schema_findings(output_schema, "output_schema", profile_capabilities, facts)
    )
    findings.extend(_contextual_security_review_findings(tool_snapshot, facts))
    return _deduplicate_findings(findings)
