from __future__ import annotations
import hashlib
from app.services.tda.types import AnalysisFinding
from app.services.tda.configuration import DRIFT_BENIGN
from app.services.tda.configuration import DRIFT_CRITICAL
from app.services.tda.configuration import DRIFT_HIGH
from app.services.tda.configuration import DRIFT_LOW
from app.services.tda.configuration import DRIFT_MEDIUM
from app.services.tda.configuration import DRIFT_NONE
from app.services.tda.types import DriftResult
from app.services.tda.types import EmbeddingModel
from app.services.tda.text import _schema_field_name
from app.services.tda.text import _schema_field_text
from app.services.tda.text import _schema_properties
from app.services.tda.findings import _finding
from app.services.tda.serialization import _safe_json
from app.services.tda.m6_comparison.consistency import capabilities_from_schema
from app.services.tda.m6_comparison.consistency import capabilities_from_text
from app.services.tda.security_guards.extraction import extract_tool_semantic_facts as extract_safety_metadata_facts
from app.services.tda.m6_comparison.constraint_delta import (
    supplemental_constraint_delta,
)
from typing import Any


def _schema_diff(
    previous: dict[str, Any], current: dict[str, Any]
) -> list[dict[str, Any]]:
    from typing import Any
    import re

    changes: list[dict[str, Any]] = []
    previous_props = _schema_properties(previous)
    current_props = _schema_properties(current)
    for name in sorted(set(current_props) - set(previous_props)):
        field_name = _schema_field_name(name)
        field_text = _schema_field_text(current_props[name])
        process_execution = field_name in {"command", "shell", "script"} and bool(
            re.search(
                "\\b(shell|script|process|executable|operating system command).{0,30}\\b(execute|run|launch|execution)\\b|\\b(execute|run|launch).{0,30}\\b(shell|script|process|executable|operating system command)\\b",
                field_text,
                re.IGNORECASE,
            )
        )
        severity = (
            "critical"
            if process_execution
            else "high"
            if field_name in {"upload_url", "callback_url", "destination_url"}
            else "medium"
        )
        changes.append({"type": "parameter_added", "name": name, "severity": severity})
    for name in sorted(set(previous_props) - set(current_props)):
        changes.append({"type": "parameter_removed", "name": name, "severity": "low"})
    for name in sorted(set(previous_props) & set(current_props)):
        if previous_props[name].get("type") != current_props[name].get("type"):
            changes.append(
                {"type": "parameter_type_changed", "name": name, "severity": "high"}
            )
        previous_enum = previous_props[name].get("enum")
        current_enum = current_props[name].get("enum")
        if isinstance(previous_enum, list) and isinstance(current_enum, list):
            if set(map(str, current_enum)) - set(map(str, previous_enum)):
                changes.append(
                    {"type": "enum_expanded", "name": name, "severity": "medium"}
                )
    if previous.get("additionalProperties") != current.get("additionalProperties"):
        changes.append({"type": "additional_properties_modified", "severity": "high"})
    previous_required = set(previous.get("required") or [])
    current_required = set(current.get("required") or [])
    for name in sorted(previous_required - current_required):
        changes.append(
            {"type": "field_became_optional", "name": name, "severity": "medium"}
        )
    for name in sorted(current_required - previous_required):
        changes.append(
            {"type": "field_became_required", "name": name, "severity": "low"}
        )
    return changes


def _drift_capability_severity(capability: str) -> str:
    if capability in {"process.execute", "secret.access"} or capability.endswith(
        ".delete"
    ):
        return "critical"
    if capability.endswith(
        (
            ".write",
            ".send",
            ".manage",
            ".initiate",
            ".refund",
            ".transfer",
            ".execute",
            ".mutate",
        )
    ):
        return "high"
    return "medium"


def _drift_findings(drift: DriftResult) -> list[AnalysisFinding]:
    findings: list[AnalysisFinding] = []
    for change in drift.changes:
        if change.get("severity") in {"high", "critical"}:
            findings.append(
                _finding(
                    f"drift_{change['type']}",
                    "drift",
                    "schema",
                    str(change["severity"]),
                    84,
                    _safe_json(change),
                    "Review the changed tool version before approval.",
                )
            )
    return findings


def _drift_status(changes: list[dict[str, Any]], similarity: float | None) -> str:
    if not changes:
        return DRIFT_NONE if similarity is None else DRIFT_BENIGN
    severities = {change.get("severity") for change in changes}
    if "critical" in severities:
        return DRIFT_CRITICAL
    if "high" in severities:
        return DRIFT_HIGH
    if "medium" in severities:
        return DRIFT_MEDIUM
    return DRIFT_LOW


def _drift_severity_score(status: str) -> int:
    return {
        DRIFT_NONE: 0,
        DRIFT_BENIGN: 5,
        DRIFT_LOW: 15,
        DRIFT_MEDIUM: 40,
        DRIFT_HIGH: 70,
        DRIFT_CRITICAL: 95,
    }.get(status, 40)


def drift_result(
    baseline_snapshot: dict[str, Any] | None,
    current_snapshot: dict[str, Any],
    embedding_model: EmbeddingModel,
) -> DriftResult:
    from typing import Any

    if baseline_snapshot is None:
        return DriftResult(status=DRIFT_NONE, changes=[], similarity=None)
    unchanged_security_definition = all(
        (
            (baseline_snapshot.get(field) or default)
            == (current_snapshot.get(field) or default)
            for field, default in (
                ("name", ""),
                ("description", ""),
                ("input_schema", {}),
                ("output_schema", {}),
                ("annotations", {}),
                ("execution", {}),
            )
        )
    )
    if unchanged_security_definition:
        return DriftResult(status=DRIFT_NONE, changes=[], similarity=1.0)
    changes: list[dict[str, Any]] = []
    previous_schema = baseline_snapshot.get("input_schema") or {}
    current_schema = current_snapshot.get("input_schema") or {}
    changes.extend(_schema_diff(previous_schema, current_schema))
    constraint_delta = supplemental_constraint_delta(previous_schema, current_schema)
    checks = constraint_delta["schema_profile_checks"]
    if (
        checks["previous"]["status"] == "SUPPORTED_PROFILE_SYNTAX"
        and checks["current"]["status"] == "SUPPORTED_PROFILE_SYNTAX"
    ):
        for observation in constraint_delta["changes"]:
            direction = observation["comparison"]
            severity = (
                "high"
                if direction in {"RELAXED", "BOUND_REMOVED"}
                else "low"
                if direction in {"TIGHTENED", "BOUND_ADDED"}
                else "medium"
            )
            changes.append(
                {
                    "type": "input_constraint_modified",
                    "severity": severity,
                    "path": observation["path"],
                    "keyword": observation["keyword"],
                    "previous": observation["old"],
                    "current": observation["new"],
                    "direction": direction,
                    "origin": "EXACT_JSON_SCHEMA",
                }
            )
    if (baseline_snapshot.get("name") or "") != (current_snapshot.get("name") or ""):
        changes.append({"type": "tool_name_modified", "severity": "high"})
    if (baseline_snapshot.get("output_schema") or {}) != (
        current_snapshot.get("output_schema") or {}
    ):
        changes.append({"type": "output_schema_modified", "severity": "medium"})
    if (baseline_snapshot.get("execution") or {}) != (
        current_snapshot.get("execution") or {}
    ):
        changes.append({"type": "execution_modified", "severity": "high"})
    if (baseline_snapshot.get("annotations") or {}) != (
        current_snapshot.get("annotations") or {}
    ):
        changes.append({"type": "annotations_modified", "severity": "medium"})
    previous_caps = capabilities_from_schema(previous_schema)
    current_caps = capabilities_from_schema(current_schema)
    added_caps = sorted(current_caps - previous_caps)
    for capability in added_caps:
        severity = _drift_capability_severity(capability)
        changes.append(
            {"type": "capability_added", "capability": capability, "severity": severity}
        )
    previous_description_caps = capabilities_from_text(
        baseline_snapshot.get("description") or ""
    )
    current_description_caps = capabilities_from_text(
        current_snapshot.get("description") or ""
    )
    for capability in sorted(current_description_caps - previous_description_caps):
        changes.append(
            {
                "type": "description_capability_added",
                "capability": capability,
                "severity": _drift_capability_severity(capability),
            }
        )
    previous_facts = extract_safety_metadata_facts(baseline_snapshot)
    current_facts = extract_safety_metadata_facts(current_snapshot)
    semantic_fact_severities = {
        "side_effects": {
            "destructive": "critical",
            "code_execution": "critical",
            "access_control_change": "critical",
            "financial_transaction": "critical",
            "external_transfer": "high",
            "public_exposure": "high",
            "communication": "medium",
            "state_change": "medium",
        },
        "scopes": {
            "cross_tenant": "high",
            "public": "high",
            "bulk": "high",
            "recursive": "medium",
        },
        "privileges": {
            "administrator": "critical",
            "access_control": "high",
            "delegated_identity": "high",
        },
        "data_categories": {
            "credentials": "critical",
            "personal_data": "high",
            "financial_data": "high",
            "location": "high",
        },
    }
    for category, severity_by_value in semantic_fact_severities.items():
        previous_values = previous_facts.values(category)
        current_values = current_facts.values(category)
        for value in sorted(current_values - previous_values):
            changes.append(
                {
                    "type": "semantic_fact_added",
                    "category": category,
                    "value": value,
                    "severity": severity_by_value.get(value, "medium"),
                }
            )
    previous_description = baseline_snapshot.get("description") or ""
    current_description = current_snapshot.get("description") or ""
    if previous_description == current_description:
        # Exact text equality proves that no description-level change
        # occurred. Avoid costly E5 model loading for schema-only drift.
        similarity = 1.0
    else:
        similarity = embedding_model.similarity(
            previous_description,
            current_description,
        )
    if previous_description != current_description:
        # E5 measures semantic proximity, not verified behavioral equivalence.
        # Every text mutation remains visible as an unresolved comparison;
        # this does not assert a new capability or create an authorization.
        changes.append({
            "type": "description_change_unverified",
            "severity": "medium",
            "origin": "EXACT_TEXT_CHANGE",
            "equivalence": "UNVERIFIED",
            "source_path": "/description",
            "previous_description_sha256": hashlib.sha256(
                previous_description.encode("utf-8")
            ).hexdigest(),
            "current_description_sha256": hashlib.sha256(
                current_description.encode("utf-8")
            ).hexdigest(),
        })
    if similarity < 0.72:
        changes.append({"type": "semantic_description_shift", "severity": "medium"})
    status = _drift_status(changes, similarity)
    return DriftResult(status=status, changes=changes, similarity=similarity)

def drift_result_from_m4(
    baseline_snapshot: dict[str, Any] | None,
    current_snapshot: dict[str, Any],
    embedding_model: EmbeddingModel | None = None,
) -> DriftResult:
    """M6 conservative version drift without old M4 text/fact extraction.

    Exact structural changes are evidence. E5 similarity is an M6 diagnostic,
    not proof of equivalent behavior. Text mutation always stays reviewable.
    """
    if baseline_snapshot is None:
        return DriftResult(status=DRIFT_NONE, changes=[], similarity=None)
    fields = ("name", "description", "input_schema", "output_schema",
              "annotations", "execution")
    defaults = {"name": "", "description": "", "input_schema": {},
                "output_schema": {}, "annotations": {}, "execution": {}}
    changed = [
        key for key in fields
        if (baseline_snapshot.get(key) or defaults[key])
           != (current_snapshot.get(key) or defaults[key])
    ]
    if not changed:
        return DriftResult(status=DRIFT_NONE, changes=[], similarity=1.0)
    changes: list[dict[str, Any]] = []
    if "input_schema" in changed:
        changes.extend(_schema_diff(
            baseline_snapshot.get("input_schema") or {},
            current_snapshot.get("input_schema") or {},
        ))
        changes.append({"type": "input_schema_modified", "severity": "high",
                        "origin": "EXACT_STRUCTURAL_COMPARISON"})
    for name in changed:
        if name == "input_schema":
            continue
        severity = "high" if name in {"execution", "name"} else "medium"
        changes.append({"type": name + "_modified", "severity": severity,
                        "origin": "EXACT_FIELD_COMPARISON"})
    similarity = None
    if "description" in changed and embedding_model is not None:
        similarity = embedding_model.similarity(
            baseline_snapshot.get("description") or "",
            current_snapshot.get("description") or "",
        )
    return DriftResult(
        status=_drift_status(changes, similarity),
        changes=changes, similarity=similarity,
    )
