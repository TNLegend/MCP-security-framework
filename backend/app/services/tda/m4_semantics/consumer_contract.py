"""Strict M4 -> M3/M6/M7 *advisory* handoff, isolated migration candidate.

The only trusted fact here is that an excerpt occurs at the recorded offset
in the recorded source text. A model hypothesis is NOT a capability, an observed
effect, a prompt injection verdict, a risk score, or a permission.
"""
from __future__ import annotations

import hashlib
from typing import Any

ROLES = frozenset({"HAS_OBJECT", "HAS_SOURCE", "HAS_DESTINATION",
                   "HAS_CONDITION", "HAS_QUALIFIER"})
HEADS = ("speech_act", "actor", "polarity", "directive_force")
# Exact frozen labels from DEBERTA_V2/LABELS_FOUR_HEADS.json.
VALID_LABELS = {
    "speech_act": frozenset({"CLAIM", "DIRECTIVE", "MENTION"}),
    "actor": frozenset({"TOOL", "CALLER", "END_USER", "THIRD_PARTY"}),
    "polarity": frozenset({"AFFIRMED", "DENIED", "NONCOMMITTAL", "NOT_APPLICABLE"}),
    "directive_force": frozenset({"REQUIRE", "PROHIBIT", "RECOMMEND", "PERMIT", "NOT_APPLICABLE"}),
}


class M4ConsumerContractError(ValueError):
    pass


def _exact(span: Any, text: str) -> dict[str, Any]:
    if not isinstance(span, dict):
        raise M4ConsumerContractError("MISSING_SPAN")
    start, end = span.get("start"), span.get("end")
    if (type(start) is not int or type(end) is not int or
            not (0 <= start < end <= len(text)) or
            span.get("text") != text[start:end]):
        raise M4ConsumerContractError("M4_EXCERPT_NOT_EXACT_SOURCE")
    return {"start": start, "end": end, "text": text[start:end],
            "source_path": "/description"}


def _labels(classification: Any) -> tuple[dict[str, str], list[str]]:
    classification = classification if isinstance(classification, dict) else {}
    raw = classification.get("heads")
    raw = raw if isinstance(raw, dict) else {}
    labels: dict[str, str] = {}
    issues: list[str] = []
    for head in HEADS:
        item = raw.get(head)
        val = item.get("label") if isinstance(item, dict) else None
        if not isinstance(val, str) or not val:
            labels[head] = "UNKNOWN"
            issues.append("MISSING_CLASSIFICATION_" + head.upper())
        elif val not in VALID_LABELS[head]:
            labels[head] = "UNKNOWN"
            issues.append("INVALID_CLASSIFICATION_" + head.upper())
        else:
            labels[head] = val
    if classification.get("status") != "MODEL_HYPOTHESIS":
        issues.append("CLASSIFICATION_NOT_ESTABLISHED")
    return labels, issues


def project_m4_for_consumers(report: dict[str, Any],
                             source_text: str) -> dict[str, Any]:
    """Produce isolated read-only inputs for downstream modules.

    Strict evidence checks, no conversion to ToolSemanticFacts or security
    capabilities. Such a conversion would prematurely promote model output
    to the legacy decision engine.
    """
    if not isinstance(report, dict) or not isinstance(source_text, str):
        raise M4ConsumerContractError("REPORT_AND_SOURCE_REQUIRED")
    if (report.get("mode") != "SHADOW" or
            report.get("authority") != "NON_AUTHORITATIVE"):
        raise M4ConsumerContractError("M4_NON_ADVISORY_REPORT_REFUSED")
    if report.get("source_path") != "/description":
        raise M4ConsumerContractError("M4_UNKNOWN_SOURCE_PATH")
    if report.get("source_sha256") != hashlib.sha256(
            source_text.encode("utf-8")).hexdigest():
        raise M4ConsumerContractError("M4_SOURCE_DIGEST_MISMATCH")
    raw_events = report.get("events")
    if not isinstance(raw_events, list):
        raise M4ConsumerContractError("M4_EVENTS_REQUIRED")

    operations = []
    directives = []
    uncertainties: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for number, raw_event in enumerate(raw_events):
        if not isinstance(raw_event, dict):
            raise M4ConsumerContractError("M4_EVENT_NOT_OBJECT")
        event_id = raw_event.get("event_id")
        if not isinstance(event_id, str) or not event_id or event_id in seen_ids:
            raise M4ConsumerContractError("M4_DUPLICATE_OR_MISSING_EVENT_ID")
        seen_ids.add(event_id)
        predicate = _exact(raw_event.get("predicate"), source_text)
        labels, issues = _labels(raw_event.get("classification"))
        raw_uncertainties = raw_event.get("uncertainty_reasons")
        if raw_uncertainties is None:
            raw_uncertainties = []
        if not isinstance(raw_uncertainties, list) or any(
            not isinstance(x, str) for x in raw_uncertainties
        ):
            raise M4ConsumerContractError("M4_UNCERTAINTIES_NOT_STRING_LIST")
        issues.extend(raw_uncertainties)
        if raw_event.get("source_path") != "/description":
            raise M4ConsumerContractError("M4_EVENT_SOURCE_PATH_MISMATCH")
        links = raw_event.get("links", [])
        if not isinstance(links, list):
            raise M4ConsumerContractError("M4_LINKS_NOT_LIST")
        arguments = []
        for link in links:
            if not isinstance(link, dict) or link.get("role") not in ROLES:
                raise M4ConsumerContractError("M4_UNKNOWN_RELATION_ROLE")
            head = _exact(link.get("head"), source_text)
            tail = _exact(link.get("tail"), source_text)
            if (head["start"], head["end"]) != (
                    predicate["start"], predicate["end"]):
                raise M4ConsumerContractError("M4_RELATION_HEAD_NOT_PREDICATE")
            supported = (
                link.get("support") == "MODEL_HYPOTHESIS" and
                link.get("head_predicate_detected") is True and
                link.get("target_entity_detected") is True and
                link.get("multiple_roles_same_pair") is False)
            if not supported:
                issues.append("RELATION_UNRESOLVED")
            arguments.append({
                "role": link["role"], "span": tail,
                "interpretation": "MODEL_HYPOTHESIS" if supported else "UNRESOLVED",
                "verified_effect": False})
        issues = sorted(set(issues))
        event = {
            "event_id": event_id, "predicate": predicate, "labels": labels,
            "arguments": arguments, "uncertainty_reasons": issues,
            "source_evidence": "EXACT_TEXT_SPAN",
            "truth_status": "MODEL_HYPOTHESIS_UNVERIFIED",
            "asserted_capability": None,
            "authorized_effect": None}
        operations.append(event)
        if labels["speech_act"] == "DIRECTIVE":
            directives.append({
                "event_id": event_id, "predicate": predicate,
                "actor": labels["actor"],
                "directive_force": labels["directive_force"],
                "uncertainty_reasons": issues,
                "prompt_injection_verdict": "NOT_EVALUATED"})
        if issues:
            uncertainties.append({"event_id": event_id, "reasons": issues})

    raw_unresolved = report.get("unresolved_predictions", [])
    if not isinstance(raw_unresolved, list):
        raise M4ConsumerContractError("M4_UNRESOLVED_NOT_LIST")
    coverage = report.get("coverage")
    coverage = coverage if isinstance(coverage, dict) else {}
    return {
        "mode": "SHADOW", "authority": "NON_AUTHORITATIVE",
        "source_sha256": report["source_sha256"],
        "source_path": "/description",
        "m3": {"advisory_directives": directives,
               "instruction_verdict": "NOT_EVALUATED"},
        "m6": {"advisory_operations": operations,
               "capability_comparison": "NOT_EVALUATED",
               "drift_comparison": "NOT_EVALUATED"},
        "m7": {"events_seen": len(operations),
               "events_with_uncertainty": uncertainties,
               "unresolved_prediction_count": len(raw_unresolved),
               "source_token_coverage": coverage.get("source_tokens_covered"),
               "risk_or_approval_decision": "NOT_EVALUATED"},
        "security_decision_changes": "NONE",
        "claims_promoted_to_fact": 0,
    }
