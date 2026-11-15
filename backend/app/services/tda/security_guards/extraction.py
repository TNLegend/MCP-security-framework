from __future__ import annotations
from app.services.tda.security_guards.facts import SemanticFact
from app.services.tda.security_guards.facts import ToolSemanticFacts
from app.services.tda.security_guards.facts import _TextSegment
from app.services.tda.security_guards.facts import FactEvidence
from app.services.tda.security_guards.context import _fact_safe_excerpt
from app.services.tda.security_guards.patterns import _ACTION_PATTERNS
from app.services.tda.security_guards.patterns import _DATA_PATTERNS
from app.services.tda.security_guards.patterns import _EXTERNAL_TRANSFER_PATTERNS
from app.services.tda.security_guards.patterns import _IRREVERSIBLE_PATTERNS
from app.services.tda.security_guards.patterns import _PRIVILEGE_PATTERNS
from app.services.tda.security_guards.patterns import _PUBLIC_EXPOSURE_PATTERNS
from app.services.tda.security_guards.patterns import _RESOURCE_PATTERNS
from app.services.tda.security_guards.patterns import _REVERSIBLE_PATTERNS
from app.services.tda.security_guards.patterns import _SCOPE_PATTERNS
from app.services.tda.security_guards.patterns import _URL_RE
from app.services.tda.security_guards.action_resource import (
    _bound_action_resource_relations,
)
from app.services.tda.security_guards.context import _execution_is_explicitly_negated
from app.services.tda.security_guards.context import _financial_domain_unresolved
from app.services.tda.security_guards.context import _match_is_non_operational
from app.services.tda.security_guards.context import _matches_any
from app.services.tda.security_guards.context import _public_destination
from app.services.tda.security_guards.sources import _tool_segments
from app.services.tda.security_guards.context import _url_is_documentation_example
from app.services.tda.security_guards.context import _fact_is_ignored
from typing import Any
import re
_ABSOLUTE_URI_TOKEN_RE = re.compile('(?i)(?:\\b[a-z][a-z0-9+.-]*://[^\\s<>"\\x27]+|\\bmailto:[^@\\s<>"\\x27]+@[a-z0-9.-]+\\.[a-z]{2,})')


class _FactCollector:
    def __init__(self) -> None:
        self._facts: dict[str, dict[str, tuple[float, list[FactEvidence]]]] = {}

    def add(self, category: str, value: str, segment: _TextSegment) -> None:
        category_facts = self._facts.setdefault(category, {})
        base_confidence, evidence = category_facts.setdefault(value, (0.0, []))
        item = FactEvidence(
            source=segment.source,
            path=segment.path,
            excerpt=_fact_safe_excerpt(segment.text),
            kind=segment.kind,
        )
        # Only distinct, retained evidence contributes to the score.
        # Replaying the same observation must be idempotent.
        if item in evidence:
            # A re-observed span may have a higher base score; the order
            # of these repeated observations must not affect confidence.
            category_facts[value] = (max(base_confidence, segment.confidence), evidence)
            return
        if len(evidence) >= 5:
            return
        evidence.append(item)
        category_facts[value] = (max(base_confidence, segment.confidence), evidence)


    def facts(self, category: str) -> tuple[SemanticFact, ...]:
        return tuple(
            (
                SemanticFact(
                    value=value,
                    confidence=min(
                        0.99,
                        confidence
                        + (
                            0.08
                            if len({entry.source for entry in evidence}) > 1
                            else 0.0
                        ),
                    ),
                    evidence=tuple(evidence),
                )
                for value, (confidence, evidence) in sorted(
                    self._facts.get(category, {}).items()
                )
            )
        )


def extract_tool_semantic_facts(tool_snapshot: dict[str, Any]) -> ToolSemanticFacts:
    import re

    segments = list(_tool_segments(tool_snapshot))
    collector = _FactCollector()
    for segment in segments:
        _collect_patterns(collector, "actions", _ACTION_PATTERNS, segment)
        _collect_patterns(collector, "resources", _RESOURCE_PATTERNS, segment)
        _collect_patterns(collector, "data_categories", _DATA_PATTERNS, segment)
        _collect_patterns(collector, "scopes", _SCOPE_PATTERNS, segment)
        _collect_patterns(collector, "privileges", _PRIVILEGE_PATTERNS, segment)
        for raw_url in _URL_RE.findall(segment.text):
            if _url_is_documentation_example(segment.text, raw_url):
                continue
            collector.add(
                "external_destinations", _public_destination(raw_url), segment
            )
        if _matches_any(segment.text, _EXTERNAL_TRANSFER_PATTERNS):
            collector.add("side_effects", "external_transfer", segment)
        if _matches_any(segment.text, _PUBLIC_EXPOSURE_PATTERNS):
            collector.add("side_effects", "public_exposure", segment)
        if (
            segment.source == "execution"
            and _matches_any(segment.text, _RESOURCE_PATTERNS["process"])
            and (not _execution_is_explicitly_negated(segment.text))
        ):
            collector.add("actions", "execute", segment)
    action_values = {item.value for item in collector.facts("actions")}
    external_destinations = collector.facts("external_destinations")
    if "send" in action_values and external_destinations:
        send_fact = next(
            (item for item in collector.facts("actions") if item.value == "send")
        )
        for evidence in send_fact.evidence:
            collector.add(
                "side_effects",
                "external_transfer",
                _TextSegment(
                    source=evidence.source,
                    path=evidence.path,
                    text=evidence.excerpt,
                    confidence=send_fact.confidence,
                    kind=evidence.kind,
                ),
            )
    public_exposure = next(
        (
            item
            for item in collector.facts("side_effects")
            if item.value == "public_exposure"
        ),
        None,
    )
    if public_exposure is not None:
        for evidence in public_exposure.evidence:
            collector.add(
                "scopes",
                "public",
                _TextSegment(
                    source=evidence.source,
                    path=evidence.path,
                    text=evidence.excerpt,
                    confidence=public_exposure.confidence,
                    kind=evidence.kind,
                ),
            )
    for action, side_effect in {
        "create": "state_change",
        "update": "state_change",
        "delete": "destructive",
        "send": "communication",
        "execute": "code_execution",
        "authorize": "access_control_change",
        "transact": "financial_transaction",
    }.items():
        if action not in action_values:
            continue
        action_fact = next(
            (item for item in collector.facts("actions") if item.value == action)
        )
        for evidence in action_fact.evidence:
            collector.add(
                "side_effects",
                side_effect,
                _TextSegment(
                    source=evidence.source,
                    path=evidence.path,
                    text=evidence.excerpt,
                    confidence=action_fact.confidence,
                    kind=evidence.kind,
                ),
            )
    relations = _bound_action_resource_relations(segments)
    combined_text = " ".join((segment.text for segment in segments))
    if _matches_any(combined_text, _IRREVERSIBLE_PATTERNS):
        reversibility = "irreversible"
    elif _matches_any(combined_text, _REVERSIBLE_PATTERNS):
        reversibility = "reversible"
    elif "destructive" in {item.value for item in collector.facts("side_effects")}:
        reversibility = "unknown"
    elif action_values.intersection(
        {"create", "update", "send", "authorize", "transact"}
    ):
        reversibility = "unknown"
    else:
        reversibility = "not_applicable"
    meaningful_sources = {
        "description",
        "input_schema",
        "output_schema",
        "annotations",
        "execution",
    }
    evidenced_actions = {
        fact.value
        for fact in collector.facts("actions")
        if any(
            (
                item.source in meaningful_sources and item.kind == "CLAIM_TEXT"
                for item in fact.evidence
            )
        )
    }
    evidenced_resources = {
        fact.value
        for fact in collector.facts("resources")
        if any(
            (
                item.source in meaningful_sources and item.kind == "CLAIM_TEXT"
                for item in fact.evidence
            )
        )
    }
    unknown_reasons: list[str] = []
    if not evidenced_actions:
        unknown_reasons.append("action_not_evidenced")
    if "health_check" not in evidenced_actions and (not evidenced_resources):
        unknown_reasons.append("resource_not_evidenced")
    for segment in segments:
        if segment.source not in meaningful_sources:
            continue
        for hit in re.finditer(
            "\\b(?:charg\\w*|transf(?:er|ers|erred|erring))\\b",
            segment.text,
            re.IGNORECASE,
        ):
            if _financial_domain_unresolved(segment.text, hit) and (
                not _match_is_non_operational(segment.text, hit)
            ):
                unknown_reasons.append("ambiguous_action_domain")
                break
    if evidenced_actions - {"health_check"} and evidenced_resources and (not relations):
        unknown_reasons.append("action_resource_relation_not_evidenced")
    literal_actions = {
        fact.value
        for fact in collector.facts("actions")
        if any((e.kind == "SCHEMA_VALUE" for e in fact.evidence))
    }
    related_actions = {relation.action for relation in relations}
    if literal_actions - related_actions:
        unknown_reasons.append("schema_operation_hint_unresolved")
    effectful_actions = {
        "create",
        "update",
        "delete",
        "send",
        "execute",
        "authorize",
        "transact",
    }
    if any(
        (
            relation.action in effectful_actions
            and relation.action not in action_values
            for relation in relations
        )
    ):
        unknown_reasons.append("ambiguous_action_polarity")
    return ToolSemanticFacts(
        actions=collector.facts("actions"),
        resources=collector.facts("resources"),
        data_categories=collector.facts("data_categories"),
        side_effects=collector.facts("side_effects"),
        external_destinations=collector.facts("external_destinations"),
        privileges=collector.facts("privileges"),
        scopes=collector.facts("scopes"),
        reversibility=reversibility,
        unknown_reasons=tuple(dict.fromkeys(unknown_reasons)),
        action_resource_relations=relations,
    )


def _collect_patterns(
    collector: _FactCollector,
    category: str,
    patterns_by_value: dict[str, tuple[str, ...]],
    segment: _TextSegment,
) -> None:
    import re

    # Raw URIs are data values, not free-text capability statements.
    # Their path segments can contain words such as 'upload' or 'delete'.
    # Scope matching to the original source spans and reject overlap with
    # any URI; actual prose outside the URI remains available to matching.
    uri_spans = tuple(m.span() for m in _ABSOLUTE_URI_TOKEN_RE.finditer(segment.text))
    for value, patterns in patterns_by_value.items():
        accepted = False
        for pattern in patterns:
            for match in re.finditer(pattern, segment.text, re.IGNORECASE):
                if any(a < match.end() and match.start() < b
                       for a, b in uri_spans):
                    continue
                if _match_is_non_operational(segment.text, match):
                    continue
                if _fact_is_ignored(category, value, segment, match=match):
                    continue
                collector.add(category, value, segment)
                accepted = True
                break
            if accepted:
                break


def claims(snapshot):
    facts = extract_tool_semantic_facts(snapshot)
    return {
        "legacy_semantic_facts": facts.to_dict(),
        "claims": [],
        "links": [],
        "coverage": "PARTIAL",
        "status": "NOT_QUALIFIED_GENERAL_EXTRACTOR",
        "authority": "NON_AUTHORITATIVE",
    }
