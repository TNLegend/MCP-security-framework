from __future__ import annotations
from app.services.tda.security_guards.facts import ActionResourceRelation
from app.services.tda.security_guards.facts import _TextSegment
from app.services.tda.security_guards.facts import FactEvidence
from app.services.tda.security_guards.patterns import _ACTION_PATTERNS
from app.services.tda.security_guards.patterns import _RESOURCE_PATTERNS
from app.services.tda.security_guards.patterns import _URL_RE
from app.services.tda.security_guards.context import _execution_is_explicitly_negated
from app.services.tda.security_guards.context import _fact_is_ignored
from app.services.tda.security_guards.context import _fact_safe_excerpt
from app.services.tda.security_guards.context import _match_is_non_operational
from app.services.tda.claim_context import quotation_spans


def _bound_action_resource_relations(
    segments: list[_TextSegment],
) -> tuple[ActionResourceRelation, ...]:
    """Conservative predicate/object relations backed by one textual clause.

    Do not combine independent descriptions or schema fields. A relation with
    multiple competing actions/resources in the *same* clause is ambiguous
    rather than an authorization fact.
    """
    import re

    relations: dict[tuple[str, str, str, str], ActionResourceRelation] = {}
    split_pattern = "([;!?\\n]|\\.(?=\\s|$)|\\b(?:and|et|but|mais|puis|then|after|before|apres|avant|while|whereas|pendant\\s+que|alors\\s+que|pendant\\s+qu['?]|alors\\s+qu['?])\\b)"
    for segment in segments:
        if segment.kind != "CLAIM_TEXT":
            continue
        protected = quotation_spans(segment.text)
        for link in _URL_RE.finditer(segment.text):
            end = link.end()
            while end > link.start() and segment.text[end - 1] in ".;!?":
                end -= 1
            protected.append((link.start(), end))
        parts = []
        cursor = 0
        for boundary in re.finditer(split_pattern, segment.text, flags=re.IGNORECASE):
            if any(
                (
                    start <= boundary.start() and boundary.end() <= end
                    for start, end in protected
                )
            ):
                continue
            parts.extend((segment.text[cursor : boundary.start()], boundary.group()))
            cursor = boundary.end()
        parts.append(segment.text[cursor:])
        previous_actions: set[str] = set()
        previous_clause = ""
        for index in range(0, len(parts), 2):
            clause = parts[index].strip()
            if not clause:
                continue
            connector = parts[index - 1].strip().lower() if index else ""
            evidence_segment = _TextSegment(
                segment.source, segment.path, clause, segment.confidence, segment.kind
            )
            hits: dict[str, set[str]] = {"actions": set(), "resources": set()}
            raw_action_mentioned = False
            for category, patterns_by_value in (
                ("actions", _ACTION_PATTERNS),
                ("resources", _RESOURCE_PATTERNS),
            ):
                for value, patterns in patterns_by_value.items():
                    for pattern in patterns:
                        matches = list(re.finditer(pattern, clause, re.IGNORECASE))
                        if category == "actions" and matches:
                            raw_action_mentioned = True
                        if any(
                            (
                                not _match_is_non_operational(clause, hit)
                                and (
                                    not _fact_is_ignored(
                                        category, value, evidence_segment, match=hit
                                    )
                                )
                                for hit in matches
                            )
                        ):
                            hits[category].add(value)
                            break
            if (
                segment.source == "execution"
                and "process" in hits["resources"]
                and (not _execution_is_explicitly_negated(clause))
            ):
                hits["actions"].add("execute")
            relation_excerpt = clause
            if (
                connector in {"and", "et"}
                and len(previous_actions) == 1
                and hits["resources"]
                and (not hits["actions"])
                and (not raw_action_mentioned)
            ):
                hits["actions"] = set(previous_actions)
                relation_excerpt = f"{previous_clause} {connector} {clause}"
            pairs: set[tuple[str, str]] = set()
            if (
                hits["actions"]
                and hits["resources"]
                and (len(hits["actions"]) == 1 or len(hits["resources"]) == 1)
            ):
                pairs.update(
                    (
                        (action, resource)
                        for action in hits["actions"]
                        for resource in hits["resources"]
                    )
                )
            if (
                "send" in hits["actions"]
                and "network_endpoint" in hits["resources"]
                and re.search(
                    "\\b(?:to|towards|via|through|vers)\\b.{0,80}\\b(?:url|endpoint|webhook|host)\\b",
                    clause,
                    re.IGNORECASE,
                )
            ):
                pairs.add(("send", "network_endpoint"))
            for action, resource in sorted(pairs):
                key = (action, resource, segment.source, segment.path)
                relations[key] = ActionResourceRelation(
                    action,
                    resource,
                    FactEvidence(
                        segment.source,
                        segment.path,
                        _fact_safe_excerpt(relation_excerpt),
                        segment.kind,
                    ),
                )
            previous_actions = set(hits["actions"])
            previous_clause = relation_excerpt
    return tuple(relations.values())
