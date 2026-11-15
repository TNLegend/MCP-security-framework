"""Diagnostic typed claims. Never consulted by authorization or status policy."""

from __future__ import annotations
from app.services.tda.claim_context import claim_mode
from app.services.tda.security_guards.facts import ToolSemanticFacts
from app.services.tda.schema_traversal import iter_schema_fields
from dataclasses import asdict, dataclass
import re
from typing import Literal
from proxy.tool_security_v2 import CapabilityCatalog, ResourceTypeRegistry


@dataclass(frozen=True)
class EffectClaim:
    actor: Literal["TOOL", "AGENT", "UNKNOWN"]
    action: str
    resource: dict
    destination: dict
    condition: dict
    scope: dict
    evidence: tuple[dict, ...]
    uncertainty: tuple[str, ...]
    mode: str


def extract_shadow_effects(snapshot: dict, facts: ToolSemanticFacts) -> dict:
    catalog = CapabilityCatalog()
    registry = ResourceTypeRegistry()
    claims = []
    definitions = catalog.as_policy_data()
    verbs = {x["verb"] for x in definitions}
    fields = list(iter_schema_fields(snapshot.get("input_schema") or {}))
    for relation in facts.action_resource_relations:
        evidence = relation.evidence
        text = evidence.excerpt
        raw = (
            str(snapshot.get(evidence.source) or "")
            if evidence.source == "description"
            else ""
        )
        positions = (
            [m.start() for m in re.finditer(re.escape(text), raw)]
            if raw and text
            else []
        )
        start = positions[0] if len(positions) == 1 else -1
        uncertainty = []
        if len(positions) > 1:
            uncertainty.append("source_span_ambiguous")
        if start < 0:
            uncertainty.append("exact_source_span_unavailable")
        mode = claim_mode(raw, start, start + len(text)) if start >= 0 else "UNKNOWN"
        actor = (
            "AGENT"
            if re.search(
                "\\b(?:you\\s+(?:must|should)|before\\s+(?:using|calling))\\b",
                text,
                re.I,
            )
            else "TOOL"
        )
        action = relation.action
        if action not in verbs:
            uncertainty.append("action_not_in_catalog_verbs")
        types = sorted(
            {
                typ
                for d in definitions
                if d["domain"] == relation.resource and d["verb"] == action
                for typ in d["allowed_resource_types"]
            }
        )
        for typ in types:
            registry.get(typ)
        resource = {
            "category": relation.resource,
            "candidate_resource_types": types,
            "argument_binding": None,
        }
        uncertainty.append("resource_argument_binding_unresolved")
        destination = {"kind": "UNKNOWN", "argument_binding": None, "values": []}
        for target in facts.external_destinations:
            if (
                any(
                    (
                        e.source == evidence.source and e.path == evidence.path
                        for e in target.evidence
                    )
                )
                and target.value in text
            ):
                destination["values"].append(target.value)
        if destination["values"]:
            destination["kind"] = "CLAIMED_EXTERNAL"
        elif action == "send":
            uncertainty.append("destination_unresolved")
        matches = re.finditer("\\b(?:if|unless|when|si|cuando)\\b[^.;]*", text, re.I)
        conditional = next(
            (
                m
                for m in matches
                if start >= 0
                and claim_mode(
                    raw,
                    start + m.start(),
                    start + m.start() + len(m.group().split(maxsplit=1)[0]),
                )
                not in {"QUOTED", "HYPOTHETICAL", "NEGATED"}
            ),
            None,
        )
        condition = {
            "text": conditional.group() if conditional else None,
            "argument_binding": None,
            "enforceable": False,
        }
        if conditional:
            if mode not in {"QUOTED", "NEGATED", "HYPOTHETICAL", "UNKNOWN"}:
                mode = "CONDITIONAL"
            named = [
                p
                for p, name, _ in fields
                if re.search("\\b" + re.escape(name) + "\\b", conditional.group())
            ]
            if len(named) == 1:
                condition["argument_binding"] = named[0]
            uncertainty.append("condition_not_compiled")
        scope_values = [
            s.value
            for s in facts.scopes
            if any((e.path == evidence.path and e.excerpt == text for e in s.evidence))
        ]
        claims.append(
            asdict(
                EffectClaim(
                    actor,
                    action,
                    resource,
                    destination,
                    condition,
                    {"claimed": scope_values, "bound": False},
                    (
                        {
                            "source": evidence.source,
                            "path": evidence.path,
                            "excerpt": text,
                            "start": start if start >= 0 else None,
                            "end": start + len(text) if start >= 0 else None,
                            "trust": "UNTRUSTED_METADATA",
                        },
                    ),
                    tuple(uncertainty),
                    mode,
                )
            )
        )
    return {
        "revision": "typed-effects-shadow-v1",
        "shadow_only": True,
        "creates_permissions": False,
        "capability_catalog_version": catalog.version,
        "resource_registry_version": registry.version,
        "claims": claims,
        "unresolved_semantic_reasons": list(facts.unknown_reasons),
        "limitations": [
            "legacy extraction recall",
            "implicit/conditional actor and destination binding incomplete",
            "not proof of remote behavior",
        ],
    }
