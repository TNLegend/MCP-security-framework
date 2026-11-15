from __future__ import annotations
from app.services.tda.security_guards.patterns import _SENSITIVE_ACTIONS
from app.services.tda.security_guards.patterns import _SENSITIVE_DATA
from app.services.tda.security_guards.patterns import _SENSITIVE_SIDE_EFFECTS
from typing import Any
from dataclasses import dataclass


@dataclass(frozen=True)
class FactEvidence:
    source: str
    path: str
    excerpt: str
    kind: str = "CLAIM_TEXT"

    def to_dict(self) -> dict[str, str]:
        return {
            "source": self.source,
            "path": self.path,
            "excerpt": self.excerpt,
            "kind": self.kind,
        }


@dataclass(frozen=True)
class SemanticFact:
    value: str
    confidence: float
    evidence: tuple[FactEvidence, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "confidence": round(self.confidence, 3),
            "evidence": [item.to_dict() for item in self.evidence],
        }


@dataclass(frozen=True)
class ActionResourceRelation:
    action: str
    resource: str
    evidence: FactEvidence

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "resource": self.resource,
            "evidence": self.evidence.to_dict(),
        }


@dataclass(frozen=True)
class ToolSemanticFacts:
    actions: tuple[SemanticFact, ...]
    resources: tuple[SemanticFact, ...]
    data_categories: tuple[SemanticFact, ...]
    side_effects: tuple[SemanticFact, ...]
    external_destinations: tuple[SemanticFact, ...]
    privileges: tuple[SemanticFact, ...]
    scopes: tuple[SemanticFact, ...]
    reversibility: str
    unknown_reasons: tuple[str, ...]
    action_resource_relations: tuple[ActionResourceRelation, ...] = ()

    def values(self, category: str, *, sources: set[str] | None = None) -> set[str]:
        facts = getattr(self, category, ())
        if sources is None:
            return {fact.value for fact in facts}
        return {
            fact.value
            for fact in facts
            if any((evidence.source in sources for evidence in fact.evidence))
        }

    @property
    def is_sensitive(self) -> bool:
        return bool(
            self.values("data_categories").intersection(_SENSITIVE_DATA)
            or self.values("actions").intersection(_SENSITIVE_ACTIONS)
            or self.values("side_effects").intersection(_SENSITIVE_SIDE_EFFECTS)
            or self.values("privileges")
            or self.values("scopes").intersection({"bulk", "cross_tenant", "public"})
        )

    @property
    def sensitivity(self) -> str:
        if not self.is_sensitive:
            return "normal"
        if self.values("side_effects").intersection(
            {"code_execution", "access_control_change", "financial_transaction"}
        ) or "credentials" in self.values("data_categories"):
            return "high"
        return "sensitive"

    def to_dict(self) -> dict[str, Any]:
        return {
            "actions": [item.to_dict() for item in self.actions],
            "resources": [item.to_dict() for item in self.resources],
            "data_categories": [item.to_dict() for item in self.data_categories],
            "side_effects": [item.to_dict() for item in self.side_effects],
            "external_destinations": [
                item.to_dict() for item in self.external_destinations
            ],
            "privileges": [item.to_dict() for item in self.privileges],
            "scopes": [item.to_dict() for item in self.scopes],
            "reversibility": self.reversibility,
            "unknown_reasons": list(self.unknown_reasons),
            "action_resource_relations": [
                rel.to_dict() for rel in self.action_resource_relations
            ],
            "is_sensitive": self.is_sensitive,
            "sensitivity": self.sensitivity,
        }


@dataclass(frozen=True)
class _TextSegment:
    source: str
    path: str
    text: str
    confidence: float
    kind: str = "CLAIM_TEXT"
