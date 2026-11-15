from __future__ import annotations
from typing import Any
from typing import Protocol
from dataclasses import dataclass


@dataclass(frozen=True)
class AnalysisFinding:
    code: str
    category: str
    source: str
    severity: str
    confidence: int
    evidence: dict[str, Any]
    recommendation: str


@dataclass(frozen=True)
class SemanticResult:
    scores: dict[str, float]
    best_category: str
    confidence: float
    model_name: str
    model_version: str
    flagged: bool
    coverage: dict[str, Any] | None = None


@dataclass(frozen=True)
class DriftResult:
    status: str
    changes: list[dict[str, Any]]
    similarity: float | None


class SemanticModel(Protocol):
    def classify(self, text: str, categories: list[str]) -> SemanticResult: ...


class EmbeddingModel(Protocol):
    def similarity(self, previous_text: str, current_text: str) -> float: ...


class SemanticModelUnavailable(RuntimeError):
    pass
