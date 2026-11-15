from __future__ import annotations
from app.services.tda.configuration import SEMANTIC_CORROBORATION_PATTERNS
from app.services.tda.configuration import SEMANTIC_REVIEW_THRESHOLD
from app.services.tda.types import SemanticResult
from app.services.tda.security_guards.facts import ToolSemanticFacts
from app.services.tda.security_guards.risk_support import _semantic_fact_support
from app.services.tda.linguistic_context import operational_pattern_search


def _corroborate_semantic_result(
    result: SemanticResult, text: str, facts: ToolSemanticFacts
) -> SemanticResult:
    from dataclasses import replace

    candidates = sorted(
        (
            (category, score)
            for category, score in result.scores.items()
            if category != "normal_tool_description"
        ),
        key=lambda item: item[1],
        reverse=True,
    )
    fact_supported_categories = {
        "secret_collection",
        "data_exfiltration",
        "hidden_additional_action",
        "unauthorized_data_access",
        "privilege_escalation",
        "cross_tenant_access",
        "unexpected_destructive_operation",
        "public_sharing",
        "bulk_messaging",
        "server_side_request_forgery",
        "shell_injection",
        "unauthorized_financial_transaction",
    }
    for category, score in candidates:
        if score < SEMANTIC_REVIEW_THRESHOLD:
            continue
        patterns = SEMANTIC_CORROBORATION_PATTERNS.get(category, ())
        pattern_match = any(
            (operational_pattern_search(pattern, text) for pattern in patterns)
        )
        fact_support = _semantic_fact_support(category, facts, text)
        if (
            pattern_match
            and fact_support
            or (category in fact_supported_categories and fact_support)
        ):
            return replace(
                result, best_category=category, confidence=score, flagged=True
            )
    return replace(result, flagged=False)
