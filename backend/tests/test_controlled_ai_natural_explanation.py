"""The controlled AI may explain evidence, but cannot create security authority."""
import pytest
from pydantic import ValidationError

from app.schemas.controlled_ai import ControlledAIAssistancePublic
from app.services.controlled_ai_assistance import _AIAdvice, _build_prompt


def test_explanation_is_optional_for_old_provider_results():
    old = _AIAdvice.model_validate({
        "confidence": .5, "evidence_refs": ["analysis:17"],
        "template_ids": [], "adapter_ids": [],
    })
    assert old.explanation == ""


def test_specific_explanation_is_bounded_and_extra_decisions_rejected():
    text = (
        "The current report contains a HIGH finding about the declared "
        "tool behavior. This evidence warrants administrator review but "
        "does not prove what the remote implementation will execute."
    )
    advice = _AIAdvice.model_validate({
        "confidence": .6, "evidence_refs": ["finding:TOOL_SCOPE_RISK"],
        "template_ids": [], "adapter_ids": [], "explanation": text,
    })
    assert advice.explanation == text
    with pytest.raises(ValidationError):
        _AIAdvice.model_validate({
            **advice.model_dump(), "recommended_action": "APPROVE_AND_EXECUTE",
        })
    with pytest.raises(ValidationError):
        _AIAdvice.model_validate({
            **advice.model_dump(), "explanation": "x" * 1801,
        })


def test_provider_prompt_requests_exact_typed_evidence_without_provider_prose():
    prompt = _build_prompt(
        mode="EXPLAIN",
        question="Pourquoi cet outil nécessite-t-il une revue ?",
        context={
            "analysis": {"risk_level": "HIGH", "analysis_status": "REVIEW_REQUIRED"},
            "findings": [{"code": "TOOL_SCOPE_RISK", "severity": "HIGH"}],
            "evidence_refs": ["finding:TOOL_SCOPE_RISK"],
        },
    )
    assert "type and evidence_ids" in prompt
    assert "Do not generate claim text" in prompt
    assert "the operator question" in prompt
    assert "never assert" not in prompt.lower() or "Never assert" in prompt
    assert "You cannot approve tools" in prompt


def test_public_response_separates_model_explanation_from_framework_facts():
    response = ControlledAIAssistancePublic(
        mode="EXPLAIN", provider="gemini",
        tool_id=9, fingerprint="a" * 64, analysis_id=17,
        summary="The current state still requires human review.",
        ai_explanation="This HIGH finding points to permissions beyond the described tool scope.",
        recommended_action="HUMAN_REVIEW",
        rationale="Review the recorded findings through the approval workflow.",
        confidence=.7,
    )
    assert response.ai_explanation.startswith("This HIGH")
    assert response.non_authoritative is True
    assert response.requires_human_review is True
    assert response.can_mutate_runtime is False
