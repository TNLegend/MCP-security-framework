"""UX-14: AI format failures are not outages; each attempt is validated before selection.

Uses fake in-process providers only: no network, no credentials, no provider calls.
"""
from __future__ import annotations

import pytest

from agent.llm_providers.base import LLMProviderError
from app.services import controlled_ai_assistance as ai
from app.services.controlled_ai_assistance import ControlledAIAssistanceError, _generate_advice

ALLOWED = {"analysis:7", "finding:SCOPE_MISMATCH"}
VALID = {"explanation": "The scope check failed for the recorded finding.",
         "evidence_refs": ["finding:SCOPE_MISMATCH"], "template_ids": [], "adapter_ids": [], "confidence": 0.6}


def provider(result=None, error=None, seen=None):
    class Fake:
        timeout_seconds = 20.0

        def generate_json(self, prompt):
            if seen is not None:
                seen.append(self.timeout_seconds)
            if error is not None:
                raise error
            return result
    return Fake


@pytest.fixture(autouse=True)
def providers_env(monkeypatch):
    monkeypatch.setattr(ai, "load_project_environment", lambda: None)
    monkeypatch.setenv("CONTROLLED_AI_PROVIDER", "primary")
    monkeypatch.setenv("CONTROLLED_AI_FALLBACK_PROVIDER", "fallback")
    monkeypatch.delenv("CONTROLLED_AI_REQUEST_BUDGET_SECONDS", raising=False)


def run(types, **kwargs):
    return _generate_advice("prompt", allowed_evidence=ALLOWED, allowed_templates=set(),
                            allowed_adapters=set(), provider_types=types, **kwargs)


def failure(types, **kwargs):
    with pytest.raises(ControlledAIAssistanceError) as caught:
        run(types, **kwargs)
    return caught.value


def test_malformed_primary_falls_back_to_valid_reply():
    advice, name, fallback_used = run({"primary": provider({"explanation": "x", "bogus": 1}),
                                       "fallback": provider(VALID)})
    assert (name, fallback_used, advice.evidence_refs) == ("fallback", True, ("finding:SCOPE_MISMATCH",))


def test_out_of_set_reference_triggers_fallback_instead_of_failing_later():
    invented = {**VALID, "evidence_refs": ["finding:INVENTED_PERMISSION"]}
    advice, name, _ = run({"primary": provider(invented), "fallback": provider(VALID)})
    assert name == "fallback"


def test_both_malformed_is_response_invalid_not_unavailable():
    error = failure({"primary": provider({"confidence": "high", "oops": True}),
                     "fallback": provider({**VALID, "evidence_refs": ["nope"]})})
    assert error.code == "controlled_ai_response_invalid"
    assert [a["outcome"] for a in error.attempts] == ["schema_invalid", "reference_invalid"]


def test_numeric_string_and_percentage_confidence_are_accepted():
    for value, expected in (("0.8", 0.8), ("75%", 0.75), (80, 0.8), ("not a number", None)):
        advice, _, _ = run({"primary": provider({**VALID, "confidence": value}), "fallback": provider(VALID)})
        assert advice.confidence == pytest.approx(expected) if expected is not None else advice.confidence is None


def test_rate_limit_timeout_missing_credentials_and_unavailable_are_distinct():
    assert failure({"primary": provider(error=LLMProviderError("x", code="rate_limited")),
                    "fallback": provider(error=LLMProviderError("x", code="timeout"))}).code == "controlled_ai_rate_limited"
    assert failure({"primary": provider(error=LLMProviderError("x", code="timeout")),
                    "fallback": provider(error=LLMProviderError("y"))}).code == "controlled_ai_timeout"
    missing = failure({"primary": provider(error=LLMProviderError("GEMINI_API_KEY is not configured.")),
                       "fallback": provider(error=LLMProviderError("GROQ_API_KEY is not configured."))})
    assert missing.code == "controlled_ai_not_configured"
    assert failure({"primary": provider(error=RuntimeError("boom")),
                    "fallback": provider(error=RuntimeError("boom"))}).code == "controlled_ai_unavailable"
    assert failure({}).code == "controlled_ai_not_configured"


def test_total_budget_bounds_fallback_and_shrinks_provider_timeout(monkeypatch):
    monkeypatch.setenv("CONTROLLED_AI_REQUEST_BUDGET_SECONDS", "10")
    ticks = iter([0.0, 0.0, 9.5])  # start, before primary, before fallback
    seen = []
    error = failure({"primary": provider(error=LLMProviderError("x", code="timeout"), seen=seen),
                     "fallback": provider(VALID, seen=seen)}, clock=lambda: next(ticks))
    assert seen == [10.0]  # primary got the remaining budget, not its 20 s default
    assert [a["outcome"] for a in error.attempts] == ["timeout", "budget_exhausted"]
    assert error.code == "controlled_ai_timeout"


def test_attempt_records_never_contain_raw_provider_text():
    error = failure({"primary": provider(error=LLMProviderError("secret-key-ABC123 leaked in message")),
                     "fallback": provider({"raw": "payload"})})
    assert "secret" not in repr(error.attempts) and "payload" not in repr(error.attempts)
    assert all(set(a) == {"provider", "outcome"} for a in error.attempts)
