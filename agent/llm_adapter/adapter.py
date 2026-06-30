import os
from typing import Any

from agent.llm_providers.base import (
    BaseLLMProvider,
    LLMProviderError,
    load_project_env,
)
from agent.llm_providers.gemini_provider import GeminiProvider
from agent.llm_providers.groq_provider import GroqProvider
from agent.llm_providers.mock_provider import MockProvider
from agent.tool_call_schema import (
    ToolProposalValidationError,
    normalize_tool_proposal,
    safe_no_tool_response,
)


PROVIDERS: dict[str, type[BaseLLMProvider]] = {
    "mock": MockProvider,
    "gemini": GeminiProvider,
    "groq": GroqProvider,
}


class LLMAdapter:
    def __init__(
        self,
        primary_provider_name: str | None = None,
        fallback_provider_name: str | None = None,
    ) -> None:
        load_project_env()
        self.primary_provider_name = normalize_provider_name(
            primary_provider_name or os.getenv("LLM_PROVIDER") or "mock"
        )
        self.fallback_provider_name = normalize_provider_name(
            fallback_provider_name
            if fallback_provider_name is not None
            else os.getenv("LLM_FALLBACK_PROVIDER", "")
        )

    def generate_tool_proposal(
        self,
        user_prompt: str,
        available_tools: list[dict[str, Any]],
    ) -> dict[str, Any]:
        provider_names = [self.primary_provider_name]
        if (
            self.fallback_provider_name
            and self.fallback_provider_name != self.primary_provider_name
        ):
            provider_names.append(self.fallback_provider_name)

        provider_errors = []
        for index, provider_name in enumerate(provider_names):
            try:
                proposal = self._generate_with_provider(
                    provider_name,
                    user_prompt,
                    available_tools,
                )
                proposal["provider"] = provider_name
                proposal["fallback_used"] = index > 0
                proposal["provider_error"] = (
                    "; ".join(provider_errors) if provider_errors else None
                )
                return proposal
            except Exception as exc:
                provider_errors.append(f"{provider_name}: {exc}")

        response = safe_no_tool_response(
            user_message="No valid tool proposal was produced.",
            rationale="All configured LLM providers failed.",
        )
        response["provider"] = None
        response["fallback_used"] = len(provider_errors) > 1
        response["provider_error"] = "; ".join(provider_errors) if provider_errors else None
        return response

    def generate_tool_call(
        self,
        user_message: str,
        available_tools: list[dict[str, Any]],
    ) -> dict[str, Any]:
        proposal = self.generate_tool_proposal(user_message, available_tools)
        if not proposal.get("should_call_tool"):
            return {
                "tool_name": None,
                "arguments": {},
                "proposal": proposal,
            }

        return {
            "tool_name": proposal["tool_name"],
            "arguments": proposal["arguments"],
            "proposal": proposal,
        }

    def _generate_with_provider(
        self,
        provider_name: str,
        user_prompt: str,
        available_tools: list[dict[str, Any]],
    ) -> dict[str, Any]:
        provider_class = PROVIDERS.get(provider_name)
        if provider_class is None:
            raise LLMProviderError(f"Unsupported LLM provider '{provider_name}'.")

        provider = provider_class()
        raw_proposal = provider.generate_tool_proposal(user_prompt, available_tools)
        try:
            return normalize_tool_proposal(raw_proposal, available_tools)
        except ToolProposalValidationError as exc:
            raise LLMProviderError(f"Invalid tool proposal: {exc}") from exc


def normalize_provider_name(value: str | None) -> str:
    return (value or "").strip().lower()
