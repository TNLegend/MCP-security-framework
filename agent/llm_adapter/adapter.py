from agent.llm_adapter.gemini_provider import GeminiProvider
from agent.llm_adapter.groq_provider import GroqProvider


class LLMAdapter:
    def __init__(
        self,
        primary_provider: GeminiProvider | None = None,
        fallback_provider: GroqProvider | None = None,
    ) -> None:
        self.primary_provider = primary_provider or GeminiProvider()
        self.fallback_provider = fallback_provider or GroqProvider()

    def generate_tool_call(self, user_message: str, available_tools: list[dict]) -> dict:
        try:
            return self.primary_provider.generate_tool_call(user_message, available_tools)
        except Exception:
            return self.fallback_provider.generate_tool_call(user_message, available_tools)
