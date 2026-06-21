from abc import ABC, abstractmethod


class LLMProvider(ABC):
    @abstractmethod
    def generate_tool_call(self, user_message: str, available_tools: list[dict]) -> dict:
        pass
