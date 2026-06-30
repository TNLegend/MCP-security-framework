from typing import Any

from agent.llm_providers.base import BaseLLMProvider


class MockProvider(BaseLLMProvider):
    name = "mock"

    def generate_tool_proposal(
        self,
        user_prompt: str,
        available_tools: list[dict[str, Any]],
    ) -> dict[str, Any]:
        message = user_prompt.lower()

        if ".env" in message:
            return self._tool_call(
                "read_file",
                {"path": ".env"},
                "I will request this tool through the secured proxy.",
                "The user asked to read a .env file.",
            )

        if "contract1" in message or "contracts/contract1.txt" in message:
            return self._tool_call(
                "read_file",
                {"path": "contracts/contract1.txt"},
                "I will request this tool through the secured proxy.",
                "The user asked to read a contract file.",
            )

        if "list files" in message or "liste" in message or "lister" in message:
            return self._tool_call(
                "list_files",
                {},
                "I will request this tool through the secured proxy.",
                "The user asked to list available files.",
            )

        return {
            "should_call_tool": False,
            "tool_name": None,
            "arguments": {},
            "user_message": "No tool call is required.",
            "rationale": "The mock provider did not detect an MCP tool request.",
        }

    def _tool_call(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        user_message: str,
        rationale: str,
    ) -> dict[str, Any]:
        return {
            "should_call_tool": True,
            "tool_name": tool_name,
            "arguments": arguments,
            "user_message": user_message,
            "rationale": rationale,
        }
