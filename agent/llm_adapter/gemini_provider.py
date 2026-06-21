from agent.llm_adapter.base import LLMProvider


class GeminiProvider(LLMProvider):
    def generate_tool_call(self, user_message: str, available_tools: list[dict]) -> dict:
        message = user_message.lower()

        if ".env" in message:
            return self._read_file_call(".env")

        if "contract" in message or "contrat" in message:
            return self._read_file_call("contracts/contract1.txt")

        return self._read_file_call("README.md")

    def _read_file_call(self, path: str) -> dict:
        return {
            "tool_name": "read_file",
            "arguments": {
                "path": path,
            },
        }
