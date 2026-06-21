from agent.llm_adapter.base import LLMProvider


class GroqProvider(LLMProvider):
    def generate_tool_call(self, user_message: str, available_tools: list[dict]) -> dict:
        message = user_message.lower()

        if ".env" in message:
            path = ".env"
        elif "contract" in message or "contrat" in message:
            path = "contracts/contract1.txt"
        else:
            path = "README.md"

        return {
            "tool_name": "read_file",
            "arguments": {
                "path": path,
            },
        }
