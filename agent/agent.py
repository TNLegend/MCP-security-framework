import json

from agent.llm_adapter.adapter import LLMAdapter

AVAILABLE_TOOLS = [
    {
        "name": "read_file",
        "description": "Read a file from an authorized directory.",
        "parameters": {
            "path": "string",
        },
    },
]


class DemoAgent:
    def __init__(self, llm_adapter: LLMAdapter | None = None) -> None:
        self.llm_adapter = llm_adapter or LLMAdapter()

    def propose_tool_call(self, user_message: str) -> dict:
        return self.llm_adapter.generate_tool_call(user_message, AVAILABLE_TOOLS)


def main() -> None:
    agent = DemoAgent()

    messages = [
        "Lis le fichier contracts/contract1.txt",
        "Lis le fichier .env",
    ]

    for message in messages:
        print(f"User message: {message}")
        tool_call = agent.propose_tool_call(message)
        print(json.dumps(tool_call, indent=2))


if __name__ == "__main__":
    main()
