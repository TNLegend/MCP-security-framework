import os
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_TIMEOUT_SECONDS = 20.0


class LLMProviderError(Exception):
    pass


class BaseLLMProvider:
    name = "base"

    def generate_tool_proposal(
        self,
        user_prompt: str,
        available_tools: list[dict[str, Any]],
    ) -> dict[str, Any]:
        raise NotImplementedError


def load_project_env() -> None:
    env_path = REPO_ROOT / ".env"
    if not env_path.exists():
        return

    for line in env_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue

        key, value = stripped.split("=", maxsplit=1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def get_required_secret(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value or value == "change_me":
        raise LLMProviderError(f"{name} is not configured.")
    return value


def get_float_env(name: str, default: float) -> float:
    value = os.getenv(name)
    if value is None or value == "":
        return default

    try:
        return float(value)
    except ValueError as exc:
        raise LLMProviderError(f"{name} must be a number.") from exc


def build_tool_prompt(user_prompt: str, available_tools: list[dict[str, Any]]) -> str:
    tools_text = format_available_tools(available_tools)
    return f"""
You are an AI agent using MCP tools through a security framework.

You never execute tools directly.
You only propose one structured tool call as JSON.
The MCP Security Framework proxy will decide whether execution is allowed.

Available tools:
{tools_text}

Rules:
- Return JSON only.
- Choose at most one tool.
- Choose only a tool from the available tools list.
- Do not invent tools or parameters.
- If no tool is needed, set should_call_tool to false.
- If a tool is needed, set should_call_tool to true and provide tool_name and arguments.

Required JSON format:
{{
  "should_call_tool": true,
  "tool_name": "read_file",
  "arguments": {{
    "path": "contracts/contract1.txt"
  }},
  "user_message": "I will request this tool through the secured proxy.",
  "rationale": "The user asked to read a contract file."
}}

User prompt:
{user_prompt}
""".strip()


def format_available_tools(available_tools: list[dict[str, Any]]) -> str:
    lines = []
    for tool in available_tools:
        lines.append(
            "- "
            f"name={tool.get('name')}, "
            f"title={tool.get('title')}, "
            f"description={tool.get('description')}, "
            f"input_schema={tool.get('input_schema')}, "
            f"sensitivity={tool.get('sensitivity')}, "
            f"risk_score={tool.get('risk_score')}, "
            f"policy_status={tool.get('policy_status')}"
        )
    return "\n".join(lines) if lines else "- no tools available"
