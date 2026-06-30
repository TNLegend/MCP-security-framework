import json
import os
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from agent.llm_providers.base import (
    DEFAULT_TIMEOUT_SECONDS,
    BaseLLMProvider,
    LLMProviderError,
    build_tool_prompt,
    get_float_env,
    get_required_secret,
)


DEFAULT_GROQ_MODEL = "openai/gpt-oss-20b"


class GroqProvider(BaseLLMProvider):
    name = "groq"

    def __init__(self) -> None:
        self.api_key = get_required_secret("GROQ_API_KEY")
        self.model = os.getenv("GROQ_MODEL", "").strip() or DEFAULT_GROQ_MODEL
        self.temperature = get_float_env("LLM_TEMPERATURE", 0.0)
        self.timeout_seconds = get_float_env(
            "LLM_TIMEOUT_SECONDS",
            DEFAULT_TIMEOUT_SECONDS,
        )

    def generate_tool_proposal(
        self,
        user_prompt: str,
        available_tools: list[dict[str, Any]],
    ) -> dict[str, Any]:
        prompt = build_tool_prompt(user_prompt, available_tools)
        payload = {
            "model": self.model,
            "temperature": self.temperature,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "Return one valid JSON object only. "
                        "Do not use markdown. "
                        "Do not wrap the JSON in code fences. "
                        "Propose MCP tool calls only; never execute tools."
                    ),
                },
                {
                    "role": "user",
                    "content": prompt,
                },
            ],
        }
        response = self._post_json(payload)

        try:
            content = response["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise LLMProviderError("Groq response did not include message content.") from exc

        if not isinstance(content, str) or not content.strip():
            raise LLMProviderError("Groq returned an empty response.")

        return json.loads(_extract_json_object(content))

    def _post_json(self, payload: dict[str, Any]) -> dict[str, Any]:
        request = Request(
            "https://api.groq.com/openai/v1/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": "mcp-security-framework/0.1.0",
            },
            method="POST",
        )

        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:
                response_body = response.read().decode("utf-8")
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise LLMProviderError(
                f"Groq API returned HTTP {exc.code}: {_shorten(detail)}"
            ) from exc
        except URLError as exc:
            raise LLMProviderError(f"Groq API request failed: {exc.reason}") from exc
        except TimeoutError as exc:
            raise LLMProviderError("Groq API request timed out.") from exc

        try:
            data = json.loads(response_body)
        except json.JSONDecodeError as exc:
            raise LLMProviderError("Groq API returned invalid JSON.") from exc

        if not isinstance(data, dict):
            raise LLMProviderError("Groq API response was not a JSON object.")
        return data


def _extract_json_object(text: str) -> str:
    cleaned = text.strip()
    if cleaned.startswith("```"):
        lines = cleaned.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        cleaned = "\n".join(lines).strip()

    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise LLMProviderError("Groq output did not contain a JSON object.")
    return cleaned[start : end + 1]


def _shorten(value: str, max_length: int = 500) -> str:
    if len(value) <= max_length:
        return value
    return f"{value[: max_length - 3]}..."
