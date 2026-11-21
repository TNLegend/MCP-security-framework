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
        return self.generate_json(build_tool_prompt(user_prompt, available_tools))

    def generate_json(self, prompt: str) -> dict[str, Any]:
        payload = {
            "model": self.model,
            "temperature": self.temperature,
            # JSON mode ensures the fallback returns a JSON object rather than
            # prose/reasoning. Pydantic and exact schema-path guards still decide
            # whether a suggestion is safe to display.
            "response_format": {"type": "json_object"},
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
        if self.model.startswith("openai/gpt-oss-"):
            # GPT-OSS exposes separate reasoning; reasoning_format is unsupported.
            payload["include_reasoning"] = False
        response = self._post_json(payload)

        try:
            content = response["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise LLMProviderError("Groq response did not include message content.") from exc

        if not isinstance(content, str) or not content.strip():
            raise LLMProviderError("Groq returned an empty response.")

        try:
            result = json.loads(_extract_json_object(content))
        except json.JSONDecodeError as exc:
            raise LLMProviderError("Groq output was not valid JSON.") from exc
        if not isinstance(result, dict):
            raise LLMProviderError("Groq output was not a JSON object.")
        return result

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
            exc.close()
            raise LLMProviderError(
                f"Groq API returned HTTP {exc.code}.",
                code="rate_limited" if exc.code == 429 else "unavailable",
            ) from None
        except URLError as exc:
            if isinstance(exc.reason, TimeoutError):
                raise LLMProviderError("Groq API request timed out.", code="timeout") from None
            raise LLMProviderError("Groq API connection failed.") from None
        except TimeoutError:
            raise LLMProviderError("Groq API request timed out.", code="timeout") from None

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
