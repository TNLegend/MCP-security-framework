import json
import os
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from agent.llm_providers.base import (
    DEFAULT_TIMEOUT_SECONDS,
    BaseLLMProvider,
    LLMProviderError,
    build_tool_prompt,
    get_float_env,
    get_required_secret,
)


DEFAULT_GEMINI_MODEL = "gemini-3.1-flash-lite"


class GeminiProvider(BaseLLMProvider):
    name = "gemini"

    def __init__(self) -> None:
        self.api_key = get_required_secret("GEMINI_API_KEY")
        self.model = os.getenv("GEMINI_MODEL", "").strip() or DEFAULT_GEMINI_MODEL
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
            "contents": [
                {
                    "role": "user",
                    "parts": [
                        {
                            "text": prompt,
                        },
                    ],
                },
            ],
            "generationConfig": {
                "temperature": self.temperature,
            },
        }
        response = self._post_json(payload)

        try:
            text = response["candidates"][0]["content"]["parts"][0]["text"]
        except (KeyError, IndexError, TypeError) as exc:
            raise LLMProviderError("Gemini response did not include text output.") from exc

        if not isinstance(text, str) or not text.strip():
            raise LLMProviderError("Gemini returned an empty response.")

        return json.loads(_extract_json_object(text))

    def _post_json(self, payload: dict[str, Any]) -> dict[str, Any]:
        model = quote(self.model, safe="")
        url = (
            "https://generativelanguage.googleapis.com/v1beta/models/"
            f"{model}:generateContent?key={self.api_key}"
        )
        request = Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:
                response_body = response.read().decode("utf-8")
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise LLMProviderError(
                f"Gemini API returned HTTP {exc.code}: {_shorten(detail)}"
            ) from exc
        except URLError as exc:
            raise LLMProviderError(f"Gemini API request failed: {exc.reason}") from exc
        except TimeoutError as exc:
            raise LLMProviderError("Gemini API request timed out.") from exc

        try:
            data = json.loads(response_body)
        except json.JSONDecodeError as exc:
            raise LLMProviderError("Gemini API returned invalid JSON.") from exc

        if not isinstance(data, dict):
            raise LLMProviderError("Gemini API response was not a JSON object.")
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
        raise LLMProviderError("Gemini output did not contain a JSON object.")
    return cleaned[start : end + 1]


def _shorten(value: str, max_length: int = 500) -> str:
    if len(value) <= max_length:
        return value
    return f"{value[: max_length - 3]}..."
