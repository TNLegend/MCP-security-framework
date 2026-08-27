import os
import unittest
from unittest.mock import patch

from agent.llm_providers.base import LLMProviderError
from agent.llm_providers.gemini_provider import GeminiProvider
from agent.llm_providers.groq_provider import GroqProvider


class LLMProviderJsonTests(unittest.TestCase):
    def test_gemini_generic_json_accepts_fenced_object(self):
        with patch.dict(os.environ, {"GEMINI_API_KEY": "test-key"}, clear=False):
            provider = GeminiProvider()
        with patch.object(
            provider,
            "_post_json",
            return_value={
                "candidates": [
                    {"content": {"parts": [{"text": "```json\n{\"template_id\":\"http.request\"}\n```"}]}}
                ]
            },
        ):
            self.assertEqual(
                provider.generate_json("prompt"),
                {"template_id": "http.request"},
            )

    def test_groq_generic_json_accepts_object(self):
        with patch.dict(os.environ, {"GROQ_API_KEY": "test-key"}, clear=False):
            provider = GroqProvider()
        with patch.object(
            provider,
            "_post_json",
            return_value={"choices": [{"message": {"content": "{\"confidence\":0.8}"}}]},
        ):
            self.assertEqual(provider.generate_json("prompt"), {"confidence": 0.8})

    def test_invalid_provider_json_fails_closed(self):
        with patch.dict(os.environ, {"GROQ_API_KEY": "test-key"}, clear=False):
            provider = GroqProvider()
        with patch.object(
            provider,
            "_post_json",
            return_value={"choices": [{"message": {"content": "not json"}}]},
        ):
            with self.assertRaises(LLMProviderError):
                provider.generate_json("prompt")


if __name__ == "__main__":
    unittest.main()
