import json
import socket
import sys
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND_DIR = REPO_ROOT / "backend"

sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(BACKEND_DIR))

from app.schemas.policy_decision import PolicyDecision  # noqa: E402
from app.services.opa_client import (  # noqa: E402
    MAX_OPA_RESPONSE_BYTES,
    OPAClient,
    OPAClientError,
)
from test_policy_context import valid_context  # noqa: E402
from test_policy_decision import valid_decision_payload  # noqa: E402


class FakeResponse:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        return None

    def read(self, size: int) -> bytes:
        return self.payload[:size]


def response_payload(payload) -> FakeResponse:
    return FakeResponse(json.dumps(payload).encode("utf-8"))


class OPAClientTests(unittest.TestCase):
    def client(self) -> OPAClient:
        return OPAClient(
            base_url="http://127.0.0.1:8181/",
            decision_path="v1/data/mcp/security/runtime/decision",
            timeout_seconds=2.0,
        )

    def test_request_uses_data_api_input_and_expected_headers(self) -> None:
        captured = {}

        def fake_urlopen(request, timeout):
            captured["request"] = request
            captured["timeout"] = timeout
            return response_payload({"result": valid_decision_payload()})

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            decision = self.client().evaluate(valid_context())

        request = captured["request"]
        headers = dict(request.header_items())
        body = json.loads(request.data.decode("utf-8"))

        self.assertIsInstance(decision, PolicyDecision)
        self.assertEqual(
            request.full_url,
            "http://127.0.0.1:8181/v1/data/mcp/security/runtime/decision",
        )
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(headers["Accept"], "application/json")
        self.assertEqual(headers["Content-type"], "application/json")
        self.assertEqual(body, {"input": valid_context()})
        self.assertEqual(captured["timeout"], 2.0)

    def test_valid_allow_returns_policy_decision(self) -> None:
        with patch(
            "urllib.request.urlopen",
            return_value=response_payload({"result": valid_decision_payload()}),
        ):
            decision = self.client().evaluate(valid_context())

        self.assertIsInstance(decision, PolicyDecision)
        self.assertEqual(decision.effect, "ALLOW")

    def test_valid_deny_returns_policy_decision(self) -> None:
        payload = valid_decision_payload()
        payload.update(
            {
                "effect": "DENY",
                "obligations": [
                    {"type": "LOG", "parameters": {}},
                    {"type": "ALERT", "parameters": {}},
                ],
                "rule_ids": ["deny_sensitive_paths"],
                "reason": "Access to sensitive path is forbidden.",
                "severity": "high",
                "decision": "BLOCK",
                "rule_id": "deny_sensitive_paths",
            }
        )

        with patch(
            "urllib.request.urlopen",
            return_value=response_payload({"result": payload}),
        ):
            decision = self.client().evaluate(valid_context())

        self.assertIsInstance(decision, PolicyDecision)
        self.assertEqual(decision.effect, "DENY")

    def assert_opa_error(self, response, expected_code: str) -> None:
        with patch("urllib.request.urlopen", side_effect=response):
            with self.assertRaises(OPAClientError) as exc:
                self.client().evaluate(valid_context())

        self.assertEqual(exc.exception.code, expected_code)

    def test_http_error_has_code(self) -> None:
        error = urllib.error.HTTPError(
            "http://127.0.0.1:8181",
            500,
            "Internal Server Error",
            hdrs=None,
            fp=None,
        )
        self.assert_opa_error(error, "opa_http_error")

    def test_connection_refused_has_code(self) -> None:
        self.assert_opa_error(
            urllib.error.URLError(ConnectionRefusedError("refused")),
            "opa_unavailable",
        )

    def test_timeout_has_code(self) -> None:
        self.assert_opa_error(
            urllib.error.URLError(socket.timeout("timed out")),
            "opa_timeout",
        )

    def test_invalid_json_has_code(self) -> None:
        with patch("urllib.request.urlopen", return_value=FakeResponse(b"{bad-json")):
            with self.assertRaises(OPAClientError) as exc:
                self.client().evaluate(valid_context())

        self.assertEqual(exc.exception.code, "opa_invalid_json")

    def test_root_non_object_has_code(self) -> None:
        self.assert_opa_response_error(["not", "object"], "opa_invalid_response")

    def test_missing_result_has_code(self) -> None:
        self.assert_opa_response_error({"decision": "missing"}, "opa_undefined_result")

    def test_non_object_result_has_code(self) -> None:
        self.assert_opa_response_error({"result": True}, "opa_invalid_result")

    def test_invalid_policy_decision_has_code(self) -> None:
        self.assert_opa_response_error(
            {"result": {"effect": "ALLOW"}},
            "opa_invalid_decision",
        )

    def test_response_too_large_has_code(self) -> None:
        payload = b"x" * (MAX_OPA_RESPONSE_BYTES + 1)

        with patch("urllib.request.urlopen", return_value=FakeResponse(payload)):
            with self.assertRaises(OPAClientError) as exc:
                self.client().evaluate(valid_context())

        self.assertEqual(exc.exception.code, "opa_response_too_large")

    def assert_opa_response_error(self, payload, expected_code: str) -> None:
        with patch("urllib.request.urlopen", return_value=response_payload(payload)):
            with self.assertRaises(OPAClientError) as exc:
                self.client().evaluate(valid_context())

        self.assertEqual(exc.exception.code, expected_code)


if __name__ == "__main__":
    unittest.main()
