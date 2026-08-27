import asyncio
import json
import sys
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

from pydantic import ValidationError

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND_DIR = REPO_ROOT / "backend"

sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(BACKEND_DIR))

try:
    from fastapi.testclient import TestClient as FastAPITestClient  # noqa: E402

    TESTCLIENT_IMPORT_ERROR = None
except RuntimeError as exc:
    FastAPITestClient = None
    TESTCLIENT_IMPORT_ERROR = str(exc)

from app.main import app  # noqa: E402
from app.schemas.policy_decision import PolicyDecision  # noqa: E402
from app.schemas.policy_context import RuntimePolicyInput  # noqa: E402
from app.services import policy_runtime  # noqa: E402
from identity_test_helpers import runtime_context  # noqa: E402
from test_policy_decision import valid_decision_payload  # noqa: E402


class MinimalASGIResponse:
    def __init__(self, status_code: int, body: bytes) -> None:
        self.status_code = status_code
        self._body = body

    def json(self) -> Any:
        return json.loads(self._body.decode("utf-8"))


class MinimalASGITestClient:
    def __init__(self, asgi_app: Any) -> None:
        self.app = asgi_app

    def post(
        self,
        path: str,
        json: dict[str, Any],
        headers: dict[str, str] | None = None,
    ) -> MinimalASGIResponse:
        return asyncio.run(self._post(path, json, headers or {}))

    async def _post(
        self,
        path: str,
        payload: dict[str, Any],
        headers: dict[str, str],
    ) -> MinimalASGIResponse:
        body = json.dumps(payload).encode("utf-8")
        response_status = 500
        response_body = bytearray()
        request_sent = False

        scope = {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1",
            "method": "POST",
            "scheme": "http",
            "path": path,
            "raw_path": path.encode("ascii"),
            "query_string": b"",
            "headers": [
                (b"host", b"testserver"),
                (b"accept", b"application/json"),
                (b"content-type", b"application/json"),
            ]
            + [
                (key.lower().encode("ascii"), value.encode("ascii"))
                for key, value in headers.items()
            ],
            "client": ("testclient", 50000),
            "server": ("testserver", 80),
            "root_path": "",
        }

        async def receive() -> dict[str, Any]:
            nonlocal request_sent
            if request_sent:
                return {"type": "http.disconnect"}
            request_sent = True
            return {"type": "http.request", "body": body, "more_body": False}

        async def send(message: dict[str, Any]) -> None:
            nonlocal response_status
            if message["type"] == "http.response.start":
                response_status = message["status"]
            elif message["type"] == "http.response.body":
                response_body.extend(message.get("body", b""))

        await self.app(scope, receive, send)
        return MinimalASGIResponse(response_status, bytes(response_body))


TestClient = FastAPITestClient or MinimalASGITestClient
TRUSTED_IDENTITY_HEADERS = {"X-MCP-Identity-Assertion": "test.assertion.value"}


def trust_identity(context: dict[str, Any]) -> dict[str, Any]:
    return RuntimePolicyInput.model_validate(context).model_dump(mode="json")


def valid_context() -> dict:
    return runtime_context(
        subject={
            "identity_binding_revision": "test-bindings-v2",
            "session_reference": "session-demo",
            "authorization_revision": "test-authorization-v2",
            "role": "legal_agent",
            "authorization_status": "resolved",
            "grants": [
                {
                    "capability": "filesystem.read",
                    "scopes": ["fs.project_workspace"],
                }
            ],
            "allowed_capabilities": ["filesystem.read"],
            "allowed_scopes": ["fs.project_workspace"],
        },
    )


def read_file_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "path": {
                "type": "string",
                "minLength": 1,
                "maxLength": 4096,
            }
        },
        "required": ["path"],
        "additionalProperties": False,
    }


class RuntimePolicyInputTests(unittest.TestCase):
    def test_complete_structure_contains_expected_sections(self) -> None:
        model = RuntimePolicyInput.model_validate(valid_context())

        self.assertEqual(
            set(model.model_dump().keys()),
            {"subject", "server", "tool", "request", "runtime", "policy_settings"},
        )

    def test_tool_name_is_required(self) -> None:
        payload = valid_context()
        del payload["tool"]["name"]

        with self.assertRaises(ValidationError):
            RuntimePolicyInput.model_validate(payload)

    def test_invalid_description_score_is_rejected(self) -> None:
        payload = valid_context()
        payload["tool"]["description_risk_score"] = "high"

        with self.assertRaises(ValidationError):
            RuntimePolicyInput.model_validate(payload)

    def test_unknown_tool_field_is_rejected(self) -> None:
        payload = valid_context()
        payload["tool"]["untrusted_extra_field"] = "unexpected"

        with self.assertRaises(ValidationError):
            RuntimePolicyInput.model_validate(payload)

    def test_invalid_server_id_is_rejected(self) -> None:
        payload = valid_context()
        payload["server"]["id"] = 0

        with self.assertRaises(ValidationError):
            RuntimePolicyInput.model_validate(payload)

    def test_strict_booleans_are_not_coerced(self) -> None:
        payload = valid_context()
        payload["tool"]["capability_mismatch"] = "true"

        with self.assertRaises(ValidationError):
            RuntimePolicyInput.model_validate(payload)

        payload = valid_context()
        payload["request"]["arguments_valid"] = "false"

        with self.assertRaises(ValidationError):
            RuntimePolicyInput.model_validate(payload)

    def test_arguments_must_be_json_object(self) -> None:
        payload = valid_context()
        payload["request"]["arguments"] = ["not", "an", "object"]

        with self.assertRaises(ValidationError):
            RuntimePolicyInput.model_validate(payload)

    def test_arguments_valid_is_required(self) -> None:
        payload = valid_context()
        del payload["request"]["arguments_valid"]

        with self.assertRaises(ValidationError):
            RuntimePolicyInput.model_validate(payload)

    def test_valid_arguments_cannot_have_error_codes(self) -> None:
        payload = valid_context()
        payload["request"]["validation_error_codes"] = ["invalid_type:path"]

        with self.assertRaises(ValidationError):
            RuntimePolicyInput.model_validate(payload)

    def test_invalid_arguments_require_error_codes(self) -> None:
        payload = valid_context()
        payload["request"]["arguments_valid"] = False
        payload["request"]["canonical_resource"] = None

        with self.assertRaises(ValidationError):
            RuntimePolicyInput.model_validate(payload)

    def test_invalid_arguments_can_omit_v2_security_metadata(self) -> None:
        payload = valid_context()
        request = payload["request"]
        request["arguments_valid"] = False
        request["canonical_resource"] = None
        request["validation_error_codes"] = ["unexpected_argument:path"]
        request["canonical_arguments_hash"] = "invalid"
        for field in (
            "contract_hash",
            "tool_security_contract",
            "normalized_facts",
            "tool_observation_approval",
        ):
            request.pop(field, None)
        request["capability_catalog"] = []

        model = RuntimePolicyInput.model_validate(payload)

        self.assertFalse(model.request.arguments_valid)
        self.assertEqual(
            model.request.validation_error_codes,
            ["unexpected_argument:path"],
        )

    def test_invalid_arguments_cannot_have_canonical_resource(self) -> None:
        payload = valid_context()
        payload["request"]["arguments_valid"] = False
        payload["request"]["validation_error_codes"] = ["invalid_type:path"]

        with self.assertRaises(ValidationError):
            RuntimePolicyInput.model_validate(payload)

    def test_canonical_resource_is_allowed_for_valid_arguments(self) -> None:
        model = RuntimePolicyInput.model_validate(valid_context())

        self.assertEqual(
            model.request.canonical_resource,
            "contracts/contract1.txt",
        )

    def test_too_many_validation_error_codes_are_rejected(self) -> None:
        payload = valid_context()
        payload["request"]["arguments_valid"] = False
        payload["request"]["canonical_resource"] = None
        payload["request"]["validation_error_codes"] = [f"error_{index}" for index in range(21)]

        with self.assertRaises(ValidationError):
            RuntimePolicyInput.model_validate(payload)

    def test_too_long_validation_error_code_is_rejected(self) -> None:
        payload = valid_context()
        payload["request"]["arguments_valid"] = False
        payload["request"]["canonical_resource"] = None
        payload["request"]["validation_error_codes"] = ["x" * 129]

        with self.assertRaises(ValidationError):
            RuntimePolicyInput.model_validate(payload)

    def test_too_long_canonical_resource_is_rejected(self) -> None:
        payload = valid_context()
        payload["request"]["canonical_resource"] = "a" * 4097

        with self.assertRaises(ValidationError):
            RuntimePolicyInput.model_validate(payload)

    def test_valid_grant_is_accepted(self) -> None:
        model = RuntimePolicyInput.model_validate(valid_context())

        self.assertEqual(model.subject.grants[0].capability, "filesystem.read")
        self.assertEqual(model.subject.grants[0].scopes, ["fs.project_workspace"])

    def test_empty_capability_is_rejected(self) -> None:
        payload = valid_context()
        payload["subject"]["grants"][0]["capability"] = ""

        with self.assertRaises(ValidationError):
            RuntimePolicyInput.model_validate(payload)

    def test_empty_scope_is_rejected(self) -> None:
        payload = valid_context()
        payload["subject"]["grants"][0]["scopes"] = [""]

        with self.assertRaises(ValidationError):
            RuntimePolicyInput.model_validate(payload)

    def test_duplicate_scope_is_rejected(self) -> None:
        payload = valid_context()
        payload["subject"]["grants"][0]["scopes"] = ["contracts", "contracts"]

        with self.assertRaises(ValidationError):
            RuntimePolicyInput.model_validate(payload)

    def test_duplicate_grant_is_rejected(self) -> None:
        payload = valid_context()
        payload["subject"]["grants"].append(
            {
                "capability": "filesystem.read",
                "scopes": ["lab_root"],
            }
        )

        with self.assertRaises(ValidationError):
            RuntimePolicyInput.model_validate(payload)

    def test_unknown_grant_field_is_rejected(self) -> None:
        payload = valid_context()
        payload["subject"]["grants"][0]["unexpected"] = True

        with self.assertRaises(ValidationError):
            RuntimePolicyInput.model_validate(payload)

    def test_unknown_authorization_status_requires_empty_grants(self) -> None:
        payload = valid_context()
        payload["subject"]["authorization_status"] = "unknown"

        with self.assertRaises(ValidationError):
            RuntimePolicyInput.model_validate(payload)

    def test_resolved_authorization_requires_revision(self) -> None:
        payload = valid_context()
        payload["subject"]["authorization_revision"] = ""

        with self.assertRaises(ValidationError):
            RuntimePolicyInput.model_validate(payload)

    def test_resolved_subject_without_grants_is_valid(self) -> None:
        payload = valid_context()
        payload["subject"]["grants"] = []
        payload["subject"]["allowed_capabilities"] = []
        payload["subject"]["allowed_scopes"] = []

        RuntimePolicyInput.model_validate(payload)

    def test_required_capability_is_required(self) -> None:
        payload = valid_context()
        del payload["request"]["required_capability"]

        with self.assertRaises(ValidationError):
            RuntimePolicyInput.model_validate(payload)

    def test_empty_required_capability_is_rejected(self) -> None:
        payload = valid_context()
        payload["request"]["required_capability"] = ""

        with self.assertRaises(ValidationError):
            RuntimePolicyInput.model_validate(payload)

    def test_required_capability_values_are_valid(self) -> None:
        for capability in ("filesystem.read", "unclassified"):
            with self.subTest(capability=capability):
                payload = valid_context()
                payload["request"]["required_capability"] = capability
                RuntimePolicyInput.model_validate(payload)


class RuntimeDecisionHttpTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(app)

    def test_runtime_decision_returns_422_for_invalid_payload(self) -> None:
        payload = valid_context()
        del payload["tool"]["name"]

        response = self.client.post("/api/v1/runtime/decision", json=payload)

        self.assertEqual(response.status_code, 422)

    def test_runtime_decision_accepts_valid_payload(self) -> None:
        class FakeOPAClient:
            def evaluate(self, context: dict) -> PolicyDecision:
                payload = valid_decision_payload()
                payload["policy_revision"] = "opa-runtime-v1"
                return PolicyDecision.model_validate(payload)

        with patch.object(
            policy_runtime,
            "verify_trusted_identity_context",
            side_effect=lambda **kwargs: trust_identity(kwargs["context"]),
        ), patch.object(
            policy_runtime,
            "enrich_subject_authorization",
            side_effect=lambda context, *args, **kwargs: context,
        ), patch.object(policy_runtime, "OPAClient", return_value=FakeOPAClient()):
            response = self.client.post(
                "/api/v1/runtime/decision",
                json=valid_context(),
                headers=TRUSTED_IDENTITY_HEADERS,
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["decision"], "ALLOW")

    def test_runtime_decision_missing_assertion_fails_closed(self) -> None:
        response = self.client.post("/api/v1/runtime/decision", json=valid_context())

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["decision"], "BLOCK")
        self.assertEqual(response.json()["rule_id"], "trusted_identity_required")


if __name__ == "__main__":
    unittest.main()
