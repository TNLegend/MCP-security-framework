import asyncio
import json
import sys
import unittest
from copy import deepcopy
from pathlib import Path
from typing import Any

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
from app.schemas.policy_context import RuntimePolicyInput  # noqa: E402
from app.services.policy_engine import evaluate_policy  # noqa: E402
from proxy.mcp_proxy import MCPProxy  # noqa: E402
from proxy.tool_request_preparation import prepare_tool_request  # noqa: E402


class MinimalASGIResponse:
    def __init__(self, status_code: int, body: bytes) -> None:
        self.status_code = status_code
        self._body = body

    def json(self) -> Any:
        return json.loads(self._body.decode("utf-8"))


class MinimalASGITestClient:
    def __init__(self, asgi_app: Any) -> None:
        self.app = asgi_app

    def post(self, path: str, json: dict[str, Any]) -> MinimalASGIResponse:
        return asyncio.run(self._post(path, json))

    async def _post(self, path: str, payload: dict[str, Any]) -> MinimalASGIResponse:
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


def valid_context() -> dict:
    return {
        "subject": {
            "agent_id": "agent-demo",
            "role": "legal_agent",
            "authorization_status": "resolved",
            "authorization_revision": "test-authorization-v1",
            "grants": [
                {
                    "capability": "filesystem.read",
                    "scopes": ["contracts"],
                }
            ],
            "allowed_capabilities": ["filesystem.read"],
            "allowed_scopes": ["contracts"],
        },
        "server": {
            "id": 1,
            "endpoint": "http://127.0.0.1:9000/mcp",
            "trust_status": "trusted",
            "security_status": "pending_analysis",
        },
        "tool": {
            "id": 1,
            "name": "read_file",
            "risk_score": 40,
            "sensitivity": "medium",
            "capabilities": [],
            "admission_status": "unknown",
            "description_risk_score": 0.0,
            "capability_mismatch": False,
            "drift_status": "unknown",
        },
        "request": {
            "operation": "read",
            "resource_type": "file",
            "resource_scope": "contracts",
            "required_capability": "filesystem.read",
            "canonical_resource": "contracts/contract1.txt",
            "arguments": {"path": "contracts/contract1.txt"},
            "arguments_valid": True,
            "validation_error_codes": [],
            "estimated_output_size_mb": 0.001,
        },
        "runtime": {
            "environment": "local",
            "session_id": "session-demo",
        },
    }


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
            {"subject", "server", "tool", "request", "runtime"},
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

    def test_invalid_arguments_cannot_have_canonical_resource(self) -> None:
        payload = valid_context()
        payload["request"]["arguments_valid"] = False
        payload["request"]["validation_error_codes"] = ["invalid_type:path"]

        with self.assertRaises(ValidationError):
            RuntimePolicyInput.model_validate(payload)

    def test_canonical_resource_is_allowed_for_valid_arguments(self) -> None:
        model = RuntimePolicyInput.model_validate(valid_context())

        self.assertEqual(model.request.canonical_resource, "contracts/contract1.txt")

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
        self.assertEqual(model.subject.grants[0].scopes, ["contracts"])

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


class ProxyPolicyContextTests(unittest.TestCase):
    def test_proxy_builds_expected_structured_context(self) -> None:
        proxy = MCPProxy()
        tool_call = {
            "agent_id": "agent-demo",
            "agent_role": "legal_agent",
            "session_id": "session-001",
            "tool_name": "read_file",
            "arguments": {"path": "contracts/contract1.txt"},
        }
        server = {
            "id": 1,
            "endpoint": "http://127.0.0.1:9000/mcp",
            "trust_status": "trusted",
            "security_status": "pending_analysis",
        }
        tool = {
            "id": 2,
            "name": "read_file",
            "risk_score": 40,
            "sensitivity": "medium",
            "description_risk_score": 0,
            "input_schema": read_file_schema(),
        }

        prepared = prepare_tool_request(
            tool_name="read_file",
            raw_arguments=tool_call["arguments"],
            input_schema=tool["input_schema"],
        )
        prepared_tool_call = proxy._prepared_tool_call(tool_call, prepared)
        context = proxy._build_policy_context(prepared_tool_call, server, tool, prepared)
        validated = RuntimePolicyInput.model_validate(context)

        self.assertEqual(validated.subject.role, "unknown")
        self.assertEqual(validated.subject.authorization_status, "unknown")
        self.assertEqual(validated.subject.grants, [])
        self.assertEqual(validated.request.operation, "read")
        self.assertEqual(validated.request.resource_type, "file")
        self.assertEqual(validated.request.resource_scope, "contracts")
        self.assertEqual(validated.request.required_capability, "filesystem.read")
        self.assertEqual(validated.request.canonical_resource, "contracts/contract1.txt")
        self.assertEqual(validated.tool.admission_status, "unknown")

    def test_proxy_does_not_mask_invalid_capability_mismatch(self) -> None:
        proxy = MCPProxy()
        tool_call = {
            "agent_id": "agent-demo",
            "session_id": "session-001",
            "tool_name": "read_file",
            "arguments": {"path": "contracts/contract1.txt"},
        }
        server = {
            "id": 1,
            "endpoint": "http://127.0.0.1:9000/mcp",
            "trust_status": "trusted",
        }
        tool = {
            "id": 2,
            "name": "read_file",
            "risk_score": 40,
            "sensitivity": "medium",
            "capability_mismatch": "true",
            "input_schema": read_file_schema(),
        }

        prepared = prepare_tool_request(
            tool_name="read_file",
            raw_arguments=tool_call["arguments"],
            input_schema=tool["input_schema"],
        )
        prepared_tool_call = proxy._prepared_tool_call(tool_call, prepared)
        context = proxy._build_policy_context(prepared_tool_call, server, tool, prepared)

        self.assertEqual(context["tool"]["capability_mismatch"], "true")
        with self.assertRaises(ValidationError):
            RuntimePolicyInput.model_validate(context)

    def test_proxy_requires_agent_id_and_session_id_in_policy_context(self) -> None:
        proxy = MCPProxy()
        server = {
            "id": 1,
            "endpoint": "http://127.0.0.1:9000/mcp",
            "trust_status": "trusted",
        }
        tool = {
            "id": 2,
            "name": "read_file",
        }

        with self.assertRaises(KeyError):
            proxy._build_policy_context(
                {
                    "session_id": "session-001",
                    "tool_name": "read_file",
                    "arguments": {},
                },
                server,
                tool,
                prepare_tool_request(
                    tool_name="read_file",
                    raw_arguments={},
                    input_schema=read_file_schema(),
                ),
            )

        with self.assertRaises(KeyError):
            proxy._build_policy_context(
                {
                    "agent_id": "agent-demo",
                    "tool_name": "read_file",
                    "arguments": {},
                },
                server,
                tool,
                prepare_tool_request(
                    tool_name="read_file",
                    raw_arguments={},
                    input_schema=read_file_schema(),
                ),
            )

    def test_proxy_does_not_mask_invalid_scores(self) -> None:
        proxy = MCPProxy()
        tool_call = {
            "agent_id": "agent-demo",
            "session_id": "session-001",
            "tool_name": "read_file",
            "arguments": {"path": "contracts/contract1.txt"},
        }
        server = {
            "id": 1,
            "endpoint": "http://127.0.0.1:9000/mcp",
            "trust_status": "trusted",
        }
        tool = {
            "id": 2,
            "name": "read_file",
            "risk_score": "",
            "description_risk_score": "high",
            "input_schema": read_file_schema(),
        }

        prepared = prepare_tool_request(
            tool_name="read_file",
            raw_arguments=tool_call["arguments"],
            input_schema=tool["input_schema"],
        )
        prepared_tool_call = proxy._prepared_tool_call(tool_call, prepared)
        context = proxy._build_policy_context(prepared_tool_call, server, tool, prepared)

        self.assertEqual(context["tool"]["risk_score"], "")
        self.assertEqual(context["tool"]["description_risk_score"], "high")
        with self.assertRaises(ValidationError):
            RuntimePolicyInput.model_validate(context)


class PolicyEngineNestedContextTests(unittest.TestCase):
    def test_contract_read_still_allows(self) -> None:
        decision = evaluate_policy(valid_context())

        self.assertEqual(decision["decision"], "ALLOW")
        self.assertEqual(decision["rule_id"], "allow_contracts_read")

    def test_sensitive_path_still_blocks(self) -> None:
        payload = deepcopy(valid_context())
        payload["request"]["arguments"] = {"path": ".env"}
        payload["request"]["canonical_resource"] = ".env"

        decision = evaluate_policy(payload)

        self.assertEqual(decision["decision"], "BLOCK")
        self.assertEqual(decision["rule_id"], "deny_sensitive_paths")

    def test_invalid_arguments_block_before_lower_priority_rules(self) -> None:
        payload = deepcopy(valid_context())
        payload["request"]["arguments_valid"] = False
        payload["request"]["validation_error_codes"] = ["invalid_type:path"]
        payload["request"]["canonical_resource"] = None

        decision = evaluate_policy(payload)

        self.assertEqual(decision["decision"], "BLOCK")
        self.assertEqual(decision["rule_id"], "deny_invalid_arguments")

    def test_canonical_sensitive_path_overrides_raw_contract(self) -> None:
        payload = deepcopy(valid_context())
        payload["request"]["arguments"] = {"path": "contracts/contract1.txt"}
        payload["request"]["canonical_resource"] = ".env"

        decision = evaluate_policy(payload)

        self.assertEqual(decision["decision"], "BLOCK")
        self.assertEqual(decision["rule_id"], "deny_sensitive_paths")

    def test_canonical_contract_path_overrides_raw_sensitive_path(self) -> None:
        payload = deepcopy(valid_context())
        payload["request"]["arguments"] = {"path": ".env"}
        payload["request"]["canonical_resource"] = "contracts/contract1.txt"

        decision = evaluate_policy(payload)

        self.assertEqual(decision["decision"], "ALLOW")
        self.assertEqual(decision["rule_id"], "allow_contracts_read")


class RuntimeDecisionHttpTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(app)

    def test_runtime_decision_returns_422_for_invalid_payload(self) -> None:
        payload = valid_context()
        del payload["tool"]["name"]

        response = self.client.post("/api/v1/runtime/decision", json=payload)

        self.assertEqual(response.status_code, 422)

    def test_runtime_decision_accepts_valid_payload(self) -> None:
        response = self.client.post("/api/v1/runtime/decision", json=valid_context())

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["decision"], "ALLOW")


if __name__ == "__main__":
    unittest.main()
