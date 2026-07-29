import sys
import unittest
from pathlib import Path
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND_DIR = REPO_ROOT / "backend"

sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(BACKEND_DIR))

from app.core.config import PolicyEngineMode, settings  # noqa: E402
from app.schemas.policy_decision import PolicyDecision  # noqa: E402
from app.services import policy_runtime  # noqa: E402
from app.services.opa_client import OPAClientError  # noqa: E402
from test_policy_context import TestClient, app, valid_context  # noqa: E402
from test_policy_decision import valid_decision_payload  # noqa: E402

TRUSTED_IDENTITY_HEADERS = {"X-MCP-Identity-Assertion": "test.assertion.value"}


def trusted_context(**kwargs) -> dict:
    return kwargs["context"]


def opa_decision() -> PolicyDecision:
    payload = valid_decision_payload()
    payload["policy_revision"] = "opa-runtime-v1"
    return PolicyDecision.model_validate(payload)


class FakeOPAClient:
    def __init__(self, error=None) -> None:
        self.error = error

    def evaluate(self, context: dict) -> PolicyDecision:
        if self.error is not None:
            raise self.error
        return opa_decision()


class RuntimePolicyModesRouteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(app)
        self.original_mode = settings.policy_engine_mode

    def tearDown(self) -> None:
        settings.policy_engine_mode = self.original_mode

    def test_legacy_mode_route_returns_yaml_without_opa(self) -> None:
        settings.policy_engine_mode = PolicyEngineMode.LEGACY

        with patch.object(policy_runtime, "OPAClient") as opa:
            with patch.object(
                policy_runtime,
                "verify_trusted_identity_context",
                side_effect=trusted_context,
            ):
                response = self.client.post(
                    "/api/v1/runtime/decision",
                    json=valid_context(),
                    headers=TRUSTED_IDENTITY_HEADERS,
                )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["decision"], "ALLOW")
        opa.assert_not_called()

    def test_shadow_mode_route_returns_yaml_and_adds_shadow(self) -> None:
        settings.policy_engine_mode = PolicyEngineMode.SHADOW

        with patch.object(policy_runtime, "run_opa_shadow_evaluation") as shadow:
            with patch.object(
                policy_runtime,
                "verify_trusted_identity_context",
                side_effect=trusted_context,
            ):
                response = self.client.post(
                    "/api/v1/runtime/decision",
                    json=valid_context(),
                    headers=TRUSTED_IDENTITY_HEADERS,
                )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["decision"], "ALLOW")
        shadow.assert_called_once()

    def test_opa_mode_route_returns_opa_without_yaml(self) -> None:
        settings.policy_engine_mode = PolicyEngineMode.OPA

        with patch.object(policy_runtime, "evaluate_policy") as yaml, patch.object(
            policy_runtime,
            "OPAClient",
            return_value=FakeOPAClient(),
        ):
            with patch.object(
                policy_runtime,
                "verify_trusted_identity_context",
                side_effect=trusted_context,
            ):
                response = self.client.post(
                    "/api/v1/runtime/decision",
                    json=valid_context(),
                    headers=TRUSTED_IDENTITY_HEADERS,
                )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["policy_revision"], "opa-runtime-v1")
        yaml.assert_not_called()

    def test_opa_unavailable_route_fails_closed_without_http_500(self) -> None:
        settings.policy_engine_mode = PolicyEngineMode.OPA

        with patch.object(policy_runtime, "evaluate_policy") as yaml, patch.object(
            policy_runtime,
            "OPAClient",
            return_value=FakeOPAClient(
                error=OPAClientError("opa_unavailable", "OPA unavailable.")
            ),
        ):
            with patch.object(
                policy_runtime,
                "verify_trusted_identity_context",
                side_effect=trusted_context,
            ):
                response = self.client.post(
                    "/api/v1/runtime/decision",
                    json=valid_context(),
                    headers=TRUSTED_IDENTITY_HEADERS,
                )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["effect"], "DENY")
        self.assertEqual(payload["decision"], "BLOCK")
        self.assertEqual(payload["rule_id"], "opa_unavailable")
        yaml.assert_not_called()

    def test_invalid_input_still_returns_422(self) -> None:
        payload = valid_context()
        del payload["tool"]["name"]

        response = self.client.post("/api/v1/runtime/decision", json=payload)

        self.assertEqual(response.status_code, 422)


if __name__ == "__main__":
    unittest.main()
