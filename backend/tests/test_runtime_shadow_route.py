import sys
import unittest
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND_DIR = REPO_ROOT / "backend"

sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(BACKEND_DIR))

from app.core.config import PolicyEngineMode, settings  # noqa: E402
from app.services import policy_runtime  # noqa: E402
from test_policy_context import TestClient, app, valid_context  # noqa: E402

TRUSTED_IDENTITY_HEADERS = {"X-MCP-Identity-Assertion": "test.assertion.value"}


def trusted_context(**kwargs) -> dict:
    return kwargs["context"]


class RuntimeShadowRouteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(app)
        self.original_mode = settings.policy_engine_mode

    def tearDown(self) -> None:
        settings.policy_engine_mode = self.original_mode

    def test_legacy_mode_does_not_call_shadow_evaluation(self) -> None:
        settings.policy_engine_mode = PolicyEngineMode.LEGACY

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
        shadow.assert_not_called()

    def test_shadow_mode_calls_background_shadow_evaluation(self) -> None:
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

    def test_dangerous_shadow_mismatch_does_not_change_yaml_response(self) -> None:
        settings.policy_engine_mode = PolicyEngineMode.SHADOW
        payload = valid_context()
        payload["request"]["arguments"] = {"path": ".env"}
        payload["request"]["canonical_resource"] = ".env"

        with patch.object(policy_runtime, "run_opa_shadow_evaluation") as shadow:
            with patch.object(
                policy_runtime,
                "verify_trusted_identity_context",
                side_effect=trusted_context,
            ):
                response = self.client.post(
                    "/api/v1/runtime/decision",
                    json=payload,
                    headers=TRUSTED_IDENTITY_HEADERS,
                )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["effect"], "DENY")
        self.assertEqual(response.json()["decision"], "BLOCK")
        shadow.assert_called_once()

    def test_shadow_task_does_not_change_yaml_response(self) -> None:
        settings.policy_engine_mode = PolicyEngineMode.SHADOW

        with patch.object(policy_runtime, "run_opa_shadow_evaluation"):
            with patch.object(
                policy_runtime,
                "verify_trusted_identity_context",
                side_effect=trusted_context,
            ):
                response = self.client.post(
                    "/api/v1/runtime/decision",
                    json=deepcopy(valid_context()),
                    headers=TRUSTED_IDENTITY_HEADERS,
                )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["decision"], "ALLOW")

    def test_contract_regression_remains_allow(self) -> None:
        settings.policy_engine_mode = PolicyEngineMode.SHADOW

        with patch.object(policy_runtime, "run_opa_shadow_evaluation"):
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
        self.assertEqual(response.json()["effect"], "ALLOW")
        self.assertEqual(response.json()["decision"], "ALLOW")

    def test_env_regression_remains_block(self) -> None:
        settings.policy_engine_mode = PolicyEngineMode.SHADOW
        payload = valid_context()
        payload["request"]["arguments"] = {"path": ".env"}
        payload["request"]["canonical_resource"] = ".env"

        with patch.object(policy_runtime, "run_opa_shadow_evaluation"):
            with patch.object(
                policy_runtime,
                "verify_trusted_identity_context",
                side_effect=trusted_context,
            ):
                response = self.client.post(
                    "/api/v1/runtime/decision",
                    json=payload,
                    headers=TRUSTED_IDENTITY_HEADERS,
                )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["effect"], "DENY")
        self.assertEqual(response.json()["decision"], "BLOCK")


if __name__ == "__main__":
    unittest.main()
