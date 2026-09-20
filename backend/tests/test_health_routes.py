import json
from pathlib import Path
from types import SimpleNamespace
import sys
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient


ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend"
for path in (str(ROOT), str(BACKEND)):
    if path not in sys.path:
        sys.path.insert(0, path)

from app.api import routes_health  # noqa: E402
from app.main import app  # noqa: E402


class BrokenEngine:
    def connect(self):
        raise RuntimeError(
            "postgresql://admin:super-secret@db.internal.example:5432/mcp failed"
        )


class HealthRouteTests(unittest.TestCase):
    def test_db_check_does_not_expose_raw_database_exception(self) -> None:
        original_engine = routes_health.engine
        routes_health.engine = BrokenEngine()
        try:
            response = TestClient(app).get("/api/v1/db-check")
        finally:
            routes_health.engine = original_engine

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload, {"status": "error", "database": "not connected"})
        self.assertNotIn("super-secret", response.text)
        self.assertNotIn("db.internal.example", response.text)
        self.assertNotIn("postgresql://", response.text)



    def test_readiness_is_200_only_when_all_required_components_are_healthy(self) -> None:
        healthy = SimpleNamespace(status="healthy")
        runtime = SimpleNamespace(
            ready=True,
            backend=healthy,
            database=healthy,
            opa=healthy,
            gateway=healthy,
        )
        manager = SimpleNamespace(
            status=lambda **kwargs: runtime,
            identity_provider_status=lambda: healthy,
            mcp_lab_status=lambda: healthy,
        )
        with patch.object(routes_health, "LocalRuntimeManager", return_value=manager):
            response = routes_health.readiness_check(db=object())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(json.loads(response.body)["status"], "ready")

    def test_readiness_fails_closed_when_mcp_lab_is_unavailable(self) -> None:
        healthy = SimpleNamespace(status="healthy")
        unavailable = SimpleNamespace(status="unavailable")
        runtime = SimpleNamespace(
            ready=True,
            backend=healthy,
            database=healthy,
            opa=healthy,
            gateway=healthy,
        )
        manager = SimpleNamespace(
            status=lambda **kwargs: runtime,
            identity_provider_status=lambda: healthy,
            mcp_lab_status=lambda: unavailable,
        )
        with patch.object(routes_health, "LocalRuntimeManager", return_value=manager):
            response = routes_health.readiness_check(db=object())
        payload = json.loads(response.body)
        self.assertEqual(response.status_code, 503)
        self.assertEqual(payload["status"], "not_ready")
        self.assertEqual(payload["components"]["mcp_lab"], "unavailable")

    def test_readiness_fails_closed_when_dependency_is_unavailable(self) -> None:
        healthy = SimpleNamespace(status="healthy")
        unavailable = SimpleNamespace(status="unavailable")
        runtime = SimpleNamespace(
            ready=False,
            backend=healthy,
            database=healthy,
            opa=unavailable,
            gateway=healthy,
        )
        manager = SimpleNamespace(
            status=lambda **kwargs: runtime,
            identity_provider_status=lambda: healthy,
            mcp_lab_status=lambda: healthy,
        )
        with patch.object(routes_health, "LocalRuntimeManager", return_value=manager):
            response = routes_health.readiness_check(db=object())
        payload = json.loads(response.body)
        self.assertEqual(response.status_code, 503)
        self.assertEqual(payload["status"], "not_ready")
        self.assertEqual(payload["components"]["opa"], "unavailable")



if __name__ == "__main__":
    unittest.main()
