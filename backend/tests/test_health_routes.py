from pathlib import Path
import sys
import unittest

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


if __name__ == "__main__":
    unittest.main()
