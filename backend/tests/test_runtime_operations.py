import os
import sys
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND_DIR = REPO_ROOT / "backend"
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(BACKEND_DIR))

from fastapi.testclient import TestClient  # noqa: E402
from app.core.config import settings  # noqa: E402
from app.db.database import Base, get_db  # noqa: E402
from app.main import app  # noqa: E402
from app.models.control_plane import ControlPlaneAuditEvent  # noqa: E402
from app.models.policy_decision import PolicyDecision  # noqa: E402
from app.models.runtime_call import RuntimeCall  # noqa: E402
from app.services.control_plane_auth import create_user  # noqa: E402
from app.services.runtime_operations import (  # noqa: E402
    cleanup_runtime_logs,
    maybe_auto_cleanup_runtime_logs,
    operations_summary,
)


class _HealthyComponent:
    def __init__(self, component):
        self.component = component

    def as_dict(self):
        return {
            "component": self.component,
            "status": "healthy",
            "endpoint": None,
            "managed_by_framework": False,
            "detail": None,
        }


class _HealthyRuntime:
    def as_dict(self, *, include_ownership=True):
        return {
            "ready": True,
            "backend": _HealthyComponent("backend").as_dict(),
            "database": _HealthyComponent("database").as_dict(),
            "opa": _HealthyComponent("opa").as_dict(),
            "gateway": _HealthyComponent("gateway").as_dict(),
        }


class _HealthyManager:
    def status(self, **kwargs):
        return _HealthyRuntime()

    def identity_provider_status(self):
        return _HealthyComponent("identity_provider")


class RuntimeOperationsTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)

        def override_get_db():
            db = self.Session()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = override_get_db
        self.client = TestClient(app)
        self.original = {
            "operations_metrics_window_minutes": settings.operations_metrics_window_minutes,
            "runtime_log_retention_days": settings.runtime_log_retention_days,
            "runtime_log_max_rows": settings.runtime_log_max_rows,
            "runtime_log_cleanup_batch_size": settings.runtime_log_cleanup_batch_size,
            "runtime_log_auto_cleanup_interval_rows": settings.runtime_log_auto_cleanup_interval_rows,
        }
        settings.operations_metrics_window_minutes = 15
        settings.runtime_log_retention_days = 30
        settings.runtime_log_max_rows = 3
        settings.runtime_log_cleanup_batch_size = 10
        settings.runtime_log_auto_cleanup_interval_rows = 1000

    def tearDown(self):
        app.dependency_overrides.clear()
        self.client.close()
        self.engine.dispose()
        for key, value in self.original.items():
            setattr(settings, key, value)

    def _add_call(
        self,
        db,
        *,
        created_at,
        decision="ALLOW",
        execution_status="success",
        executed=True,
        duration=10.0,
    ):
        db.add(
            RuntimeCall(
                agent_id="agent-demo",
                session_id="session-demo",
                server_id=None,
                tool_name="list_files",
                status="allowed" if decision == "ALLOW" else "blocked",
                decision=decision,
                executed=executed,
                execution_status=execution_status,
                total_duration_ms=duration,
                policy_duration_ms=duration / 5,
                upstream_duration_ms=duration / 2 if executed else None,
                result_guard_duration_ms=duration / 10 if executed else None,
                created_at=created_at,
            )
        )

    def _seed_recent(self):
        now = datetime.utcnow()
        with self.Session() as db:
            self._add_call(db, created_at=now - timedelta(minutes=1), duration=10)
            self._add_call(db, created_at=now - timedelta(minutes=2), duration=20)
            self._add_call(
                db,
                created_at=now - timedelta(minutes=3),
                decision="BLOCK",
                execution_status="blocked",
                executed=False,
                duration=30,
            )
            self._add_call(
                db,
                created_at=now - timedelta(minutes=4),
                decision="BLOCK",
                execution_status="result_blocked",
                executed=True,
                duration=40,
            )
            self._add_call(
                db,
                created_at=now - timedelta(minutes=5),
                decision="ALLOW",
                execution_status="http_error",
                executed=False,
                duration=50,
            )
            db.commit()

    def _login(self, role):
        username = f"{role.lower()}-operations"
        with self.Session() as db:
            create_user(db, username=username, password="Password123!", role=role)
            db.commit()
        response = self.client.post(
            "/api/v1/control-plane/auth/login",
            json={"username": username, "password": "Password123!"},
        )
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()["csrf_token"]

    def test_summary_reports_real_window_percentiles_and_health(self):
        self._seed_recent()
        with self.Session() as db, patch(
            "app.services.runtime_operations.LocalRuntimeManager",
            _HealthyManager,
        ):
            summary = operations_summary(db)

        self.assertTrue(summary.ready)
        self.assertEqual(summary.window.total_calls, 5)
        self.assertEqual(summary.window.allowed, 3)
        self.assertEqual(summary.window.blocked, 2)
        self.assertEqual(summary.window.errors, 1)
        self.assertEqual(summary.window.result_blocked, 1)
        self.assertEqual(summary.window.total_latency.samples, 5)
        self.assertEqual(summary.window.total_latency.p50_ms, 30.0)
        self.assertEqual(summary.window.total_latency.p95_ms, 48.0)
        self.assertEqual(summary.window.total_latency.p99_ms, 49.6)
        self.assertEqual(summary.runtime_storage.total_rows, 5)
        self.assertEqual(summary.runtime_storage.max_rows, 3)
        self.assertIn("identity_provider", summary.components)

    def test_authenticated_viewer_can_read_operations_summary(self):
        self._seed_recent()
        self._login("VIEWER")
        with patch("app.services.runtime_operations.LocalRuntimeManager", _HealthyManager):
            response = self.client.get("/api/v1/control-plane/operations/summary")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertIn("window", response.json())
        self.assertIn("database_pool", response.json())

    def test_viewer_cannot_run_retention_maintenance(self):
        csrf = self._login("VIEWER")
        response = self.client.post(
            "/api/v1/control-plane/operations/runtime-logs/cleanup",
            json={"dry_run": True, "reason": "Review retention state safely."},
            headers={"x-csrf-token": csrf},
        )
        self.assertEqual(response.status_code, 403, response.text)

    def test_retention_dry_run_then_apply_is_bounded_and_audited(self):
        now = datetime.utcnow()
        with self.Session() as db:
            for days in (90, 60, 20, 10, 5, 1):
                self._add_call(db, created_at=now - timedelta(days=days), duration=10)
            db.commit()

        with self.Session() as db:
            preview = cleanup_runtime_logs(db, dry_run=True)
            self.assertEqual(preview.total_before, 6)
            self.assertEqual(preview.eligible_expired, 2)
            self.assertEqual(preview.eligible_over_limit, 3)
            self.assertEqual(preview.planned, 3)
            self.assertEqual(preview.deleted, 0)
            self.assertEqual(
                db.scalar(select(func.count()).select_from(RuntimeCall)),
                6,
            )

        csrf = self._login("ADMIN")
        response = self.client.post(
            "/api/v1/control-plane/operations/runtime-logs/cleanup",
            json={"dry_run": False, "reason": "Apply bounded runtime retention policy."},
            headers={"x-csrf-token": csrf},
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["deleted"], 3)
        self.assertEqual(response.json()["total_after"], 3)
        with self.Session() as db:
            self.assertEqual(
                db.scalar(select(func.count()).select_from(RuntimeCall)),
                3,
            )
            event = db.scalar(
                select(ControlPlaneAuditEvent)
                .where(ControlPlaneAuditEvent.action == "RUNTIME_LOG_RETENTION_APPLIED")
                .order_by(ControlPlaneAuditEvent.timestamp.desc())
            )
            self.assertIsNotNone(event)
            self.assertEqual(event.result, "SUCCESS")
            self.assertEqual(event.after_json["deleted"], 3)



    def test_retention_preserves_runtime_calls_referenced_by_policy_decisions(self):
        now = datetime.utcnow()
        with self.Session() as db:
            self._add_call(db, created_at=now - timedelta(days=90), duration=10)
            db.flush()
            protected = db.scalar(select(RuntimeCall).order_by(RuntimeCall.id.desc()))
            db.add(
                PolicyDecision(
                    runtime_call_id=protected.id,
                    decision="ALLOW",
                    rule_id="protected-evidence",
                    reason="Referenced evidence must survive retention.",
                    severity="low",
                )
            )
            self._add_call(db, created_at=now - timedelta(days=60), duration=10)
            self._add_call(db, created_at=now - timedelta(days=5), duration=10)
            self._add_call(db, created_at=now - timedelta(days=1), duration=10)
            db.commit()
            protected_id = protected.id

        with self.Session() as db:
            result = cleanup_runtime_logs(db, dry_run=False)
            db.commit()
            self.assertEqual(result.deleted, 1)
            self.assertIsNotNone(db.get(RuntimeCall, protected_id))
            self.assertEqual(
                db.scalar(select(func.count()).select_from(PolicyDecision)),
                1,
            )

    def test_automatic_retention_is_interval_bounded_and_system_audited(self):
        settings.runtime_log_auto_cleanup_interval_rows = 1
        now = datetime.utcnow()
        with self.Session() as db:
            for days in (4, 3, 2, 1):
                self._add_call(db, created_at=now - timedelta(days=days), duration=10)
            db.commit()
            newest_id = db.scalar(select(func.max(RuntimeCall.id)))
            self.assertEqual(
                db.scalar(select(func.count()).select_from(RuntimeCall)),
                4,
            )

            result = maybe_auto_cleanup_runtime_logs(
                db,
                runtime_log_id=newest_id,
            )
            db.commit()

            self.assertIsNotNone(result)
            self.assertEqual(result.deleted, 1)
            self.assertEqual(
                db.scalar(select(func.count()).select_from(RuntimeCall)),
                3,
            )
            event = db.scalar(
                select(ControlPlaneAuditEvent)
                .where(
                    ControlPlaneAuditEvent.action
                    == "RUNTIME_LOG_RETENTION_AUTO_APPLIED"
                )
                .order_by(ControlPlaneAuditEvent.timestamp.desc())
            )
            self.assertIsNotNone(event)
            self.assertEqual(event.actor_username_snapshot, "system")
            self.assertEqual(event.actor_role_snapshot, "SYSTEM")
            self.assertEqual(event.after_json["deleted"], 1)

    def test_automatic_retention_skips_non_interval_runtime_call(self):
        settings.runtime_log_auto_cleanup_interval_rows = 100
        with self.Session() as db:
            self.assertIsNone(
                maybe_auto_cleanup_runtime_logs(
                    db,
                    runtime_log_id=99,
                )
            )
            self.assertEqual(
                db.scalar(
                    select(func.count())
                    .select_from(ControlPlaneAuditEvent)
                    .where(
                        ControlPlaneAuditEvent.action
                        == "RUNTIME_LOG_RETENTION_AUTO_APPLIED"
                    )
                ),
                0,
            )



if __name__ == "__main__":
    unittest.main()
