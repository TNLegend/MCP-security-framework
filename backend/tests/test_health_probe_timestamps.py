"""Independent server-side check times do not masquerade as GUI receipt times."""
from datetime import datetime, timezone
from types import SimpleNamespace

from app.api import routes_health
from app.services.local_runtime_manager import (
    LocalRuntimeComponentStatus, LocalRuntimeStatus,
)


def test_each_service_observation_is_utc_timestamped():
    components = [
        LocalRuntimeComponentStatus(component=name, status="healthy")
        for name in ("backend", "database", "opa", "gateway")
    ]
    for item in components:
        encoded = item.as_dict()
        checked = datetime.fromisoformat(encoded["checked_at"])
        assert checked.tzinfo is not None
        assert abs((datetime.now(timezone.utc) - checked).total_seconds()) < 10
        assert encoded["component"] == item.component
    assert components[0].checked_at is not components[-1].checked_at


def test_local_runtime_health_returns_real_per_component_observation_time(monkeypatch):
    objects = {
        name: LocalRuntimeComponentStatus(component=name, status="healthy")
        for name in ("backend", "database", "opa", "gateway")
    }
    status = LocalRuntimeStatus(**objects)

    class FakeManager:
        def status(self, *, db, backend_current_process):
            assert backend_current_process is True
            return status
        def mcp_lab_status(self):
            return LocalRuntimeComponentStatus(component="mcp_lab", status="healthy")

    monkeypatch.setattr(routes_health, "LocalRuntimeManager", FakeManager)
    result = routes_health.local_runtime_status(None, object())
    assert result["ready"] is True
    for name in objects:
        assert result[name]["checked_at"] == objects[name].checked_at.isoformat()
        assert result[name]["status"] == "healthy"
        assert "managed_by_framework" not in result[name]
    assert "checked_at" in result["mcp_lab"]


def test_api_health_has_independent_server_check_time():
    result = routes_health.health_check()
    stamp = datetime.fromisoformat(result["checked_at"])
    assert stamp.tzinfo is not None
    assert result["status"] == "ok"
