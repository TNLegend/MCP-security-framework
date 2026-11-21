"""Operator diagnostics are readable and startup integrity still fails closed."""
from __future__ import annotations

import json
from types import SimpleNamespace

from scripts import start_framework as start


def test_startup_failure_guidance_is_actionable_and_safe():
    for code in start.STARTUP_GUIDANCE:
        payload = start.startup_failure(code)
        assert payload["ready"] is False
        assert payload["error"] == code
        assert len(payload["operator_guidance"]) >= 55
        assert "secret" not in payload
        assert "password" not in payload
        assert json.loads(json.dumps(payload)) == payload

    unknown = start.startup_failure("AN_UNRECOGNIZED_ERROR",
                                    details={"component": "isolated-test"})
    assert unknown["component"] == "isolated-test"
    assert "prerequisite" in unknown["operator_guidance"]


def test_incorrect_running_opa_policy_stays_fail_closed_with_repair_guidance(monkeypatch, capsys):
    events = []
    manager = SimpleNamespace(
        ensure_database=lambda **kwargs: SimpleNamespace(status="healthy"),
        ensure_opa=lambda **kwargs: SimpleNamespace(status="healthy"),
        shutdown=lambda: events.append("shutdown"),
    )
    monkeypatch.setattr(start, "configure_runtime_environment", lambda: None)
    monkeypatch.setattr(start, "LocalRuntimeManager", lambda **kwargs: manager)
    monkeypatch.setattr(start, "local_policy_sha256", lambda: None)
    monkeypatch.setattr(start, "_opa_dual_policy_ready", lambda url: True)
    monkeypatch.setattr(start, "_opa_remote_bundle_matches_manifest", lambda url: False)

    rc = start.main()
    assert rc == 1
    assert events == ["shutdown"]
    out = json.loads(capsys.readouterr().out)
    assert out["ready"] is False
    assert out["error"] == "opa_remote_policy_bundle_mismatch"
    assert "restart" in out["operator_guidance"]
    assert "never suppress" in out["operator_guidance"]

def test_child_failure_cannot_override_fail_closed_launcher_result(monkeypatch, capsys):
    events = []
    healthy = SimpleNamespace(status="healthy", as_dict=lambda: {"status": "healthy"})
    manager = SimpleNamespace(
        ensure_database=lambda **kwargs: healthy,
        ensure_opa=lambda **kwargs: healthy,
        ensure_identity_provider=lambda **kwargs: healthy,
        ensure_mcp_lab=lambda **kwargs: healthy,
        start_backend=lambda: healthy,
        ensure_gateway=lambda **kwargs: healthy,
        status=lambda: SimpleNamespace(ready=True,
                                       as_dict=lambda: {"ready": True}),
        required_child_failure=lambda: {
            "component": "gateway",
            "ready": True,
            "error": "untrusted_component_override",
        },
        recover_required_child=lambda _: False,
        shutdown=lambda: events.append("shutdown"),
    )
    monkeypatch.setattr(start, "configure_runtime_environment", lambda: None)
    monkeypatch.setattr(start, "LocalRuntimeManager", lambda **kwargs: manager)
    monkeypatch.setattr(start, "local_policy_sha256", lambda: None)
    monkeypatch.setattr(start, "_opa_dual_policy_ready", lambda url: True)
    monkeypatch.setattr(start, "_opa_remote_bundle_matches_manifest", lambda url: True)
    monkeypatch.setattr(start, "init_db", lambda: None)
    assert start.main() == 1
    failure = json.loads(capsys.readouterr().err)
    assert failure["ready"] is False
    assert failure["error"] == "framework_owned_child_exited"
    assert "Review" in failure["operator_guidance"]
    assert events == ["shutdown"]
