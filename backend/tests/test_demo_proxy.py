from __future__ import annotations

from pathlib import Path

import pytest

from proxy.demo_proxy import (
    DEMO_IDENTITY_SUBJECT,
    DEMO_MCP_ENDPOINT,
    _demo_cases,
    _demo_server_id,
)


class _BackendClient:
    def __init__(self, server):
        self.server = server

    def find_server(self, *, endpoint=None):
        assert endpoint == DEMO_MCP_ENDPOINT
        return self.server


class _Proxy:
    def __init__(self, server):
        self.backend_client = _BackendClient(server)


def test_demo_uses_current_default_identity_and_registered_server_id() -> None:
    assert DEMO_IDENTITY_SUBJECT == "service-account-llm-agent-demo"

    server_id = _demo_server_id(_Proxy({"id": 7}))
    cases = _demo_cases(server_id=server_id, session_token="session-token")

    assert [label for label, _ in cases] == [
        "Case 1 - allowed contract read",
        "Case 2 - blocked .env read",
        "Case 3 - allowed contract listing",
    ]
    assert all(payload["server_id"] == 7 for _, payload in cases)
    assert all(payload["session_token"] == "session-token" for _, payload in cases)
    assert [payload["tool_name"] for _, payload in cases] == [
        "read_file",
        "read_file",
        "list_files",
    ]


@pytest.mark.parametrize("server", [None, {}, {"id": True}, {"id": "1"}])
def test_demo_fails_cleanly_when_lab_inventory_record_is_missing(server) -> None:
    with pytest.raises(RuntimeError, match="not registered"):
        _demo_server_id(_Proxy(server))


def test_demo_runtime_log_guidance_uses_authenticated_control_center() -> None:
    source = (Path(__file__).resolve().parents[2] / "proxy" / "demo_proxy.py").read_text(
        encoding="utf-8"
    )

    assert "http://127.0.0.1:5173/ -> Runtime Calls" in source
    assert "Invoke-RestMethod http://127.0.0.1:8000/api/v1/runtime/logs" not in source
