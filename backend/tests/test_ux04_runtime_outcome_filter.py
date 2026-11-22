"""UX-04: Home outcome counts land on exactly the rows they counted (isolated in-memory DB)."""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.api.routes_runtime import router
from app.db.database import Base, get_db
from app.models.mcp_server import MCPServer
from app.models.runtime_call import RuntimeCall
from app.services.control_plane_auth import require_authenticated_user


def _row(**extra):
    base = dict(agent_id="qa-agent", session_id="qa-session", tool_name="read_documents",
                status="completed", executed=False)
    return RuntimeCall(**{**base, **extra})


@pytest.fixture
def client():
    engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine, tables=[MCPServer.__table__, RuntimeCall.__table__])
    db = Session(engine, expire_on_commit=False)
    db.add_all([
        # OPA ALLOW, sent, outcome unknown: a policy allow AND an uncertain outcome.
        _row(decision="ALLOW", execution_status="upstream_outcome_unknown", dispatch_state="SENT_OUTCOME_UNKNOWN"),
        _row(decision="ALLOW", executed=True, execution_status="success", dispatch_state="SENT_CONFIRMED"),
        _row(decision="BLOCK", execution_status="skipped", dispatch_state="NOT_SENT"),
        # A pending intent is never an outcome, even when its bucket would match.
        _row(decision="ALLOW", execution_status="authorized_pending_execution"),
    ])
    db.commit()
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[require_authenticated_user] = lambda: SimpleNamespace(
        user=SimpleNamespace(id="v" * 36, role="VIEWER", username="viewer"))
    with TestClient(app) as test_client:
        yield test_client
    db.close()
    engine.dispose()


def test_allow_with_uncertain_dispatch_counts_in_both_and_not_as_execution(client):
    summary = client.get("/runtime/logs").json()["summary"]
    assert summary["total"] == 3  # the intent is excluded
    assert summary["allowed"] == 2
    assert summary["outcome_states"]["sent_uncertain"] == 1
    assert summary["outcome_states"]["execution_recorded"] == 1


def test_outcome_state_filter_returns_exactly_the_counted_rows(client):
    page = client.get("/runtime/logs", params={"outcome_state": "sent_uncertain"}).json()
    assert len(page["items"]) == page["summary"]["total"] == 1
    assert page["items"][0]["execution_status"] == "upstream_outcome_unknown"
    legacy = client.get("/runtime/logs", params={"outcome_state": "legacy_or_unclassified"}).json()
    assert all(item["execution_status"] != "authorized_pending_execution" for item in legacy["items"])


def test_unknown_outcome_state_is_rejected(client):
    response = client.get("/runtime/logs", params={"outcome_state": "executed"})
    assert response.status_code == 422
