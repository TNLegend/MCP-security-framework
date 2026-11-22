"""UX-11: an older scan of a quiet environment stays reachable (isolated in-memory DB)."""
from __future__ import annotations

from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.api.routes_cloud_security import router
from app.db.database import Base, get_db
from app.models.cloud_security import (
    CloudEnvironment, CloudEvidence, CloudFinding, CloudResource, CloudScan, CloudScanEvent,
)
from app.services.control_plane_auth import require_admin, require_authenticated_user

BASE = "/control-plane/cloud-security/scans"


@pytest.fixture
def harness():
    engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine, tables=[
        CloudEnvironment.__table__, CloudScan.__table__, CloudResource.__table__,
        CloudFinding.__table__, CloudEvidence.__table__, CloudScanEvent.__table__,
    ])
    db = Session(engine, expire_on_commit=False)
    now = datetime(2026, 11, 21, 12, 0, 0)
    env_a = CloudEnvironment(name="Quiet A", regions=["eu-west-3"], services=["S3"], credential_mode="SDK_DEFAULT", created_by="qa")
    env_b = CloudEnvironment(name="Busy B", regions=["eu-west-3"], services=["S3"], credential_mode="SDK_DEFAULT", created_by="qa")
    db.add_all([env_a, env_b])
    db.flush()
    older = CloudScan(requested_by="qa", environment_id=env_a.id, kind="AWS_ADVANCED", status="COMPLETED",
                      created_at=now - timedelta(days=30), scanner_version="5.x")
    db.add(older)
    for index in range(100):
        db.add(CloudScan(requested_by="qa", environment_id=env_b.id, kind="AWS_ADVANCED", status="COMPLETED",
                         created_at=now - timedelta(minutes=index), scanner_version="5.x"))
    db.add(CloudScan(requested_by="qa", environment_id=None, kind="IAC_CONFIG", status="COMPLETED",
                     created_at=now - timedelta(days=60), scanner_version="iac"))
    db.commit()
    app = FastAPI()
    app.include_router(router)
    actor = SimpleNamespace(user=SimpleNamespace(id="v" * 36, role="VIEWER", username="viewer"))
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[require_authenticated_user] = lambda: actor
    app.dependency_overrides[require_admin] = lambda: actor
    with TestClient(app) as client:
        yield client, env_a.id, env_b.id, older.id
    db.close()
    engine.dispose()


def test_legacy_latest_100_hides_the_older_scan(harness):
    client, _, _, older = harness
    assert older not in {item["id"] for item in client.get(BASE).json()}


def test_environment_history_page_finds_the_older_scan(harness):
    client, env_a, env_b, older = harness
    page = client.get(f"{BASE}/page", params={"environment_id": env_a}).json()
    assert page["total"] == 1 and page["items"][0]["id"] == older
    with_iac = client.get(f"{BASE}/page", params={"environment_id": env_a, "include_unscoped_iac": True}).json()
    assert with_iac["total"] == 2
    busy = client.get(f"{BASE}/page", params={"environment_id": env_b, "limit": 100, "offset": 0}).json()
    assert busy["total"] == 100 and busy["has_more"] is False


def test_exact_scan_route_reopens_by_id_and_unknown_is_404(harness):
    client, _, _, older = harness
    assert client.get(f"{BASE}/{older}").json()["scan"]["id"] == older
    assert client.get(f"{BASE}/00000000-0000-4000-8000-000000000000").status_code == 404


def test_kind_and_date_filters_and_validation(harness):
    client, env_a, env_b, _ = harness
    assert client.get(f"{BASE}/page", params={"kind": "IAC_CONFIG"}).json()["total"] == 1
    recent = client.get(f"{BASE}/page", params={"environment_id": env_b,
                                                 "created_from": "2026-11-21T11:30:00"}).json()
    assert recent["total"] == 31
    assert client.get(f"{BASE}/page", params={"kind": "PROWLER"}).status_code == 422
