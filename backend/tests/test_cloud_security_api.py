"""API contract tests with isolated in-memory DB; never touches AWS or production DB."""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db.database import get_db, Base
from app.api.routes_cloud_security import router
from app.services.control_plane_auth import require_admin, require_authenticated_user
from app.models.cloud_security import (
    CloudEnvironment, CloudScan, CloudResource, CloudEvidence, CloudFinding, CloudScanEvent
)
from fastapi import FastAPI

@pytest.fixture
def harness(monkeypatch):
    engine=create_engine("sqlite+pysqlite://",connect_args={"check_same_thread":False},
                         poolclass=StaticPool)
    Base.metadata.create_all(bind=engine,tables=[
        CloudEnvironment.__table__,CloudScan.__table__,CloudResource.__table__,
        CloudFinding.__table__,CloudEvidence.__table__,CloudScanEvent.__table__,
    ])
    db=Session(engine,expire_on_commit=False)
    app=FastAPI()
    app.include_router(router)
    actor=SimpleNamespace(user=SimpleNamespace(id="u"*36,role="ADMIN",username="test-admin"))
    app.dependency_overrides[get_db]=lambda:db
    app.dependency_overrides[require_admin]=lambda:actor
    app.dependency_overrides[require_authenticated_user]=lambda:actor
    import app.api.routes_cloud_security as routes
    monkeypatch.setattr(routes,"_audit",lambda *args,**kwargs:None)
    client=TestClient(app)
    yield client,db,monkeypatch,app
    client.close()
    db.close()
    engine.dispose()

def test_create_and_list_environment_with_no_secret_fields(harness):
    client,db,_,_=harness
    payload={"name":"AWS Lab","regions":["eu-west-3"],
             "credential_mode":"NAMED_PROFILE","profile_name":"lab-session"}
    response=client.post("/control-plane/cloud-security/environments",json=payload)
    assert response.status_code==201,response.text
    item=response.json()
    assert item["status"]=="UNVERIFIED"
    assert item["account_id"] is None
    assert "aws_secret_access_key" not in str(item)
    result=client.get("/control-plane/cloud-security/environments")
    assert result.status_code==200 and len(result.json())==1
    assert client.post("/control-plane/cloud-security/environments",json=payload).status_code==409

@pytest.mark.parametrize("payload",[
    {"name":"Lab","regions":["eu-west-3"],"credential_mode":"NAMED_PROFILE","profile_name":"../../unsafe"},
    {"name":"Lab","regions":["https://internal"]},
    {"name":"Lab","regions":["eu-west-3"],"aws_access_key_id":"not accepted"},
])
def test_api_validation_rejects_invalid_or_secret_fields(harness,payload):
    client,*_=harness
    assert client.post("/control-plane/cloud-security/environments",json=payload).status_code==422

def test_scan_requires_verified_connection(harness):
    client,db,_,_=harness
    resp=client.post("/control-plane/cloud-security/environments",
                     json={"name":"Lab","regions":["eu-west-3"]})
    assert resp.status_code==201
    scan=client.post("/control-plane/cloud-security/environments/"+resp.json()["id"]+"/scans")
    assert scan.status_code==409
    assert scan.json()["detail"]=="cloud_connection_not_verified"

def test_connection_test_persists_only_account_id(harness):
    client,db,monkeypatch,_=harness
    import app.api.routes_cloud_security as routes
    env=client.post("/control-plane/cloud-security/environments",
                    json={"name":"Lab","regions":["eu-west-3"]}).json()
    monkeypatch.setattr(routes,"check_connection",lambda e:(object(),"123456789012","assumed-role"))
    resp=client.post("/control-plane/cloud-security/environments/"+env["id"]+"/test")
    assert resp.status_code==200,resp.text
    assert resp.json()["account_id"]=="123456789012"
    assert db.get(CloudEnvironment,env["id"]).status=="CONNECTED"

def test_unknown_scan_returns_404(harness):
    client,*_=harness
    assert client.get("/control-plane/cloud-security/scans/missing").status_code==404

def test_viewer_cannot_create_or_test_or_scan(harness):
    client,db,_,app=harness
    from fastapi import HTTPException
    def reject_admin():
        raise HTTPException(status_code=403,detail="admin_required")
    app.dependency_overrides[require_admin]=reject_admin
    assert client.post("/control-plane/cloud-security/environments",json={
       "name":"Lab","regions":["eu-west-3"]}).status_code==403
    assert client.get("/control-plane/cloud-security/environments").status_code==200


def test_cross_account_onboarding_roundtrip_and_reverification(harness):
    client, db, monkeypatch, _ = harness
    import app.api.routes_cloud_security as routes

    payload = {
        "name": "External AWS account",
        "regions": ["eu-west-3"],
        "services": ["IAM", "S3"],
        "credential_mode": "SDK_DEFAULT",
        "role_arn": "arn:aws:iam::210987654321:role/McpAudit",
        "external_id": "mcp-customer-random-789",
        "expected_account_id": "210987654321",
    }
    created = client.post("/control-plane/cloud-security/environments", json=payload)
    assert created.status_code == 201, created.text
    env = created.json()
    assert env["external_id"] == payload["external_id"]
    assert env["expected_account_id"] == payload["expected_account_id"]
    assert env["status"] == "UNVERIFIED"

    # A different AWS account must never be silently accepted on first test.
    monkeypatch.setattr(routes, "check_connection",
                        lambda e: (_ for _ in ()).throw(
                            routes.CloudAuditError("AWS_ACCOUNT_CHANGED")))
    denied = client.post("/control-plane/cloud-security/environments/" + env["id"] + "/test")
    assert denied.status_code == 400
    assert denied.json()["detail"] == "AWS_ACCOUNT_CHANGED"
    assert db.get(CloudEnvironment, env["id"]).status == "FAILED"

    monkeypatch.setattr(routes, "check_connection",
                        lambda e: (object(), "210987654321", "assumed-role"))
    success = client.post("/control-plane/cloud-security/environments/" + env["id"] + "/test")
    assert success.status_code == 200
    assert success.json()["account_id"] == payload["expected_account_id"]

    # Legacy GUI clients omitting the new fields cannot silently drop the
    # trust condition or account pin when renaming the environment.
    legacy_change = {key: value for key, value in payload.items()
                     if key not in ("external_id", "expected_account_id")}
    legacy_change["name"] = "External AWS account renamed"
    renamed = client.patch("/control-plane/cloud-security/environments/" +
                           env["id"], json=legacy_change)
    assert renamed.status_code == 200, renamed.text
    assert renamed.json()["external_id"] == payload["external_id"]
    assert renamed.json()["expected_account_id"] == payload["expected_account_id"]
    assert renamed.json()["status"] == "CONNECTED"

    changed = client.patch("/control-plane/cloud-security/environments/" +
                           env["id"], json={**payload, "external_id": "mcp-rotated"})
    assert changed.status_code == 200
    assert changed.json()["status"] == "UNVERIFIED"
    assert changed.json()["account_id"] is None
    assert changed.json()["external_id"] == "mcp-rotated"


def test_cross_account_role_removal_clears_external_id(harness):
    client, _, _, _ = harness
    item = client.post("/control-plane/cloud-security/environments", json={
        "name": "Account with role", "regions": ["eu-west-3"],
        "role_arn": "arn:aws:iam::123456789012:role/Audit",
        "external_id": "mcp-unique-per-deployment",
    }).json()
    changed = client.patch("/control-plane/cloud-security/environments/" + item["id"],
                           json={"name": "Account without role", "regions": ["eu-west-3"]})
    assert changed.status_code == 200
    assert changed.json()["external_id"] is None
    assert changed.json()["role_arn"] is None


def test_start_scan_is_queued_once_and_deduplicated(harness):
    client, db, monkeypatch, _ = harness
    import app.api.routes_cloud_security as routes
    row=client.post("/control-plane/cloud-security/environments",
        json={"name":"Lab","regions":["eu-west-3"]}).json()
    monkeypatch.setattr(routes,"check_connection",lambda _: (object(),"123456789012","assumed-role"))
    assert client.post("/control-plane/cloud-security/environments/"+row["id"]+"/test").status_code==200
    queued=[]
    monkeypatch.setattr(routes,"enqueue_scan",lambda scan_id:queued.append(scan_id) or True)
    result=client.post("/control-plane/cloud-security/environments/"+row["id"]+"/scans")
    assert result.status_code==202,result.text
    assert result.json()["status"]=="QUEUED"
    assert queued==[result.json()["id"]]
    assert client.post("/control-plane/cloud-security/environments/"+row["id"]+"/scans").status_code==409
    detail=client.get("/control-plane/cloud-security/scans/"+queued[0])
    assert detail.status_code==200
    assert detail.json()["scan"]["id"]==queued[0]
    assert any(e["message_code"]=="QUEUED" for e in detail.json()["events"])


def test_update_profile_requires_reverification_and_preserves_history(harness):
    client, db, monkeypatch, _ = harness
    import app.api.routes_cloud_security as routes
    create = {"name":"Lab", "regions":["eu-west-3"],
              "credential_mode":"NAMED_PROFILE","profile_name":"old-profile",
              "services":["EC2","S3"]}
    env=client.post("/control-plane/cloud-security/environments",json=create).json()
    monkeypatch.setattr(routes,"check_connection",
                        lambda e: (object(),"123456789012","assumed-role"))
    assert client.post("/control-plane/cloud-security/environments/"+env["id"]+"/test").status_code==200
    with db.begin_nested():
        scan=CloudScan(environment_id=env["id"],kind="AWS_BASELINE",
                       status="COMPLETED",requested_by="u"*36)
        db.add(scan)
        db.flush()
        original_scan_id=scan.id
    change=dict(create,profile_name="new-temporary-profile")
    result=client.patch("/control-plane/cloud-security/environments/"+env["id"],json=change)
    assert result.status_code==200,result.text
    assert result.json()["status"]=="UNVERIFIED"
    assert result.json()["account_id"] is None
    assert result.json()["profile_name"]=="new-temporary-profile"
    assert db.get(CloudScan,original_scan_id) is not None
    assert client.post("/control-plane/cloud-security/environments/"+env["id"]+"/scans").status_code==409


def test_update_blocked_while_scan_active_and_for_viewer(harness):
    client, db, monkeypatch, app = harness
    data={"name":"Lab", "regions":["eu-west-3"]}
    env=client.post("/control-plane/cloud-security/environments",json=data).json()
    db.add(CloudScan(environment_id=env["id"],kind="AWS_BASELINE",
                     status="QUEUED",requested_by="u"*36))
    db.commit()
    response=client.patch("/control-plane/cloud-security/environments/"+env["id"],
                          json={**data,"regions":["eu-west-1"]})
    assert response.status_code==409
    from fastapi import HTTPException
    app.dependency_overrides[require_admin]=lambda: (_ for _ in ()).throw(HTTPException(status_code=403))
    assert client.patch("/control-plane/cloud-security/environments/"+env["id"],
                        json={**data,"regions":["eu-west-1"]}).status_code==403


def test_name_only_update_keeps_verified_connection(harness):
    client,db,monkeypatch,_=harness
    import app.api.routes_cloud_security as routes
    env=client.post("/control-plane/cloud-security/environments",
                    json={"name":"Lab","regions":["eu-west-3"]}).json()
    monkeypatch.setattr(routes,"check_connection",lambda e:(object(),"123456789012","assumed-role"))
    client.post("/control-plane/cloud-security/environments/"+env["id"]+"/test")
    changed=client.patch("/control-plane/cloud-security/environments/"+env["id"],
                         json={"name":"Lab renamed","regions":["eu-west-3"]})
    assert changed.status_code==200,changed.text
    assert changed.json()["status"]=="CONNECTED"
    assert changed.json()["account_id"]=="123456789012"
