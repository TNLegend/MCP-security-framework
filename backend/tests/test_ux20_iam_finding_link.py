"""UX-20: IAM findings link to the exact comparison that produced them (isolated in-memory DB).

Fixture shape mirrors the audited case: 32 persisted comparisons, 25 of them
outside the approved MCP mapping (each with its own finding, same title), plus
legacy findings that predate the durable link and must stay unlinked.
"""
from __future__ import annotations

from datetime import datetime
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

import app.models  # noqa: F401  (registers FK targets)
from app.api.routes_cloud_security import router
from app.db.database import Base, get_db
from app.models.cloud_security import (
    CloudEvidence, CloudFinding, CloudIAMComparison, CloudResource, CloudScan,
)
from app.schemas.cloud_security import FindingPublic
from app.services.control_plane_auth import require_admin, require_authenticated_user

BASE = "/control-plane/cloud-security/scans"
TITLE = "IAM identity-policy grant outside this MCP's approved mapping"


@pytest.fixture
def harness():
    engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine, tables=[
        CloudScan.__table__, CloudResource.__table__, CloudFinding.__table__,
        CloudEvidence.__table__, CloudIAMComparison.__table__,
    ])
    db = Session(engine, expire_on_commit=False)
    scan = CloudScan(requested_by="qa", environment_id=None, kind="IAM_MCP", status="PARTIAL",
                     created_at=datetime(2026, 11, 21, 12), scanner_version="iam-mcp")
    db.add(scan)
    db.flush()
    expected: dict[str, list[str]] = {}
    for index in range(32):
        outside = index < 25
        comparison = CloudIAMComparison(
            scan_id=scan.id, status="OUTSIDE_MCP_MAPPING" if outside else ("READY" if index < 29 else "UNKNOWN"),
            expected_actions=[], observed_actions=[f"s3:Action{index:02d}"],
            expected_resource_arn=f"arn:aws:s3:::bucket-{index:02d}",
            effective_permission_status="UNKNOWN",
        )
        db.add(comparison)
        db.flush()
        expected[comparison.id] = []
        db.add(CloudEvidence(scan_id=scan.id, rule_id=f"IAM_MCP_REVERSE_{index:02d}", outcome="FAIL",
                             evidence_sha256="0" * 64,
                             safe_summary={"comparison_id": comparison.id, "action": f"s3:Action{index:02d}"}))
        if outside:
            finding = CloudFinding(
                scan_id=scan.id, comparison_id=comparison.id, rule_id="IAM_MCP_OUTSIDE_APPROVED_MAPPING",
                fingerprint=f"{index:064d}", severity="MEDIUM", result="OUTSIDE_MCP_MAPPING",
                title=TITLE, description="identical text for every row",
            )
            db.add(finding)
            db.flush()
            expected[comparison.id].append(finding.id)
    # Legacy findings: same title and action text, but no durable link.
    for index in range(2):
        db.add(CloudFinding(
            scan_id=scan.id, comparison_id=None, rule_id="IAM_MCP_OUTSIDE_APPROVED_MAPPING",
            fingerprint=f"legacy{index:058d}", severity="MEDIUM", result="OUTSIDE_MCP_MAPPING",
            title=TITLE, description="s3:Action00 arn:aws:s3:::bucket-00",
        ))
    db.commit()
    app = FastAPI()
    app.include_router(router)
    actor = SimpleNamespace(user=SimpleNamespace(id="v" * 36, role="VIEWER", username="viewer"))
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[require_authenticated_user] = lambda: actor
    app.dependency_overrides[require_admin] = lambda: actor
    with TestClient(app) as client:
        yield client, db, scan.id, expected
    db.close()
    engine.dispose()


def test_every_outside_grant_has_its_own_exact_finding(harness):
    client, _, scan_id, expected = harness
    items = []
    offset = 0
    while True:
        page = client.get(f"{BASE}/{scan_id}/iam-comparisons/page", params={"offset": offset, "limit": 10}).json()
        items.extend(page["items"])
        offset += page["returned"]
        if not page["has_more"]:
            break
    assert page["total"] == 32 and len(items) == 32
    assert len({item["id"] for item in items}) == 32
    linked = {item["id"]: item["linked_finding_ids"] for item in items}
    assert linked == expected
    outside = [item for item in items if item["status"] == "OUTSIDE_MCP_MAPPING"]
    assert len(outside) == 25
    finding_ids = [fid for item in outside for fid in item["linked_finding_ids"]]
    # 25 individually selectable findings, no duplicates, no legacy rows.
    assert len(finding_ids) == 25 and len(set(finding_ids)) == 25


def test_legacy_findings_stay_unlinked_and_are_never_text_matched(harness):
    client, db, scan_id, expected = harness
    legacy = db.query(CloudFinding).filter(CloudFinding.comparison_id.is_(None)).all()
    assert len(legacy) == 2
    all_linked = {fid for ids in expected.values() for fid in ids}
    assert not ({row.id for row in legacy} & all_linked)
    legacy_rows = client.get(f"{BASE}/{scan_id}/iam-comparisons").json()
    assert not any(row.id in item["linked_finding_ids"] for item in legacy_rows for row in legacy)


def test_finding_public_exposes_comparison_id(harness):
    _, db, _, expected = harness
    some_comparison, ids = next((cid, fids) for cid, fids in expected.items() if fids)
    row = db.get(CloudFinding, ids[0])
    assert FindingPublic.model_validate(row).comparison_id == some_comparison
    legacy = db.query(CloudFinding).filter(CloudFinding.comparison_id.is_(None)).first()
    assert FindingPublic.model_validate(legacy).comparison_id is None
