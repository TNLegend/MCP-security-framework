"""UX-19: Prowler execution, findings and coverage are separate facts (isolated in-memory DB)."""
from __future__ import annotations

import hashlib
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

SEVERITIES = ["critical"] * 4 + ["high"] * 14 + ["medium"] * 25 + ["low"] * 15  # 58


def sha(value):
    return hashlib.sha256(str(value).encode()).hexdigest()


@pytest.fixture
def harness():
    engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine, tables=[
        CloudEnvironment.__table__, CloudScan.__table__, CloudResource.__table__,
        CloudFinding.__table__, CloudEvidence.__table__, CloudScanEvent.__table__,
    ])
    db = Session(engine, expire_on_commit=False)
    app = FastAPI()
    app.include_router(router)
    actor = SimpleNamespace(user=SimpleNamespace(id="v" * 36, role="VIEWER", username="viewer"))
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[require_authenticated_user] = lambda: actor
    app.dependency_overrides[require_admin] = lambda: actor
    with TestClient(app) as client:
        yield client, db
    db.close()
    engine.dispose()


def seed_completed(db, name):
    scan = CloudScan(requested_by="qa-admin", kind="AWS_ADVANCED", status="COMPLETED", resource_count=31,
                     finding_count=58, unknown_checks=0, scanner_version="5.x")
    db.add(scan)
    db.flush()
    for index, severity in enumerate(SEVERITIES):
        db.add(CloudFinding(scan_id=scan.id, rule_id=f"rule_{index % 9}", fingerprint=sha((name, index)),
                            severity=severity, result="FAIL", title=f"Synthetic finding {index}",
                            description="synthetic"))
    db.add(CloudEvidence(scan_id=scan.id, rule_id="PROWLER_EXECUTION", outcome="PASS",
                         evidence_sha256=sha(name),
                         safe_summary={"scanner": "prowler", "version": "5.x",
                                       "execution_status": "COMPLETED", "records": 120}))
    db.commit()
    return scan


def test_two_completed_31_58_0_scans_report_scan_wide_severity(harness):
    client, db = harness
    first, second = seed_completed(db, "A"), seed_completed(db, "B")
    for scan in (first, second):
        body = client.get(f"/control-plane/cloud-security/scans/{scan.id}").json()
        summary = body["assessment_summary"]
        assert summary["execution"] == {"state": "COMPLETED", "source": "SCANNER_EXECUTION_EVIDENCE",
                                        "scanner": "prowler", "scanner_version": "5.x",
                                        "records_returned": 120, "error_code": None}
        assert summary["findings"]["total"] == 58
        assert summary["findings"]["by_severity"] == {"CRITICAL": 4, "HIGH": 14, "MEDIUM": 25, "LOW": 15}
        assert summary["findings"]["matches_scan_counter"] is True
        assert summary["coverage"]["available"] is True
        assert summary["coverage"]["resources_observed"] == 31
        assert summary["coverage"]["unresolved_observations"] == 0


def test_failed_scan_without_collection_is_coverage_unavailable_not_clean(harness):
    client, db = harness
    scan = CloudScan(requested_by="qa-admin", kind="AWS_ADVANCED", status="FAILED", error_code="PROWLER_EXECUTION_FAILED",
                     resource_count=0, finding_count=0, unknown_checks=0, scanner_version="5.x")
    db.add(scan)
    db.commit()
    summary = client.get(f"/control-plane/cloud-security/scans/{scan.id}").json()["assessment_summary"]
    assert summary["execution"]["state"] == "FAILED"
    assert summary["execution"]["source"] == "SCAN_STATUS"
    assert summary["execution"]["error_code"] == "PROWLER_EXECUTION_FAILED"
    assert summary["coverage"]["available"] is False
    assert summary["coverage"]["reason"] == "SCAN_FAILED_BEFORE_COLLECTION"
    assert summary["findings"]["total"] == 0


def test_partial_and_aborted_runs_keep_coverage_distinct_from_findings(harness):
    client, db = harness
    partial = CloudScan(requested_by="qa-admin", kind="AWS_ADVANCED", status="PARTIAL", resource_count=12,
                        finding_count=1, unknown_checks=3, scanner_version="5.x")
    running = CloudScan(requested_by="qa-admin", kind="AWS_ADVANCED", status="RUNNING", resource_count=0,
                        finding_count=0, unknown_checks=0, scanner_version="5.x")
    aborted = CloudScan(requested_by="qa-admin", kind="AWS_ADVANCED", status="INTERRUPTED", resource_count=5,
                        finding_count=0, unknown_checks=2, scanner_version="5.x")
    db.add_all([partial, running, aborted])
    db.flush()
    db.add(CloudFinding(scan_id=partial.id, rule_id="r", fingerprint=sha("p"), severity="high",
                        result="FAIL", title="t", description="d"))
    db.add(CloudEvidence(scan_id=partial.id, rule_id="PROWLER_READ_S3", outcome="UNKNOWN",
                         evidence_sha256=sha("s3"), safe_summary={"service": "s3"}))
    db.add(CloudScanEvent(scan_id=partial.id, event_type="SCANNER", message_code="PROWLER_UNASSESSED_IAM"))
    db.commit()
    p = client.get(f"/control-plane/cloud-security/scans/{partial.id}").json()["assessment_summary"]
    assert p["coverage"]["available"] is True
    assert (p["coverage"]["unresolved_observations"], p["coverage"]["unknown_service_reads"],
            p["coverage"]["unassessed_services"]) == (3, 1, 1)
    assert p["findings"]["by_severity"] == {"HIGH": 1}
    r = client.get(f"/control-plane/cloud-security/scans/{running.id}").json()["assessment_summary"]
    assert r["coverage"] == {**r["coverage"], "available": False, "reason": "SCAN_NOT_FINISHED"}
    a = client.get(f"/control-plane/cloud-security/scans/{aborted.id}").json()["assessment_summary"]
    # Aborted after collecting 5 resources: coverage is partial evidence, not unavailable.
    assert a["coverage"]["available"] is True and a["execution"]["state"] == "INTERRUPTED"
