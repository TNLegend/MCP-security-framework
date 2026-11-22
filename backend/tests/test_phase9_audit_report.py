"""Phase 9 integrated HTTP/SQLite report tests. No production DB/cloud or model calls."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.database import Base, get_db
from app.main import app
from app.models.build_security import BuildFinding, BuildScanRun, BuildScannerRun
from app.models.cloud_security import CloudFinding, CloudIAMComparison, CloudScan
from app.models.control_plane import (
    ControlPlaneAuditEvent, ControlPlaneConfigRevision, EmergencyDeny,
)
from app.models.mcp_server import MCPServer
from app.models.mcp_tool import MCPTool
from app.models.runtime_call import RuntimeCall
from app.models.tool_analysis import ToolAnalysis, ToolAnalysisFinding, ToolObservedVersion
from app.services.audit_reports import collect_report, render_report, MAX_EVIDENCE_PER_SECTION
from app.services.control_plane_auth import create_user

URI = "/api/v1/control-plane/audit/reports/generate"
CANARY = "NEVER_EXPORT_CREDENTIAL_7739_PRIVATE"


@pytest.fixture
def qa_db():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)

    def override_db():
        with Session() as session:
            yield session

    original = app.dependency_overrides.get(get_db)
    app.dependency_overrides[get_db] = override_db
    try:
        yield Session
    finally:
        if original is None:
            app.dependency_overrides.pop(get_db, None)
        else:
            app.dependency_overrides[get_db] = original
        engine.dispose()


def seed(qa_db):
    with qa_db.begin() as db:
        srv = MCPServer(
            name=CANARY, server_type="streamable_http",
            endpoint="https://" + CANARY + ".invalid/mcp",
            trust_status="trusted",
        )
        db.add(srv)
        db.flush()
        tool = MCPTool(
            server_id=srv.id,
            name="read_" + CANARY,
            description="Here is an inline password: " + CANARY,
            analysis_status="APPROVED", review_status="APPROVED", risk_level="low",
        )
        db.add(tool)
        db.flush()
        version = ToolObservedVersion(
            tool_id=tool.id, server_ref="qa-identity", tool_name=tool.name,
            fingerprint="a" * 64, snapshot={"description": CANARY},
        )
        db.add(version)
        db.flush()
        analysis = ToolAnalysis(
            tool_id=tool.id, version_id=version.id, fingerprint="a" * 64,
            analysis_status="APPROVED", analyzer_revision="qa-revision",
            created_at=datetime.utcnow() - timedelta(days=1),
        )
        db.add(analysis)
        db.flush()
        db.add(ToolAnalysisFinding(
            analysis_id=analysis.id, code="credential_request", category="test",
            source="M3", severity="HIGH", confidence=95,
            evidence={"secret": CANARY},
            recommendation="Export " + CANARY,
            created_at=datetime.utcnow() - timedelta(days=1),
        ))
        db.add(RuntimeCall(
            agent_id=CANARY, session_id=CANARY, tool_name=CANARY,
            arguments_summary={"token": CANARY},
            status="BLOCKED", decision="BLOCK", executed=False,
            dispatch_state="NOT_SENT", created_at=datetime.utcnow() - timedelta(days=1),
        ))
        db.add(RuntimeCall(
            agent_id="old", session_id="old", tool_name="old",
            status="BLOCKED", decision="BLOCK", executed=False,
            dispatch_state="NOT_SENT", created_at=datetime.utcnow() - timedelta(days=120),
        ))
        run = BuildScanRun(
            target_type="LOCAL", display_name=CANARY,
            source_locator="C:/secret/" + CANARY,
            status="COMPLETED", created_at=datetime.utcnow() - timedelta(days=1),
        )
        db.add(run)
        db.flush()
        scanner = BuildScannerRun(
            build_scan_id=run.id, scanner_id="gitleaks", status="COMPLETED",
            finding_count=1,
        )
        db.add(scanner)
        db.flush()
        db.add(BuildFinding(
            build_scan_id=run.id, scanner_run_id=scanner.id, scanner_id="gitleaks",
            rule_id="AWS_KEY_DEMO", category="SECRET", severity="HIGH",
            confidence="HIGH", fingerprint="b" * 64,
            title=CANARY, description="Do not export " + CANARY,
            file_path="C:/private/" + CANARY,
            created_at=datetime.utcnow() - timedelta(days=1),
        ))
        scan = CloudScan(
            requested_by="qa", kind="IAC_CONFIG",
            status="COMPLETED", created_at=datetime.utcnow() - timedelta(days=1),
        )
        db.add(scan)
        db.flush()
        db.add(CloudFinding(
            scan_id=scan.id, rule_id="CLOUD_TEST_R1", fingerprint="c" * 64,
            severity="CRITICAL", result="FAILED",
            title=CANARY, description=CANARY,
        ))
        db.add(CloudIAMComparison(
            scan_id=scan.id, status="POTENTIAL_EXCESS",
            role_arn="arn:aws:iam::000000000000:role/" + CANARY,
        ))
        db.add(ControlPlaneAuditEvent(
            action="TEST_RECORD", result="SUCCESS",
            reason=CANARY, before_json={"password": CANARY},
            event_metadata={"x": CANARY},
            timestamp=datetime.utcnow() - timedelta(days=1),
        ))
        db.add(ControlPlaneConfigRevision(
            revision_number=1, status="PUBLISHED", schema_version=1,
            content={"secrets": CANARY}, content_hash="d" * 64,
            published_at=datetime.utcnow() - timedelta(days=2),
        ))
        db.add(EmergencyDeny(
            target_type="server", reason=CANARY, created_by="qa",
            expires_at=datetime.utcnow() + timedelta(hours=2),
        ))


def test_snapshot_counts_time_filter_and_excludes_raw_private_data(qa_db):
    seed(qa_db)
    with qa_db() as db:
        report = collect_report(db, period="7d")
    assert report["inventory"]["servers"] == 1
    assert report["inventory"]["tools"] == 1
    assert report["tool_security"]["findings"] == 1
    assert report["tool_security"]["severity"]["HIGH"] == 1
    assert report["runtime"]["events"] == 1
    assert report["runtime"]["outcomes"]["CONFIRMED_NOT_SENT"] == 1
    assert report["build_security"]["findings"] == 1
    assert report["cloud_security"]["findings"] == 1
    assert report["cloud_security"]["iam_comparisons"]["POTENTIAL_EXCESS"] == 1
    assert report["governance"]["active_emergency_restrictions"] == 1
    assert report["governance"]["published_revision_number"] == 1
    assert "phase8_reference" not in report
    serialized = json.dumps(report)
    assert CANARY not in serialized
    assert "source_locator" not in serialized
    assert "arguments_summary" not in serialized
    assert len(report["evidence"]["runtime"]) == 1
    with qa_db() as db:
        all_records = collect_report(db, period="all", include_evidence=False)
    assert all_records["runtime"]["events"] == 2
    assert all_records["evidence"] == {}


@pytest.mark.parametrize("format_name,prefix", [
    ("pdf", b"%PDF-1.4"),
    ("html", b"<!doctype html>"),
    ("json", b"{"),
    ("csv", b"\xef\xbb\xbf"),
])
def test_all_formats_render_without_raw_secrets(qa_db, format_name, prefix):
    seed(qa_db)
    with qa_db() as db:
        report = collect_report(db, period="30d", include_evidence=True)
    data, media, filename = render_report(report, format_name)
    assert data.startswith(prefix)
    assert len(data) > 100
    assert filename.endswith("." + format_name)
    assert CANARY.encode() not in data
    assert b"phase8" not in data.lower()
    assert b"phase 8" not in data.lower()
    assert "secret" not in filename
    if format_name == "pdf":
        assert b"/Type /Page" in data
        assert b"startxref" in data
        assert b"Executive summary" in data


def test_empty_database_must_not_claim_no_risk(qa_db):
    with qa_db() as db:
        report = collect_report(db, period="30d")
    assert report["inventory"]["servers"] == 0
    assert report["cloud_security"]["scans"] == 0
    assert report["build_security"]["scans"] == 0
    assert report["runtime"]["events"] == 0
    assert "not proof of safety" in " ".join(report["limitations"])
    for format_name in ("pdf", "html", "json", "csv"):
        data, _, _ = render_report(report, format_name)
        assert len(data) > 60


def test_evidence_sample_bounded_but_aggregate_count_complete(qa_db):
    with qa_db.begin() as db:
        for i in range(MAX_EVIDENCE_PER_SECTION + 8):
            db.add(ControlPlaneAuditEvent(
                action="QA_ACTION", result="SUCCESS", timestamp=datetime.utcnow(),
                reason=CANARY,
            ))
    with qa_db() as db:
        report = collect_report(db, period="7d")
    assert report["audit"]["events"] == MAX_EVIDENCE_PER_SECTION + 8
    assert len(report["evidence"]["audit"]) == MAX_EVIDENCE_PER_SECTION


def test_endpoint_requires_session_and_admin_and_csrf_and_logs_hash(qa_db):
    with qa_db.begin() as db:
        create_user(db, username="report-qa-admin", password="qa-a-very-long-password-481",
                    role="ADMIN")
        create_user(db, username="report-qa-viewer", password="qa-v-very-long-password-481",
                    role="VIEWER")

    with TestClient(app, raise_server_exceptions=True) as client:
        unauth = client.post(URI, json={"period": "30d", "format": "pdf"})
        assert unauth.status_code == 401
        viewer_login = client.post(
            "/api/v1/control-plane/auth/login",
            json={"username": "report-qa-viewer", "password": "qa-v-very-long-password-481"},
        )
        assert viewer_login.status_code == 200
        csrf = viewer_login.json()["csrf_token"]
        denied = client.post(
            URI, json={"period": "30d", "format": "pdf"},
            headers={"x-csrf-token": csrf},
        )
        assert denied.status_code == 403
        client.post("/api/v1/control-plane/auth/logout", headers={"x-csrf-token": csrf})

        login = client.post(
            "/api/v1/control-plane/auth/login",
            json={"username": "report-qa-admin", "password": "qa-a-very-long-password-481"},
        )
        assert login.status_code == 200
        admin_csrf = login.json()["csrf_token"]
        missing_csrf = client.post(URI, json={"period": "30d", "format": "pdf"})
        assert missing_csrf.status_code == 403
        invalid = client.post(URI, json={"period": "30000", "format": "pdf"},
                              headers={"x-csrf-token": admin_csrf})
        assert invalid.status_code == 422
        legacy_request = client.post(
            URI, json={"period": "30d", "format": "pdf", "include_phase8_reference": True},
            headers={"x-csrf-token": admin_csrf},
        )
        assert legacy_request.status_code == 422
        generated_hashes = set()
        for fmt in ("pdf", "html", "json", "csv"):
            response = client.post(
                URI, json={"period": "30d", "format": fmt, "include_evidence": True},
                headers={"x-csrf-token": admin_csrf},
            )
            assert response.status_code == 200, response.text[:500]
            assert response.headers["cache-control"].startswith("no-store")
            assert response.headers["x-content-type-options"] == "nosniff"
            assert response.headers["content-disposition"].endswith("." + fmt + '"')
            digest = response.headers["x-report-sha256"]
            assert hashlib.sha256(response.content).hexdigest() == digest
            generated_hashes.add(digest)

    with qa_db() as db:
        logged = db.scalars(
            select(ControlPlaneAuditEvent)
            .where(ControlPlaneAuditEvent.action == "SECURITY_REPORT_GENERATED")
        ).all()
        assert len(logged) == 4
        assert all(row.actor_username_snapshot == "report-qa-admin" for row in logged)
        assert all(len(row.event_metadata["sha256"]) == 64 for row in logged)
        assert {row.event_metadata["sha256"] for row in logged} == generated_hashes
        assert all("token" not in json.dumps(row.event_metadata).lower() for row in logged)
