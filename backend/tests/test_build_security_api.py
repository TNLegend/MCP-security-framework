from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.models  # noqa: F401
import app.api.routes_build_security as build_routes
from app.core.config import settings
from app.db.database import Base, get_db
from app.main import app
from app.models.control_plane import (
    ControlPlaneAuditEvent,
    ControlPlaneConfigRevision,
)
from app.models.mcp_server import MCPServer
from app.schemas.control_plane import empty_latest_configuration
from app.services.published_configuration import config_content_hash
from app.services.control_plane_auth import create_user
import app.services.build_scan_orchestrator as orchestrator
from app.services.build_scan_orchestrator import BuildScannerRegistration
from scanners.contracts import (
    FindingConfidence,
    FindingSeverity,
    NormalizedFinding,
    ScannerAvailability,
    ScannerContext,
    ScannerExecutionResult,
    ScannerRunStatus,
    ValidatedWorkspace,
)


class _CleanScanner:
    def __init__(
        self,
        scanner_id: str,
        *,
        findings: tuple[NormalizedFinding, ...] = (),
    ) -> None:
        self.scanner_id = scanner_id
        self.findings = findings

    def probe(self) -> ScannerAvailability:
        return ScannerAvailability(
            available=True,
            scanner_id=self.scanner_id,
            version="test-1",
        )

    def scan(
        self,
        workspace: ValidatedWorkspace,
        context: ScannerContext,
    ) -> ScannerExecutionResult:
        return ScannerExecutionResult(
            scanner_id=self.scanner_id,
            status=ScannerRunStatus.COMPLETED,
            findings=self.findings,
            scanner_version="test-1",
        )


@pytest.fixture()
def api_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)

    def override_get_db():
        db = Session()
        try:
            yield db
        finally:
            db.close()

    previous_allowed = settings.build_scan_allowed_roots_json
    previous_cookie_secure = settings.control_plane_cookie_secure
    settings.build_scan_allowed_roots_json = json.dumps([str(tmp_path)])
    settings.control_plane_cookie_secure = False
    app.dependency_overrides[get_db] = override_get_db

    finding = NormalizedFinding.create(
        scanner_id="semgrep",
        rule_id="test.high-risk",
        category="TEST",
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.HIGH,
        title="High-risk test finding",
        file_path="server.py",
        line_start=1,
    )
    monkeypatch.setattr(
        orchestrator,
        "default_build_scanners",
        lambda: (
            BuildScannerRegistration(_CleanScanner("semgrep", findings=(finding,))),
            BuildScannerRegistration(_CleanScanner("gitleaks")),
            BuildScannerRegistration(_CleanScanner("trivy")),
        ),
    )

    with Session() as db:
        create_user(
            db,
            username="build-admin",
            password="Password123!",
            role="ADMIN",
        )
        create_user(
            db,
            username="build-viewer",
            password="Password123!",
            role="VIEWER",
        )
        server = MCPServer(
            name="inventory-build-server",
            server_type="mcp",
            endpoint="http://127.0.0.1:9999/mcp",
            status="active",
        )
        db.add(server)
        db.commit()
        server_id = server.id

    source = tmp_path / "mcp-source"
    source.mkdir()
    (source / "server.py").write_text("value = 1\n", encoding="utf-8")

    client = TestClient(app)
    yield {
        "client": client,
        "Session": Session,
        "source": source,
        "server_id": server_id,
        "tmp_path": tmp_path,
    }

    client.close()
    app.dependency_overrides.clear()
    settings.build_scan_allowed_roots_json = previous_allowed
    settings.control_plane_cookie_secure = previous_cookie_secure
    engine.dispose()


def _login(client: TestClient, username: str) -> str:
    response = client.post(
        "/api/v1/control-plane/auth/login",
        json={"username": username, "password": "Password123!"},
    )
    assert response.status_code == 200, response.text
    return response.json()["csrf_token"]


def _csrf_headers(token: str) -> dict[str, str]:
    return {settings.control_plane_csrf_header_name: token}


def test_build_security_reads_require_authentication(api_env) -> None:
    client = api_env["client"]
    response = client.get("/api/v1/control-plane/build-security/scans")
    assert response.status_code == 401


def test_viewer_can_read_but_cannot_mutate(api_env) -> None:
    client = api_env["client"]
    csrf = _login(client, "build-viewer")

    response = client.get("/api/v1/control-plane/build-security/scans")
    assert response.status_code == 200
    assert response.json() == []

    response = client.post(
        "/api/v1/control-plane/build-security/scans/local",
        headers=_csrf_headers(csrf),
        json={
            "display_name": "fixture",
            "source_locator": str(api_env["source"]),
            "reason": "Viewer must not start scans.",
        },
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "Admin role required"


def test_admin_mutation_requires_csrf(api_env) -> None:
    client = api_env["client"]
    _login(client, "build-admin")

    response = client.post(
        "/api/v1/control-plane/build-security/scans/local",
        json={
            "display_name": "fixture",
            "source_locator": str(api_env["source"]),
            "reason": "Missing CSRF should be rejected.",
        },
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "CSRF validation failed"


def test_admin_local_scan_returns_safe_summary_and_viewer_can_read_detail(api_env) -> None:
    client = api_env["client"]
    csrf = _login(client, "build-admin")
    binding = client.put(
        f"/api/v1/control-plane/build-security/inventory/{api_env['server_id']}/source",
        headers=_csrf_headers(csrf),
        json={
            "target_type": "LOCAL_DIRECTORY",
            "source_locator": str(api_env["source"]),
            "source_ref": None,
            "reason": "Bind exact source before linking direct scan evidence.",
        },
    )
    assert binding.status_code == 200, binding.text

    response = client.post(
        "/api/v1/control-plane/build-security/scans/local",
        headers=_csrf_headers(csrf),
        json={
            "display_name": "fixture-mcp",
            "source_locator": str(api_env["source"]),
            "linked_server_id": api_env["server_id"],
            "reason": "Run Build Security before publication.",
        },
    )
    assert response.status_code == 201, response.text
    payload = response.json()
    assert payload["status"] == "COMPLETED"
    assert payload["linked_server_id"] == api_env["server_id"]
    assert payload["source_fingerprint"]
    assert "source_locator" not in payload
    scan_id = payload["id"]

    sources = client.get("/api/v1/control-plane/build-security/scan-sources?limit=500")
    assert sources.status_code == 200
    source = next(item for item in sources.json() if item["scan_id"] == scan_id)
    assert source["source_locator"] == str(api_env["source"])

    client.cookies.clear()
    _login(client, "build-viewer")
    detail = client.get(
        f"/api/v1/control-plane/build-security/scans/{scan_id}"
    )
    assert detail.status_code == 200, detail.text
    body = detail.json()
    assert body["scan"]["id"] == scan_id
    assert body["assessment"]["status"] == "WARN"
    assert body["finding_total"] == 1
    assert body["findings_truncated"] is False
    assert body["findings"][0]["scanner_id"] == "semgrep"
    assert body["findings"][0]["severity"] == "HIGH"
    assert "source_locator" not in body["scan"]
    assert str(api_env["source"]) not in detail.text
    forbidden_sources = client.get(
        "/api/v1/control-plane/build-security/scan-sources?limit=500"
    )
    assert forbidden_sources.status_code == 403

    with api_env["Session"]() as db:
        audit = db.scalar(
            select(ControlPlaneAuditEvent).where(
                ControlPlaneAuditEvent.action == "BUILD_SECURITY_SCAN_COMPLETED"
            )
        )
        assert audit is not None
        serialized = json.dumps(
            {
                "before": audit.before_json,
                "after": audit.after_json,
                "metadata": audit.event_metadata,
            },
            sort_keys=True,
        )
        assert str(api_env["source"]) not in serialized
        assert audit.after_json["assessment_status"] == "WARN"


def test_scan_detail_orders_findings_by_semantic_severity(
    api_env,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    findings = tuple(
        NormalizedFinding.create(
            scanner_id="semgrep",
            rule_id=f"test.{severity.value.lower()}",
            category="TEST",
            severity=severity,
            confidence=FindingConfidence.HIGH,
            title=f"{severity.value} finding",
            file_path=f"{severity.value.lower()}.py",
            line_start=1,
        )
        for severity in (
            FindingSeverity.LOW,
            FindingSeverity.CRITICAL,
            FindingSeverity.MEDIUM,
            FindingSeverity.HIGH,
            FindingSeverity.INFO,
        )
    )
    monkeypatch.setattr(
        orchestrator,
        "default_build_scanners",
        lambda: (
            BuildScannerRegistration(_CleanScanner("semgrep", findings=findings)),
            BuildScannerRegistration(_CleanScanner("gitleaks")),
            BuildScannerRegistration(_CleanScanner("trivy")),
        ),
    )

    client = api_env["client"]
    csrf = _login(client, "build-admin")
    response = client.post(
        "/api/v1/control-plane/build-security/scans/local",
        headers=_csrf_headers(csrf),
        json={
            "display_name": "severity-order",
            "source_locator": str(api_env["source"]),
            "reason": "Verify semantic finding severity ordering.",
        },
    )
    assert response.status_code == 201, response.text

    detail = client.get(
        f"/api/v1/control-plane/build-security/scans/{response.json()['id']}"
    )
    assert detail.status_code == 200, detail.text
    assert [row["severity"] for row in detail.json()["findings"]] == [
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW",
        "INFO",
    ]


def test_direct_linked_scan_must_match_saved_inventory_source_binding(api_env) -> None:
    client = api_env["client"]
    csrf = _login(client, "build-admin")
    server_id = api_env["server_id"]

    binding = client.put(
        f"/api/v1/control-plane/build-security/inventory/{server_id}/source",
        headers=_csrf_headers(csrf),
        json={
            "target_type": "LOCAL_DIRECTORY",
            "source_locator": str(api_env["source"]),
            "source_ref": None,
            "reason": "Bind the expected source.",
        },
    )
    assert binding.status_code == 200, binding.text

    other = api_env["tmp_path"] / "other-source"
    other.mkdir()
    (other / "server.py").write_text("def ok():\n    return True\n", encoding="utf-8")

    mismatch = client.post(
        "/api/v1/control-plane/build-security/scans/local",
        headers=_csrf_headers(csrf),
        json={
            "display_name": "unrelated-clean-source",
            "source_locator": str(other),
            "linked_server_id": server_id,
            "reason": "Attempt to link unrelated source.",
        },
    )
    assert mismatch.status_code == 400
    assert mismatch.json()["detail"] == "build_source_binding_mismatch"

    unlinked = client.post(
        "/api/v1/control-plane/build-security/scans/local",
        headers=_csrf_headers(csrf),
        json={
            "display_name": "unrelated-standalone-source",
            "source_locator": str(other),
            "linked_server_id": None,
            "reason": "Standalone scans remain allowed.",
        },
    )
    assert unlinked.status_code == 201, unlinked.text
    assert unlinked.json()["linked_server_id"] is None


def test_admin_can_attach_completed_inventory_linked_scan_to_governed_draft(api_env) -> None:
    client = api_env["client"]
    csrf = _login(client, "build-admin")
    binding = client.put(
        f"/api/v1/control-plane/build-security/inventory/{api_env['server_id']}/source",
        headers=_csrf_headers(csrf),
        json={
            "target_type": "LOCAL_DIRECTORY",
            "source_locator": str(api_env["source"]),
            "source_ref": None,
            "reason": "Bind exact source before Runtime-governed evidence.",
        },
    )
    assert binding.status_code == 200, binding.text

    scan_response = client.post(
        "/api/v1/control-plane/build-security/scans/local",
        headers=_csrf_headers(csrf),
        json={
            "display_name": "governed-build-source",
            "source_locator": str(api_env["source"]),
            "linked_server_id": api_env["server_id"],
            "reason": "Generate evidence for Runtime governance.",
        },
    )
    assert scan_response.status_code == 201, scan_response.text
    scan_id = scan_response.json()["id"]

    with api_env["Session"]() as db:
        base = empty_latest_configuration()
        content = base.model_dump(mode="json")
        draft = ControlPlaneConfigRevision(
            revision_number=1,
            status="DRAFT",
            schema_version=base.schema_version,
            content=content,
            content_hash=config_content_hash(content),
            change_summary="Build gate draft",
        )
        db.add(draft)
        db.commit()
        draft_id = draft.id

    response = client.post(
        f"/api/v1/control-plane/build-security/scans/{scan_id}/attach-to-draft",
        headers=_csrf_headers(csrf),
        json={
            "draft_revision_id": draft_id,
            "mode": "ALLOW_WARN",
            "max_evidence_age_hours": 72,
            "reason": "Govern Runtime with this exact Build evidence.",
        },
    )
    assert response.status_code == 200, response.text
    revision = response.json()
    build_security = revision["content"]["build_security"]
    assert build_security["mode"] == "ALLOW_WARN"
    assert build_security["max_evidence_age_hours"] == 72
    assert len(build_security["evidence"]) == 1
    evidence = build_security["evidence"][0]
    assert evidence["scan_id"] == scan_id
    assert evidence["assessment_status"] == "WARN"
    assert evidence["required_scanners_complete"] is True
    assert "source_locator" not in evidence

    with api_env["Session"]() as db:
        event = db.scalar(
            select(ControlPlaneAuditEvent).where(
                ControlPlaneAuditEvent.action == "BUILD_EVIDENCE_ATTACHED_TO_DRAFT"
            )
        )
        assert event is not None
        assert event.revision_id == draft_id
        assert event.after_json["scan_id"] == scan_id
        assert str(api_env["source"]) not in json.dumps(event.after_json)


def test_inventory_source_binding_is_admin_only_audited_and_scanable(api_env) -> None:
    client = api_env["client"]
    csrf = _login(client, "build-admin")
    server_id = api_env["server_id"]

    response = client.put(
        f"/api/v1/control-plane/build-security/inventory/{server_id}/source",
        headers=_csrf_headers(csrf),
        json={
            "target_type": "LOCAL_DIRECTORY",
            "source_locator": str(api_env["source"]),
            "source_ref": None,
            "reason": "Associate this inventory server with its source.",
        },
    )
    assert response.status_code == 200, response.text
    binding = response.json()
    assert binding["server_id"] == server_id
    assert binding["target_type"] == "LOCAL_DIRECTORY"

    read = client.get(
        f"/api/v1/control-plane/build-security/inventory/{server_id}/source"
    )
    assert read.status_code == 200
    assert read.json()["id"] == binding["id"]

    listed = client.get("/api/v1/control-plane/build-security/inventory/sources")
    assert listed.status_code == 200
    assert any(
        item["server_id"] == server_id
        and item["source_locator"] == str(api_env["source"])
        for item in listed.json()
    )

    scan = client.post(
        f"/api/v1/control-plane/build-security/scans/inventory/{server_id}",
        headers=_csrf_headers(csrf),
        json={"reason": "Scan configured Inventory source."},
    )
    assert scan.status_code == 201, scan.text
    assert scan.json()["linked_server_id"] == server_id

    with api_env["Session"]() as db:
        events = db.scalars(
            select(ControlPlaneAuditEvent).where(
                ControlPlaneAuditEvent.action == "BUILD_SOURCE_BINDING_UPSERTED"
            )
        ).all()
        assert len(events) == 1
        assert events[0].target_id == str(server_id)
        assert str(api_env["source"]) not in json.dumps(
            events[0].after_json,
            sort_keys=True,
        )

    client.cookies.clear()
    _login(client, "build-viewer")
    forbidden = client.get(
        f"/api/v1/control-plane/build-security/inventory/{server_id}/source"
    )
    assert forbidden.status_code == 403
    forbidden_list = client.get("/api/v1/control-plane/build-security/inventory/sources")
    assert forbidden_list.status_code == 403


def test_invalid_local_target_is_rejected_and_audited_without_path_disclosure(api_env) -> None:
    client = api_env["client"]
    csrf = _login(client, "build-admin")
    outside = api_env["tmp_path"].parent / "outside-build-source"
    outside.mkdir(exist_ok=True)

    response = client.post(
        "/api/v1/control-plane/build-security/scans/local",
        headers=_csrf_headers(csrf),
        json={
            "display_name": "outside",
            "source_locator": str(outside),
            "reason": "This path must be rejected.",
        },
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "target_outside_allowed_roots"
    assert str(outside) not in response.text

    with api_env["Session"]() as db:
        audit = db.scalar(
            select(ControlPlaneAuditEvent).where(
                ControlPlaneAuditEvent.action == "BUILD_SECURITY_SCAN_REJECTED"
            )
        )
        assert audit is not None
        assert audit.event_metadata["error_code"] == "target_outside_allowed_roots"
        assert str(outside) not in json.dumps(audit.event_metadata)




def test_admin_can_open_native_folder_picker_and_viewer_cannot(
    api_env,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = api_env["client"]
    csrf = _login(client, "build-admin")
    monkeypatch.setattr(
        build_routes,
        "pick_native_local_directory",
        lambda **_: api_env["source"].resolve(),
    )

    picked = client.post(
        "/api/v1/control-plane/build-security/targets/local/pick-directory",
        headers=_csrf_headers(csrf),
        json={},
    )
    assert picked.status_code == 200, picked.text
    assert picked.json() == {
        "selected": True,
        "path": str(api_env["source"].resolve()),
        "name": api_env["source"].name,
    }

    monkeypatch.setattr(
        build_routes,
        "pick_native_local_directory",
        lambda **_: None,
    )
    cancelled = client.post(
        "/api/v1/control-plane/build-security/targets/local/pick-directory",
        headers=_csrf_headers(csrf),
        json={},
    )
    assert cancelled.status_code == 200
    assert cancelled.json() == {
        "selected": False,
        "path": None,
        "name": None,
    }

    client.cookies.clear()
    viewer_csrf = _login(client, "build-viewer")
    forbidden = client.post(
        "/api/v1/control-plane/build-security/targets/local/pick-directory",
        headers=_csrf_headers(viewer_csrf),
        json={},
    )
    assert forbidden.status_code == 403


def test_native_folder_picker_respects_explicit_root_restrictions(
    api_env,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = api_env["client"]
    csrf = _login(client, "build-admin")
    outside = api_env["tmp_path"].parent / "picker-outside-root"
    outside.mkdir(exist_ok=True)
    try:
        monkeypatch.setattr(
            build_routes,
            "pick_native_local_directory",
            lambda **_: outside.resolve(),
        )
        response = client.post(
            "/api/v1/control-plane/build-security/targets/local/pick-directory",
            headers=_csrf_headers(csrf),
            json={},
        )
        assert response.status_code == 400
        assert response.json()["detail"] == "target_outside_allowed_roots"
        assert str(outside) not in response.text
    finally:
        outside.rmdir()


def test_scan_list_filters_are_bounded(api_env) -> None:
    client = api_env["client"]
    _login(client, "build-viewer")

    invalid_status = client.get(
        "/api/v1/control-plane/build-security/scans?status=unknown"
    )
    assert invalid_status.status_code == 400
    assert invalid_status.json()["detail"] == "build_scan_status_invalid"

    excessive_limit = client.get(
        "/api/v1/control-plane/build-security/scans?limit=501"
    )
    assert excessive_limit.status_code == 422
