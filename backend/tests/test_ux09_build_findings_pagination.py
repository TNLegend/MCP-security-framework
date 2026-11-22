"""UX-09: Build findings beyond the 500-row detail cap are reachable (isolated in-memory DB)."""
from __future__ import annotations

import hashlib
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.api.routes_build_security import router
from app.db.database import Base, get_db
from app.models.build_security import BuildAssessment, BuildFinding, BuildScannerRun, BuildScanRun
from app.services.control_plane_auth import require_admin, require_authenticated_user

BASE = "/control-plane/build-security/scans"


@pytest.fixture(params=["VIEWER", "ADMIN"])
def harness(request):
    engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine, tables=[
        BuildScanRun.__table__, BuildScannerRun.__table__, BuildFinding.__table__, BuildAssessment.__table__,
    ])
    db = Session(engine, expire_on_commit=False)
    scan = BuildScanRun(target_type="LOCAL_DIRECTORY", display_name="synthetic", source_locator="synthetic",
                        status="COMPLETED")
    db.add(scan)
    db.flush()
    runs = {}
    for scanner in ("semgrep", "trivy"):
        runs[scanner] = BuildScannerRun(build_scan_id=scan.id, scanner_id=scanner, status="COMPLETED")
        db.add(runs[scanner])
    db.flush()
    # 520 findings: 500 LOW + 20 INFO, so the INFO rows sort after the 500-row cap.
    last_id = None
    for index in range(520):
        severity = "LOW" if index < 500 else "INFO"
        scanner = "semgrep" if index % 2 else "trivy"
        finding = BuildFinding(
            build_scan_id=scan.id, scanner_run_id=runs[scanner].id, scanner_id=scanner,
            rule_id=f"rule.{index % 7}", category="code", severity=severity, confidence="HIGH",
            finding_state="NEW" if index % 3 else "UNCHANGED",
            fingerprint=hashlib.sha256(str(index).encode()).hexdigest(),
            title=f"Synthetic finding {index}", file_path=f"src/module_{index:04d}.py", line_start=1,
            references=[], safe_metadata={},
        )
        db.add(finding)
        db.flush()
        last_id = finding.id if index == 519 else last_id
    db.commit()
    app = FastAPI()
    app.include_router(router)
    actor = SimpleNamespace(user=SimpleNamespace(id="u" * 36, role=request.param, username=request.param.lower()))
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[require_authenticated_user] = lambda: actor
    app.dependency_overrides[require_admin] = lambda: actor
    with TestClient(app) as client:
        yield client, scan.id, last_id
    db.close()
    engine.dispose()


def test_detail_cap_is_explicit_and_row_520_is_found_by_exact_id(harness):
    client, scan_id, last_id = harness
    detail = client.get(f"{BASE}/{scan_id}").json()
    assert detail["finding_total"] == 520 and detail["findings_truncated"] is True
    assert last_id not in {item["id"] for item in detail["findings"]}
    page = client.get(f"{BASE}/{scan_id}/findings", params={"finding_id": last_id}).json()
    assert page["total"] == 1 and page["items"][0]["id"] == last_id
    assert page["items"][0]["file_path"] == "src/module_0519.py"  # same disclosure as the detail endpoint
    assert page["unfiltered_total"] == 520


def test_pages_cover_every_record_once_in_stable_order(harness):
    client, scan_id, _ = harness
    seen = []
    offset = 0
    while True:
        page = client.get(f"{BASE}/{scan_id}/findings", params={"offset": offset, "limit": 200}).json()
        assert page["total"] == 520
        seen.extend(item["id"] for item in page["items"])
        if not page["has_more"]:
            break
        offset += page["returned"]
    assert len(seen) == len(set(seen)) == 520
    again = client.get(f"{BASE}/{scan_id}/findings", params={"offset": 400, "limit": 200}).json()
    assert [item["id"] for item in again["items"]] == seen[400:600]


def test_filters_share_the_page_total(harness):
    client, scan_id, _ = harness
    info = client.get(f"{BASE}/{scan_id}/findings", params={"severity": "info"}).json()
    assert info["total"] == 20 and all(item["severity"] == "INFO" for item in info["items"])
    by_path = client.get(f"{BASE}/{scan_id}/findings", params={"path": "module_051"}).json()
    assert by_path["total"] == 10
    combined = client.get(f"{BASE}/{scan_id}/findings",
                          params={"scanner_id": "semgrep", "finding_state": "unchanged", "rule_id": "rule.3"}).json()
    assert all(i["scanner_id"] == "semgrep" and i["finding_state"] == "UNCHANGED" and i["rule_id"] == "rule.3"
               for i in combined["items"])
    assert combined["filters"] == {"finding_state": "UNCHANGED", "scanner_id": "semgrep", "rule_id": "rule.3"}
    wildcard = client.get(f"{BASE}/{scan_id}/findings", params={"path": "%"}).json()
    assert wildcard["total"] == 0  # LIKE metacharacters are literal
    assert client.get(f"{BASE}/{scan_id}/findings", params={"severity": "SEVERE"}).status_code == 422
    assert client.get(f"{BASE}/missing/findings").status_code == 404
