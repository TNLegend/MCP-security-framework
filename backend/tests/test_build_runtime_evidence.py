from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.models  # noqa: F401
from app.db.database import Base
from app.models.build_security import BuildAssessment, BuildScanRun
from app.models.control_plane import ControlPlaneConfigRevision, ControlPlaneUser
from app.models.mcp_server import MCPServer
from app.schemas.control_plane import (
    BuildSecurityEvidenceReference,
    BuildSecuritySettings,
    ControlPlaneConfigContent,
    empty_latest_configuration,
)
from app.schemas.policy_context import PolicyBuildSecurityContext
from app.services.build_runtime_evidence import (
    attach_scan_evidence_to_draft,
    evidence_reference_from_scan,
)
from app.services.control_plane_config import (
    ControlPlaneConfigError,
    _validate_build_security_database_artifacts,
)
from app.services.published_configuration import (
    PublishedConfigurationSnapshot,
    config_content_hash,
)
from common.mcp_endpoint import server_ref_for_server


def _session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return engine, sessionmaker(bind=engine, expire_on_commit=False)()


def _seed_build_evidence(db):
    server = MCPServer(
        name="runtime-build-server",
        server_type="mcp",
        endpoint="http://127.0.0.1:9900/mcp",
        transport="streamable_http",
        status="active",
    )
    db.add(server)
    db.flush()

    scan = BuildScanRun(
        target_type="LOCAL_DIRECTORY",
        display_name="runtime-build-server",
        source_locator="D:/safe/source",
        source_fingerprint="a" * 64,
        linked_server_id=server.id,
        status="COMPLETED",
        started_at=datetime(2026, 1, 1, 11, 0, 0),
        completed_at=datetime(2026, 1, 1, 12, 0, 0),
    )
    db.add(scan)
    db.flush()
    assessment = BuildAssessment(
        build_scan_id=scan.id,
        status="PASS",
        policy_version="build-policy-v1",
        required_scanners_complete=True,
        reason_codes=[],
        summary="clean",
    )
    db.add(assessment)
    db.flush()
    return server, scan, assessment


def test_build_security_config_defaults_disabled_and_enforces_unique_server_refs() -> None:
    content = empty_latest_configuration()
    assert content.build_security.mode == "DISABLED"
    assert content.build_security.max_evidence_age_hours == 168
    assert content.build_security.evidence == ()

    evidence = BuildSecurityEvidenceReference(
        server_ref="streamable_http:http://127.0.0.1:9900/mcp",
        scan_id="11111111-1111-1111-1111-111111111111",
        source_fingerprint="a" * 64,
        source_revision=None,
        assessment_status="PASS",
        assessment_policy_version="build-policy-v1",
        required_scanners_complete=True,
        completed_at=datetime(2026, 1, 1, 12, 0, 0),
    )
    assert evidence.completed_at.tzinfo is not None

    with pytest.raises(ValidationError):
        BuildSecuritySettings(
            mode="REQUIRE_PASS",
            evidence=(evidence, evidence.model_copy(update={"scan_id": "22222222-2222-2222-2222-222222222222"})),
        )


def test_policy_build_context_fails_closed_on_incomplete_evidence_shape() -> None:
    with pytest.raises(ValidationError):
        PolicyBuildSecurityContext(
            mode="REQUIRE_PASS",
            evidence_present=True,
            scan_id="11111111-1111-1111-1111-111111111111",
            source_fingerprint="a" * 64,
            assessment_status="PASS",
            required_scanners_complete=True,
        )

    disabled = PolicyBuildSecurityContext()
    assert disabled.mode == "DISABLED"
    assert disabled.evidence_present is False


def test_database_validation_accepts_exact_build_reference_and_rejects_tampering() -> None:
    engine, db = _session()
    try:
        _server, scan, _assessment = _seed_build_evidence(db)
        reference = evidence_reference_from_scan(db, scan_id=scan.id)
        content = empty_latest_configuration().model_copy(
            update={
                "build_security": BuildSecuritySettings(
                    mode="REQUIRE_PASS",
                    max_evidence_age_hours=72,
                    evidence=(reference,),
                )
            }
        )
        _validate_build_security_database_artifacts(db, content)

        tampered = content.model_copy(
            update={
                "build_security": content.build_security.model_copy(
                    update={
                        "evidence": (
                            reference.model_copy(
                                update={"source_fingerprint": "b" * 64}
                            ),
                        )
                    }
                )
            }
        )
        with pytest.raises(
            ControlPlaneConfigError,
            match="build_evidence_source_fingerprint_mismatch",
        ):
            _validate_build_security_database_artifacts(db, tampered)
    finally:
        db.close()
        engine.dispose()


def test_attach_scan_evidence_updates_only_target_server_in_draft() -> None:
    engine, db = _session()
    try:
        server, scan, _assessment = _seed_build_evidence(db)
        actor = ControlPlaneUser(
            username="admin",
            password_hash="test-only-hash",
            role="ADMIN",
            enabled=True,
        )
        db.add(actor)
        db.flush()

        base = empty_latest_configuration()
        base_json = base.model_dump(mode="json")
        draft = ControlPlaneConfigRevision(
            revision_number=1,
            status="DRAFT",
            schema_version=base.schema_version,
            content=base_json,
            content_hash=config_content_hash(base_json),
            created_by=actor.id,
            change_summary="initial",
        )
        db.add(draft)
        db.flush()

        updated = attach_scan_evidence_to_draft(
            db,
            scan_id=scan.id,
            draft_revision_id=draft.id,
            mode="REQUIRE_PASS",
            max_evidence_age_hours=48,
            actor=actor,
            change_summary="Attach Build evidence.",
        )
        parsed = ControlPlaneConfigContent.model_validate(updated.content)
        assert parsed.build_security.mode == "REQUIRE_PASS"
        assert parsed.build_security.max_evidence_age_hours == 48
        assert len(parsed.build_security.evidence) == 1
        evidence = parsed.build_security.evidence[0]
        assert evidence.scan_id == scan.id
        assert evidence.source_fingerprint == scan.source_fingerprint
        assert evidence.server_ref == server_ref_for_server(
            {"endpoint": server.endpoint, "transport": server.transport}
        )
        _validate_build_security_database_artifacts(db, parsed)
    finally:
        db.close()
        engine.dispose()


def test_failed_scan_with_error_assessment_can_be_published_as_blocking_evidence() -> None:
    engine, db = _session()
    try:
        server, scan, assessment = _seed_build_evidence(db)
        scan.status = "FAILED"
        scan.failure_code = "required_scanner_incomplete"
        assessment.status = "ERROR"
        assessment.required_scanners_complete = False
        assessment.reason_codes = ["required_scanner_incomplete"]
        db.flush()

        reference = evidence_reference_from_scan(db, scan_id=scan.id)
        assert reference.assessment_status == "ERROR"
        assert reference.required_scanners_complete is False

        content = empty_latest_configuration().model_copy(
            update={
                "build_security": BuildSecuritySettings(
                    mode="REQUIRE_PASS",
                    max_evidence_age_hours=48,
                    evidence=(reference,),
                )
            }
        )
        _validate_build_security_database_artifacts(db, content)

        inconsistent = reference.model_copy(
            update={
                "assessment_status": "PASS",
                "required_scanners_complete": True,
            }
        )
        invalid_content = content.model_copy(
            update={
                "build_security": content.build_security.model_copy(
                    update={"evidence": (inconsistent,)}
                )
            }
        )
        with pytest.raises(ControlPlaneConfigError):
            _validate_build_security_database_artifacts(db, invalid_content)
    finally:
        db.close()
        engine.dispose()


def test_published_snapshot_exposes_only_signed_build_fact_for_requested_server() -> None:
    engine, db = _session()
    try:
        server, scan, _assessment = _seed_build_evidence(db)
        reference = evidence_reference_from_scan(db, scan_id=scan.id)
        content = empty_latest_configuration().model_copy(
            update={
                "build_security": BuildSecuritySettings(
                    mode="ALLOW_WARN",
                    max_evidence_age_hours=24,
                    evidence=(reference,),
                )
            }
        )
        snapshot = PublishedConfigurationSnapshot(
            revision_id="revision-1",
            revision_number=1,
            content_hash="f" * 64,
            schema_version=2,
            content=content,
        )
        server_ref = server_ref_for_server(
            {"endpoint": server.endpoint, "transport": server.transport}
        )
        fact = snapshot.get_build_security_context(server_ref)
        assert fact["mode"] == "ALLOW_WARN"
        assert fact["evidence_present"] is True
        assert fact["scan_id"] == scan.id
        assert fact["assessment_status"] == "PASS"
        assert fact["required_scanners_complete"] is True
        assert fact["completed_at"].endswith("Z")
        assert "source_locator" not in fact

        missing = snapshot.get_build_security_context("other-server")
        assert missing["mode"] == "ALLOW_WARN"
        assert missing["evidence_present"] is False
        assert missing["scan_id"] is None
    finally:
        db.close()
        engine.dispose()
