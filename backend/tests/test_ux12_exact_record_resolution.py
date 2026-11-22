from datetime import datetime, timedelta
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.api.routes_control_plane_audit import router
from app.db.database import Base, get_db
from app.models.control_plane import ControlPlaneAuditEvent, ControlPlaneConfigRevision, ControlPlaneUser, EmergencyDeny
from app.models.mcp_server import MCPServer
from app.models.mcp_tool import MCPTool
from app.models.tool_analysis import ToolProtocolObservation
from app.services.control_plane_auth import require_authenticated_user


def test_exact_target_resolution_and_viewer_boundary():
    engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine, tables=[
        ControlPlaneConfigRevision.__table__, ControlPlaneUser.__table__, EmergencyDeny.__table__, MCPServer.__table__,
    ])
    app = FastAPI()
    app.include_router(router)
    actor = SimpleNamespace(user=SimpleNamespace(role="VIEWER"))
    app.dependency_overrides[require_authenticated_user] = lambda: actor
    with Session(engine) as db:
        user = ControlPlaneUser(username="fixture", password_hash="synthetic-password-hash", role="ADMIN")
        historical = ControlPlaneConfigRevision(revision_number=2, status="PUBLISHED", schema_version=2,
                                               content={}, content_hash="a" * 64)
        latest = ControlPlaneConfigRevision(revision_number=3, status="PUBLISHED", schema_version=2,
                                           content={}, content_hash="b" * 64)
        archived = MCPServer(name="Repeated name", status="archived", server_type="mcp", endpoint="https://fixture.invalid/a")
        current = MCPServer(name="Repeated name", server_type="mcp", endpoint="https://fixture.invalid/b")
        deny = EmergencyDeny(target_type="global", reason="synthetic", created_by="fixture",
                             expires_at=datetime.utcnow() + timedelta(hours=1))
        db.add_all([user, historical, latest, archived, current, deny])
        db.commit()
        app.dependency_overrides[get_db] = lambda: db
        with TestClient(app) as client:
            base = "/control-plane/audit/resolve"
            result = client.get(f"{base}/control_plane_config_revision/{historical.id}")
            assert result.json() == {"type": "control_plane_config_revision", "id": historical.id,
                                     "label": "Revision #2", "status": "PUBLISHED"}
            assert client.get(f"{base}/mcp_server/{archived.id}").json()["status"] == "archived"
            assert client.get(f"{base}/emergency_deny/{deny.id}").json()["status"] == "ACTIVE"
            assert client.get(f"{base}/mcp_server/9999").status_code == 404
            assert client.get(f"{base}/control_plane_user/{user.id}").status_code == 404
            actor.user.role = "ADMIN"
            assert client.get(f"{base}/control_plane_user/{user.id}").json() == {
                "type": "control_plane_user", "id": user.id, "label": "fixture", "status": "Enabled",
            }
    engine.dispose()


def test_protocol_observation_lookup_is_exact_authenticated_and_audit_scoped():
    engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine, tables=[
        ControlPlaneAuditEvent.__table__, MCPServer.__table__, MCPTool.__table__,
        ToolProtocolObservation.__table__,
    ])
    app = FastAPI()
    app.include_router(router)
    with Session(engine) as db, TestClient(app) as client:
        server = MCPServer(name="Fixture", server_type="mcp", endpoint="https://fixture.invalid")
        db.add(server)
        db.flush()
        tool = MCPTool(server_id=server.id, name="read_fixture")
        db.add(tool)
        db.flush()
        observation = {
            "tool_id": tool.id, "server_ref": "fixture-server", "upstream_protocol_profile_id": "fixture-profile",
            "canonical_tool_definition": {"description": "evidence payload intentionally omitted from audit resolver"},
            "tool_name": "read_fixture",
        }
        old = ToolProtocolObservation(**observation, tool_fingerprint="a" * 64, analysis_state="STALE")
        recent = ToolProtocolObservation(**observation, tool_fingerprint="b" * 64, analysis_state="COMPLETE")
        db.add_all([old, recent])
        db.flush()
        db.add_all([
            ControlPlaneAuditEvent(action="TOOL_OBSERVATION_APPROVE",
                                   target_type="tool_protocol_observation", target_id=str(old.id)),
            ControlPlaneAuditEvent(action="OTHER_TYPE", target_type="mcp_tool", target_id=str(recent.id)),
        ])
        db.commit()
        app.dependency_overrides[get_db] = lambda: db
        base = "/control-plane/audit/resolve/tool_protocol_observation"
        assert client.get(f"{base}/{old.id}").status_code == 401

        actor = SimpleNamespace(user=SimpleNamespace(role="VIEWER"))
        app.dependency_overrides[require_authenticated_user] = lambda: actor
        for role in ("VIEWER", "ADMIN"):
            actor.user.role = role
            result = client.get(f"{base}/{old.id}")
            assert result.json() == {
                "type": "tool_protocol_observation", "id": str(old.id),
                "label": f"Observation #{old.id}", "status": "STALE",
            }
            for invalid in (recent.id, 999, f"0{old.id}", 2147483648):
                assert client.get(f"{base}/{invalid}").status_code == 404
    engine.dispose()
