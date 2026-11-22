from datetime import datetime, timedelta
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.api.routes_control_plane_audit import router
from app.db.database import Base, get_db
from app.models.control_plane import ControlPlaneConfigRevision, ControlPlaneUser, EmergencyDeny
from app.models.mcp_server import MCPServer
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
