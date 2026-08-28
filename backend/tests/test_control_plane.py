import os
import io
import json
import sys
import tempfile
import threading
import unittest
import zipfile
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND_DIR = REPO_ROOT / "backend"
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(BACKEND_DIR))

from app.db.database import Base, get_db  # noqa: E402
from app.main import app  # noqa: E402
from app.models.control_plane import (  # noqa: E402
    ControlPlaneAuditEvent,
    ControlPlaneConfigRevision,
    ControlPlaneSession,
    ControlPlaneState,
    ControlPlaneUser,
)
from app.models.mcp_tool import MCPTool  # noqa: E402
from app.models.mcp_server import MCPServer  # noqa: E402
from app.models.runtime_call import RuntimeCall  # noqa: E402
from app.models.tool_analysis import ToolAnalysis, ToolAnalysisFinding, ToolObservedVersion  # noqa: E402
from app.schemas.control_plane import (  # noqa: E402
    ControlPlaneConfigContent,
    PolicyRuleSettings,
    PolicySettings,
)
from app.services.control_plane_auth import (  # noqa: E402
    create_user,
    hash_password,
    verify_password,
)
from app.services.control_plane_config import (  # noqa: E402
    create_draft_from_revision,
    create_revision,
    publish_revision,
    rollback_to_revision,
)
from app.services.published_configuration import (  # noqa: E402
    PublishedConfigurationError,
    PublishedConfigurationProvider,
    config_content_hash,
    content_model_to_json,
)
from app.services.signed_service_request import (  # noqa: E402
    PERMISSION_INTERNAL_INVENTORY_SERVERS_READ,
    PERMISSION_INTERNAL_INVENTORY_TOOLS_READ,
    PERMISSION_INVENTORY_IMPORT_DISCOVERY,
    PERMISSION_RUNTIME_LOGS_WRITE,
    SERVICE_ID_DISCOVERY,
    SERVICE_ID_PROXY,
    ServiceRequestSignerConfig,
    SignedServiceRequestSigner,
    canonical_json_body,
)
from app.services.server_security_metadata import refresh_server_security_status  # noqa: E402
from app.services.subject_authorization import SubjectAuthorizationDocument  # noqa: E402
from app.services.tool_analysis import ANALYZER_REVISION  # noqa: E402
from scripts.import_control_plane_config import ensure_initial_published_configuration  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from app.core.config import settings  # noqa: E402
from proxy.identity_binding import IdentityBindingDocument  # noqa: E402


SERVER_REF = "streamable_http:http://127.0.0.1:9000/mcp"


def _private_pem(key: ed25519.Ed25519PrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _public_pem(key: ed25519.Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


def config_content(
    root_env: str = "TEST_CP_ROOT",
    *,
    agent_id: str = "agent_demo",
    required_capability: str = "filesystem.read",
    scope_sensitivity: str = "internal",
) -> ControlPlaneConfigContent:
    _ = root_env, scope_sensitivity
    _ = required_capability
    return ControlPlaneConfigContent(
        schema_version=2,
        identity_bindings=IdentityBindingDocument.model_validate(
            {
                "revision": "cp-test",
                "bindings": [{"issuer": "issuer", "subject": "subject", "agent_id": agent_id}],
            }
        ),
        agent_authorizations=SubjectAuthorizationDocument.model_validate(
            {
                "revision": "cp-test",
                "subjects": {
                    agent_id: {
                        "role": "legal_agent",
                        "grants": [],
                    }
                },
            }
        ),
        policy_settings=PolicySettings(
            rules={
                "tool_analysis_required": PolicyRuleSettings(
                    enabled=True,
                    severity="HIGH",
                )
            }
        ),
    )


class ControlPlaneTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)
        self.root_dir = tempfile.TemporaryDirectory()
        os.environ["TEST_CP_ROOT"] = self.root_dir.name
        self.previous_service_public_keys_path = settings.internal_service_public_keys_path
        self.previous_proxy_private_key_path = settings.mcp_proxy_service_private_key_path
        self.previous_discovery_private_key_path = settings.mcp_discovery_service_private_key_path
        self._configure_service_identities()

        def override_get_db():
            db = self.Session()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = override_get_db
        self.client = TestClient(app)

    def tearDown(self) -> None:
        app.dependency_overrides.clear()
        settings.internal_service_public_keys_path = self.previous_service_public_keys_path
        settings.mcp_proxy_service_private_key_path = self.previous_proxy_private_key_path
        settings.mcp_discovery_service_private_key_path = self.previous_discovery_private_key_path
        self.root_dir.cleanup()

    def create_user(self, username: str, role: str, password: str = "Password123!") -> ControlPlaneUser:
        with self.Session() as db:
            user = create_user(db, username=username, password=password, role=role)
            db.commit()
            user_id = user.id
        with self.Session() as db:
            return db.get(ControlPlaneUser, user_id)

    def login(self, username: str, password: str = "Password123!") -> str:
        response = self.client.post(
            "/api/v1/control-plane/auth/login",
            json={"username": username, "password": password},
        )
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()["csrf_token"]

    def _configure_service_identities(self) -> None:
        service_dir = Path(self.root_dir.name) / "service-identities"
        service_dir.mkdir(parents=True, exist_ok=True)
        self.proxy_private_key_path = service_dir / "proxy.pem"
        self.discovery_private_key_path = service_dir / "discovery.pem"
        proxy_key = ed25519.Ed25519PrivateKey.generate()
        discovery_key = ed25519.Ed25519PrivateKey.generate()
        self.proxy_private_key_path.write_bytes(_private_pem(proxy_key))
        self.discovery_private_key_path.write_bytes(_private_pem(discovery_key))
        registry_path = service_dir / "public.json"
        registry_path.write_text(
            json.dumps(
                {
                    "services": {
                        SERVICE_ID_PROXY: {
                            "permissions": [
                                PERMISSION_INTERNAL_INVENTORY_SERVERS_READ,
                                PERMISSION_INTERNAL_INVENTORY_TOOLS_READ,
                                PERMISSION_RUNTIME_LOGS_WRITE,
                            ],
                            "keys": [
                                {
                                    "key_id": "proxy-test",
                                    "public_key_pem": _public_pem(proxy_key),
                                }
                            ],
                        },
                        SERVICE_ID_DISCOVERY: {
                            "permissions": [PERMISSION_INVENTORY_IMPORT_DISCOVERY],
                            "keys": [
                                {
                                    "key_id": "discovery-test",
                                    "public_key_pem": _public_pem(discovery_key),
                                }
                            ],
                        },
                    }
                }
            ),
            encoding="utf-8",
        )
        settings.internal_service_public_keys_path = str(registry_path)
        settings.mcp_proxy_service_key_id = "proxy-test"
        settings.mcp_proxy_service_private_key_path = str(self.proxy_private_key_path)
        settings.mcp_discovery_service_key_id = "discovery-test"
        settings.mcp_discovery_service_private_key_path = str(self.discovery_private_key_path)

    def service_headers(
        self,
        service_id: str,
        *,
        method: str,
        path: str,
        payload: dict | None = None,
    ) -> dict[str, str]:
        key_id = "proxy-test" if service_id == SERVICE_ID_PROXY else "discovery-test"
        private_key_path = (
            self.proxy_private_key_path
            if service_id == SERVICE_ID_PROXY
            else self.discovery_private_key_path
        )
        signer = SignedServiceRequestSigner(
            ServiceRequestSignerConfig(
                service_id=service_id,
                key_id=key_id,
                private_key_path=private_key_path,
            )
        )
        return signer.signed_headers(
            method=method,
            path=path,
            body=canonical_json_body(payload),
        )


class ControlPlaneAuthTests(ControlPlaneTestCase):
    def test_create_admin_and_viewer_hashes_password(self) -> None:
        admin = self.create_user("admin", "ADMIN")
        viewer = self.create_user("viewer", "VIEWER")
        self.assertEqual(admin.role, "ADMIN")
        self.assertEqual(viewer.role, "VIEWER")
        self.assertNotEqual(admin.password_hash, "Password123!")
        self.assertTrue(verify_password("Password123!", admin.password_hash))

    def test_invalid_role_and_duplicate_username_are_rejected(self) -> None:
        self.create_user("admin", "ADMIN")
        with self.Session() as db:
            with self.assertRaises(Exception):
                create_user(db, username="bad", password="Password123!", role="OWNER")
            with self.assertRaises(Exception):
                create_user(db, username="admin", password="Password123!", role="ADMIN")

    def test_login_me_bad_password_disabled_logout_and_session_states(self) -> None:
        self.create_user("admin", "ADMIN")
        csrf = self.login("admin")
        me = self.client.get("/api/v1/control-plane/auth/me")
        self.assertEqual(me.status_code, 200)
        self.assertEqual(me.json()["username"], "admin")
        self.assertNotIn("password_hash", me.text)

        bad = self.client.post(
            "/api/v1/control-plane/auth/login",
            json={"username": "admin", "password": "wrong"},
        )
        self.assertEqual(bad.status_code, 401)

        logout = self.client.post(
            "/api/v1/control-plane/auth/logout",
            headers={"x-csrf-token": csrf},
        )
        self.assertEqual(logout.status_code, 200)
        self.assertEqual(self.client.get("/api/v1/control-plane/auth/me").status_code, 401)

    def test_expired_and_revoked_sessions_are_rejected(self) -> None:
        user = self.create_user("admin", "ADMIN")
        self.login("admin")
        with self.Session() as db:
            session = db.query(ControlPlaneSession).filter_by(user_id=user.id).one()
            session.expires_at = datetime.utcnow() - timedelta(seconds=1)
            db.commit()
        self.assertEqual(self.client.get("/api/v1/control-plane/auth/me").status_code, 401)

        self.client = TestClient(app)
        self.login("admin")
        with self.Session() as db:
            session = db.query(ControlPlaneSession).filter_by(user_id=user.id).order_by(ControlPlaneSession.created_at.desc()).first()
            session.revoked_at = datetime.utcnow()
            db.commit()
        self.assertEqual(self.client.get("/api/v1/control-plane/auth/me").status_code, 401)

    def test_disabled_user_cannot_login(self) -> None:
        user = self.create_user("disabled", "VIEWER")
        with self.Session() as db:
            db.get(ControlPlaneUser, user.id).enabled = False
            db.commit()
        response = self.client.post(
            "/api/v1/control-plane/auth/login",
            json={"username": "disabled", "password": "Password123!"},
        )
        self.assertEqual(response.status_code, 401)


class ControlPlaneUserManagementTests(ControlPlaneTestCase):
    def test_admin_can_manage_users_and_reset_password_revokes_sessions(self) -> None:
        self.create_user("admin", "ADMIN")
        csrf = self.login("admin")
        created = self.client.post(
            "/api/v1/control-plane/users",
            json={"username": "viewer", "password": "Password123!", "role": "VIEWER"},
            headers={"x-csrf-token": csrf},
        )
        self.assertEqual(created.status_code, 201, created.text)
        viewer_id = created.json()["id"]

        self.assertEqual(self.client.get("/api/v1/control-plane/users").status_code, 200)
        patch = self.client.patch(
            f"/api/v1/control-plane/users/{viewer_id}",
            json={"role": "ADMIN"},
            headers={"x-csrf-token": csrf},
        )
        self.assertEqual(patch.status_code, 200)
        self.assertEqual(patch.json()["role"], "ADMIN")

        reset = self.client.post(
            f"/api/v1/control-plane/users/{viewer_id}/reset-password",
            json={"new_password": "NewPassword123!", "reason": "operator reset"},
            headers={"x-csrf-token": csrf},
        )
        self.assertEqual(reset.status_code, 200)
        with self.Session() as db:
            audit_text = str([event.before_json for event in db.query(ControlPlaneAuditEvent).all()])
            audit_text += str([event.after_json for event in db.query(ControlPlaneAuditEvent).all()])
            audit_text += str([event.event_metadata for event in db.query(ControlPlaneAuditEvent).all()])
        self.assertNotIn("NewPassword123!", audit_text)
        self.assertNotIn("password_hash", audit_text)

        disable = self.client.post(
            f"/api/v1/control-plane/users/{viewer_id}/disable",
            json={"reason": "test disable"},
            headers={"x-csrf-token": csrf},
        )
        self.assertEqual(disable.status_code, 200)
        enable = self.client.post(
            f"/api/v1/control-plane/users/{viewer_id}/enable",
            headers={"x-csrf-token": csrf},
        )
        self.assertEqual(enable.status_code, 200)
        revoke = self.client.post(
            f"/api/v1/control-plane/users/{viewer_id}/revoke-sessions",
            json={"reason": "test revoke"},
            headers={"x-csrf-token": csrf},
        )
        self.assertEqual(revoke.status_code, 200)

    def test_viewer_cannot_manage_users(self) -> None:
        self.create_user("admin", "ADMIN")
        viewer = self.create_user("viewer", "VIEWER")
        csrf = self.login("viewer")
        self.assertEqual(self.client.get("/api/v1/control-plane/users").status_code, 403)
        self.assertEqual(
            self.client.post(
                "/api/v1/control-plane/users",
                json={"username": "new", "password": "Password123!", "role": "VIEWER"},
                headers={"x-csrf-token": csrf},
            ).status_code,
            403,
        )
        self.assertEqual(
            self.client.patch(
                f"/api/v1/control-plane/users/{viewer.id}",
                json={"role": "ADMIN"},
                headers={"x-csrf-token": csrf},
            ).status_code,
            403,
        )

    def test_last_admin_protection_and_role_change_immediate(self) -> None:
        admin = self.create_user("admin", "ADMIN")
        self.create_user("admin2", "ADMIN")
        csrf = self.login("admin")
        response = self.client.patch(
            f"/api/v1/control-plane/users/{admin.id}",
            json={"role": "VIEWER"},
            headers={"x-csrf-token": csrf},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.client.get("/api/v1/control-plane/users").status_code, 403)

        self.client = TestClient(app)
        csrf = self.login("admin2")
        with self.Session() as db:
            admin2 = db.scalar(db.query(ControlPlaneUser).filter_by(username="admin2").statement)
        response = self.client.patch(
            f"/api/v1/control-plane/users/{admin2.id}",
            json={"role": "VIEWER"},
            headers={"x-csrf-token": csrf},
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("cannot_remove_last_active_admin", response.text)

    def test_concurrent_admin_demotions_leave_one_active_admin(self) -> None:
        admin_a = self.create_user("admin_a", "ADMIN")
        admin_b = self.create_user("admin_b", "ADMIN")
        barrier = threading.Barrier(2)
        results: list[tuple[str, str | None]] = []

        def demote(user_id: str) -> None:
            with self.Session() as db:
                user = db.get(ControlPlaneUser, user_id)
                barrier.wait(timeout=5)
                try:
                    from app.services.control_plane_auth import ensure_not_last_active_admin

                    ensure_not_last_active_admin(db, user)
                    user.role = "VIEWER"
                    db.commit()
                    results.append(("ok", user_id))
                except Exception as exc:
                    db.rollback()
                    results.append(("error", str(exc)))

        threads = [
            threading.Thread(target=demote, args=(admin_a.id,)),
            threading.Thread(target=demote, args=(admin_b.id,)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)

        self.assertEqual(len(results), 2)
        with self.Session() as db:
            active_admin_count = db.query(ControlPlaneUser).filter_by(
                role="ADMIN",
                enabled=True,
            ).count()
        self.assertGreaterEqual(active_admin_count, 1)
        self.assertEqual([status for status, _ in results].count("error"), 1)

    def test_legacy_mutation_routes_require_admin(self) -> None:
        self.create_user("admin", "ADMIN")
        self.create_user("viewer", "VIEWER")
        server_payload = {"name": "srv", "endpoint": "http://127.0.0.1:9000/mcp"}
        tool_payload = {"server_id": 1, "name": "read_file", "input_schema": {"type": "object"}}
        policy_payload = {
            "rule_id": "rule",
            "name": "Rule",
            "decision": "BLOCK",
            "severity": "HIGH",
        }
        cases = [
            ("/api/v1/servers", server_payload),
            ("/api/v1/tools", tool_payload),
            ("/api/v1/policies", policy_payload),
        ]

        for path, payload in cases:
            with self.subTest(path=path):
                self.client = TestClient(app)
                self.assertEqual(self.client.post(path, json=payload).status_code, 401)
                csrf = self.login("viewer")
                self.assertEqual(
                    self.client.post(
                        path,
                        json=payload,
                        headers={"x-csrf-token": csrf},
                    ).status_code,
                    403,
                )
                self.client = TestClient(app)
                csrf = self.login("admin")
                response = self.client.post(
                    path,
                    json=payload,
                    headers={"x-csrf-token": csrf},
                )
                self.assertLess(response.status_code, 400, response.text)

    def test_admin_tool_create_cannot_forge_computed_security_state(self) -> None:
        self.create_user("admin", "ADMIN")
        with self.Session() as db:
            server = MCPServer(
                name="srv",
                server_type="mcp",
                endpoint="http://127.0.0.1:9000/mcp",
                status="active",
            )
            db.add(server)
            db.commit()
            server_id = server.id

        csrf = self.login("admin")
        response = self.client.post(
            "/api/v1/tools",
            json={
                "server_id": server_id,
                "name": "read_file",
                "input_schema": {"type": "object"},
                "analysis_status": "APPROVED",
                "approved_fingerprint_match": True,
                "deterministic_critical_finding": False,
            },
            headers={"x-csrf-token": csrf},
        )

        self.assertEqual(response.status_code, 422, response.text)


class ControlPlaneHumanRouteAuthTests(ControlPlaneTestCase):
    def test_admin_can_archive_server_and_viewer_cannot(self) -> None:
        self.create_user("admin", "ADMIN")
        self.create_user("viewer", "VIEWER")
        with self.Session() as db:
            server = MCPServer(
                name="obsolete",
                server_type="mcp",
                endpoint="https://obsolete.example/mcp",
                status="active",
                trust_status="trusted",
                security_status="approved",
            )
            db.add(server)
            db.commit()
            server_id = server.id

        viewer_csrf = self.login("viewer")
        denied = self.client.post(
            f"/api/v1/servers/{server_id}/archive",
            json={"reason": "No longer operated"},
            headers={"x-csrf-token": viewer_csrf},
        )
        self.assertEqual(denied.status_code, 403, denied.text)

        self.client = TestClient(app)
        csrf = self.login("admin")
        invalid_reason = self.client.post(
            f"/api/v1/servers/{server_id}/archive",
            json={"reason": "   "},
            headers={"x-csrf-token": csrf},
        )
        self.assertEqual(invalid_reason.status_code, 422, invalid_reason.text)
        archived = self.client.post(
            f"/api/v1/servers/{server_id}/archive",
            json={"reason": "No longer operated"},
            headers={"x-csrf-token": csrf},
        )
        self.assertEqual(archived.status_code, 200, archived.text)
        self.assertEqual(archived.json()["status"], "archived")
        self.assertEqual(archived.json()["trust_status"], "archived")
        self.assertEqual(archived.json()["security_status"], "archived")

        with self.Session() as db:
            event = db.scalar(
                select(ControlPlaneAuditEvent).where(
                    ControlPlaneAuditEvent.action == "MCP_SERVER_ARCHIVED"
                )
            )
            self.assertIsNotNone(event)
            self.assertEqual(event.reason, "No longer operated")

    def test_archiving_server_removes_framework_held_credentials(self) -> None:
        self.create_user("admin", "ADMIN")
        with self.Session() as db:
            server = MCPServer(
                name="oauth-server",
                server_type="mcp",
                endpoint="https://oauth.example/mcp",
                auth_mode="OAUTH",
                credential_ref="oauth/tokens/server.json",
                oauth_config={
                    "client_id": "public-client-id",
                    "client_secret_ref": "oauth/clients/server.secret",
                },
                oauth_status="CONNECTED",
                oauth_connected_at=datetime.now(),
                status="active",
                trust_status="trusted",
                security_status="approved",
            )
            db.add(server)
            db.commit()
            server_id = server.id

        csrf = self.login("admin")
        with patch(
            "app.api.routes_servers.delete_upstream_secret"
        ) as delete_secret:
            response = self.client.post(
                f"/api/v1/servers/{server_id}/archive",
                json={"reason": "Provider test completed"},
                headers={"x-csrf-token": csrf},
            )

        self.assertEqual(response.status_code, 200, response.text)
        self.assertCountEqual(
            [call.args[0] for call in delete_secret.call_args_list],
            ["oauth/tokens/server.json", "oauth/clients/server.secret"],
        )
        with self.Session() as db:
            stored = db.get(MCPServer, server_id)
            self.assertEqual(stored.status, "archived")
            self.assertIsNone(stored.credential_ref)
            self.assertNotIn("client_secret_ref", stored.oauth_config)
            self.assertEqual(stored.oauth_config["client_id"], "public-client-id")
            self.assertIsNone(stored.oauth_connected_at)

    def test_admin_can_manage_server_trust_and_viewer_cannot(self) -> None:
        self.create_user("admin", "ADMIN")
        self.create_user("viewer", "VIEWER")
        with self.Session() as db:
            server = MCPServer(
                name="external",
                server_type="mcp",
                endpoint="https://external.example/mcp",
                status="active",
                trust_status="unknown",
                security_status="approved",
            )
            db.add(server)
            db.commit()
            server_id = server.id

        viewer_csrf = self.login("viewer")
        denied = self.client.post(
            f"/api/v1/servers/{server_id}/trust",
            json={"reason": "Reviewed server ownership"},
            headers={"x-csrf-token": viewer_csrf},
        )
        self.assertEqual(denied.status_code, 403, denied.text)

        self.client = TestClient(app)
        csrf = self.login("admin")
        invalid = self.client.post(
            f"/api/v1/servers/{server_id}/trust",
            json={"reason": "  "},
            headers={"x-csrf-token": csrf},
        )
        self.assertEqual(invalid.status_code, 422, invalid.text)

        trusted = self.client.post(
            f"/api/v1/servers/{server_id}/trust",
            json={"reason": "Reviewed server ownership"},
            headers={"x-csrf-token": csrf},
        )
        self.assertEqual(trusted.status_code, 200, trusted.text)
        self.assertEqual(trusted.json()["trust_status"], "trusted")

        revoked = self.client.post(
            f"/api/v1/servers/{server_id}/revoke-trust",
            json={"reason": "Trust review expired"},
            headers={"x-csrf-token": csrf},
        )
        self.assertEqual(revoked.status_code, 200, revoked.text)
        self.assertEqual(revoked.json()["trust_status"], "unknown")

        with self.Session() as db:
            actions = list(
                db.scalars(
                    select(ControlPlaneAuditEvent.action).where(
                        ControlPlaneAuditEvent.target_id == str(server_id)
                    )
                )
            )
            self.assertIn("MCP_SERVER_TRUSTED", actions)
            self.assertIn("MCP_SERVER_TRUST_REVOKED", actions)

    def test_runtime_logs_empty_table_returns_empty_page_for_authenticated_users(self) -> None:
        self.create_user("admin", "ADMIN")
        self.create_user("viewer", "VIEWER")

        for role in ("viewer", "admin"):
            with self.subTest(role=role):
                self.client = TestClient(app)
                self.login(role)
                response = self.client.get("/api/v1/runtime/logs")
                self.assertEqual(response.status_code, 200, response.text)
                self.assertEqual(response.json()["items"], [])
                self.assertFalse(response.json()["has_more"])
                self.assertEqual(response.json()["summary"]["total"], 0)

    def test_runtime_logs_use_cursor_pagination_and_server_side_filters(self) -> None:
        self.create_user("viewer", "VIEWER")
        with self.Session() as db:
            server = MCPServer(
                name="runtime-server",
                server_type="mcp",
                endpoint="http://127.0.0.1:9000/mcp",
                status="active",
            )
            db.add(server)
            db.flush()
            for index in range(5):
                db.add(
                    RuntimeCall(
                        agent_id="agent-a" if index < 4 else "agent-b",
                        session_id=f"session-{index}",
                        server_id=server.id,
                        tool_name="read_file" if index % 2 == 0 else "list_files",
                        status="complete",
                        decision="ALLOW" if index < 3 else "BLOCK",
                        executed=index < 3,
                        execution_status="success" if index < 3 else "skipped",
                        upstream_protocol_profile_id="modern",
                    )
                )
            db.commit()

        self.login("viewer")
        first = self.client.get("/api/v1/runtime/logs?limit=2&agent_id=agent-a")
        self.assertEqual(first.status_code, 200, first.text)
        first_payload = first.json()
        self.assertEqual(len(first_payload["items"]), 2)
        self.assertTrue(first_payload["has_more"])
        self.assertEqual(first_payload["summary"]["total"], 4)
        self.assertEqual(first_payload["summary"]["allowed"], 3)

        second = self.client.get(
            "/api/v1/runtime/logs",
            params={"limit": 2, "agent_id": "agent-a", "cursor": first_payload["next_cursor"]},
        )
        self.assertEqual(second.status_code, 200, second.text)
        second_payload = second.json()
        self.assertEqual(len(second_payload["items"]), 2)
        self.assertFalse(second_payload["has_more"])
        self.assertTrue(
            set(item["id"] for item in first_payload["items"]).isdisjoint(
                item["id"] for item in second_payload["items"]
            )
        )

        blocked = self.client.get("/api/v1/runtime/logs?decision=block")
        self.assertEqual(blocked.status_code, 200, blocked.text)
        self.assertEqual(blocked.json()["summary"]["total"], 2)
        self.assertTrue(all(item["decision"] == "BLOCK" for item in blocked.json()["items"]))
        self.assertEqual(
            self.client.get("/api/v1/runtime/logs?cursor=not-a-cursor").status_code,
            400,
        )

    def test_human_read_routes_require_login_and_allow_admin_and_viewer(self) -> None:
        self.create_user("admin", "ADMIN")
        self.create_user("viewer", "VIEWER")
        with self.Session() as db:
            server = MCPServer(
                name="srv",
                server_type="mcp",
                endpoint="http://127.0.0.1:9000/mcp",
                status="active",
            )
            db.add(server)
            db.flush()
            tool = MCPTool(server_id=server.id, name="read_file", description="Read file.")
            db.add(tool)
            db.commit()
            tool_id = tool.id

        paths = [
            "/api/v1/servers",
            "/api/v1/tools",
            "/api/v1/policies",
            "/api/v1/runtime/logs",
            "/api/v1/control-plane/local-runtime/status",
            "/api/v1/control-plane/audit/events",
            f"/api/v1/tool-analysis/tools/{tool_id}/status",
        ]

        for path in paths:
            with self.subTest(path=path, role="unauthenticated"):
                self.client = TestClient(app)
                self.assertEqual(self.client.get(path).status_code, 401)

            with self.subTest(path=path, role="viewer"):
                self.client = TestClient(app)
                self.login("viewer")
                self.assertEqual(self.client.get(path).status_code, 200)

            with self.subTest(path=path, role="admin"):
                self.client = TestClient(app)
                self.login("admin")
                self.assertEqual(self.client.get(path).status_code, 200)

    def test_runtime_log_ingest_remains_service_to_service_not_human_cookie_auth(self) -> None:
        payload = {
            "agent_id": "agent_demo",
            "session_id": "session-1",
            "tool_name": "read_file",
            "status": "blocked",
            "decision": "BLOCK",
            "executed": False,
        }
        self.assertEqual(
            self.client.post("/api/v1/runtime/logs", json=payload).status_code,
            401,
        )
        response = self.client.post(
            "/api/v1/runtime/logs",
            json=payload,
            headers=self.service_headers(
                SERVICE_ID_PROXY,
                method="POST",
                path="/api/v1/runtime/logs",
                payload=payload,
            ),
        )
        self.assertEqual(response.status_code, 200, response.text)


class ControlPlaneConfigTests(ControlPlaneTestCase):
    def test_revision_lifecycle_hash_provider_and_fail_closed(self) -> None:
        admin = self.create_user("admin", "ADMIN")
        with self.Session() as db:
            content = config_content()
            revision = create_revision(
                db,
                content=content,
                status="PUBLISHED",
                actor=admin,
                change_summary="initial",
            )
            state = ControlPlaneState(id=1, active_revision_id=revision.id)
            db.add(state)
            db.commit()
            provider = PublishedConfigurationProvider(db)
            self.assertEqual(
                provider.get_identity_binding(issuer="issuer", subject="subject").agent_id,
                "agent_demo",
            )
            self.assertEqual(
                provider.get_agent_authorization("agent_demo").authorization_status,
                "resolved",
            )
            revision.content_hash = "0" * 64
            db.commit()
            with self.assertRaises(PublishedConfigurationError):
                PublishedConfigurationProvider(db).get_policy_settings()

    def test_snapshot_stays_atomic_when_new_revision_is_published(self) -> None:
        admin = self.create_user("admin", "ADMIN")
        with self.Session() as db:
            rev1 = create_revision(
                db,
                content=config_content(agent_id="agent_r1", scope_sensitivity="internal"),
                status="PUBLISHED",
                actor=admin,
                change_summary="r1",
            )
            db.add(ControlPlaneState(id=1, active_revision_id=rev1.id))
            db.commit()
            snapshot_r1 = PublishedConfigurationProvider(db).load_active_snapshot()

            rev2 = create_revision(
                db,
                content=config_content(
                    agent_id="agent_r2",
                    required_capability="filesystem.list",
                    scope_sensitivity="confidential",
                ),
                status="DRAFT",
                actor=admin,
                change_summary="r2",
            )
            publish_revision(db, draft_id=rev2.id, actor=admin, change_summary="publish r2")
            db.commit()

            self.assertEqual(snapshot_r1.revision_id, rev1.id)
            self.assertEqual(snapshot_r1.get_identity_binding(issuer="issuer", subject="subject").agent_id, "agent_r1")
            self.assertEqual(
                snapshot_r1.get_agent_authorization("agent_r1").authorization_status,
                "resolved",
            )

            snapshot_r2 = PublishedConfigurationProvider(db).load_active_snapshot()
            self.assertEqual(snapshot_r2.revision_id, rev2.id)
            self.assertEqual(snapshot_r2.get_identity_binding(issuer="issuer", subject="subject").agent_id, "agent_r2")

    def test_historical_snapshot_keeps_its_own_authorization(self) -> None:
        admin = self.create_user("admin", "ADMIN")
        with self.Session() as db:
            rev1 = create_revision(
                db,
                content=config_content(agent_id="agent_r1"),
                status="PUBLISHED",
                actor=admin,
                change_summary="r1",
            )
            db.add(ControlPlaneState(id=1, active_revision_id=rev1.id))
            db.commit()
            rev2 = create_revision(
                db,
                content=config_content(agent_id="agent_r2"),
                status="DRAFT",
                actor=admin,
                change_summary="r2",
            )
            publish_revision(db, draft_id=rev2.id, actor=admin, change_summary="publish r2")
            historical = PublishedConfigurationProvider(db).load_snapshot(
                rev1.id,
                expected_content_hash=rev1.content_hash,
                allow_archived=True,
            )

        self.assertEqual(historical.get_agent_authorization("agent_r1").authorization_status, "resolved")
        self.assertEqual(historical.get_agent_authorization("agent_r2").authorization_status, "unknown")

    def test_policy_settings_are_strictly_validated(self) -> None:
        good = config_content()
        self.assertTrue(good.policy_settings.rules["tool_analysis_required"].enabled)

        bad_severity = config_content().model_dump(mode="json")
        bad_severity["policy_settings"]["rules"]["tool_analysis_required"]["severity"] = "EXTREME"
        with self.assertRaises(Exception):
            ControlPlaneConfigContent.model_validate(bad_severity)

        bad_bool = config_content().model_dump(mode="json")
        bad_bool["policy_settings"]["rules"]["tool_analysis_required"]["enabled"] = "true"
        with self.assertRaises(Exception):
            ControlPlaneConfigContent.model_validate(bad_bool)

        disabled = config_content().model_dump(mode="json")
        disabled["policy_settings"]["rules"]["tool_analysis_required"]["enabled"] = False
        with self.assertRaises(Exception):
            ControlPlaneConfigContent.model_validate(disabled)

        unknown_field = config_content().model_dump(mode="json")
        unknown_field["policy_settings"]["rules"]["tool_analysis_required"]["unexpected"] = True
        with self.assertRaises(Exception):
            ControlPlaneConfigContent.model_validate(unknown_field)

        unsupported_rule = config_content().model_dump(mode="json")
        unsupported_rule["policy_settings"]["rules"]["unimplemented_rule"] = {
            "enabled": True,
            "severity": "LOW",
        }
        with self.assertRaises(Exception):
            ControlPlaneConfigContent.model_validate(unsupported_rule)

        arbitrary = config_content().model_dump(mode="json")
        arbitrary["policy_settings"] = {"anything": {"goes": True}}
        with self.assertRaises(Exception):
            ControlPlaneConfigContent.model_validate(arbitrary)

    def test_config_routes_draft_publish_rollback_and_immutability(self) -> None:
        admin = self.create_user("admin", "ADMIN")
        csrf = self.login("admin")
        with self.Session() as db:
            published = create_revision(
                db,
                content=config_content(),
                status="PUBLISHED",
                actor=admin,
                change_summary="initial",
            )
            db.add(ControlPlaneState(id=1, active_revision_id=published.id))
            db.commit()
            published_id = published.id

        draft = self.client.post(
            f"/api/v1/control-plane/config/revisions/{published_id}/draft",
            json={"change_summary": "prepare update"},
            headers={"x-csrf-token": csrf},
        )
        self.assertEqual(draft.status_code, 201, draft.text)
        draft_id = draft.json()["id"]
        patch_published = self.client.patch(
            f"/api/v1/control-plane/config/revisions/{published_id}",
            json={
                "content": config_content().model_dump(mode="json"),
                "change_summary": "should fail",
            },
            headers={"x-csrf-token": csrf},
        )
        self.assertEqual(patch_published.status_code, 400)
        validate = self.client.post(
            f"/api/v1/control-plane/config/revisions/{draft_id}/validate",
            json={"change_summary": "validate"},
            headers={"x-csrf-token": csrf},
        )
        self.assertEqual(validate.status_code, 200, validate.text)
        publish = self.client.post(
            f"/api/v1/control-plane/config/revisions/{draft_id}/publish",
            json={"change_summary": "publish"},
            headers={"x-csrf-token": csrf},
        )
        self.assertEqual(publish.status_code, 200, publish.text)
        self.assertEqual(publish.json()["status"], "PUBLISHED")
        rollback = self.client.post(
            f"/api/v1/control-plane/config/revisions/{published_id}/rollback",
            json={"change_summary": "rollback"},
            headers={"x-csrf-token": csrf},
        )
        self.assertEqual(rollback.status_code, 200, rollback.text)

    def test_concurrent_publish_serializes_and_leaves_one_published_revision(self) -> None:
        admin = self.create_user("admin", "ADMIN")
        with self.Session() as db:
            rev1 = create_revision(
                db,
                content=config_content(agent_id="agent_r1"),
                status="PUBLISHED",
                actor=admin,
                change_summary="r1",
            )
            db.add(ControlPlaneState(id=1, active_revision_id=rev1.id))
            db.commit()

            rev2 = create_revision(
                db,
                content=config_content(agent_id="agent_r2"),
                status="DRAFT",
                actor=admin,
                change_summary="r2",
            )
            rev3 = create_revision(
                db,
                content=config_content(agent_id="agent_r3"),
                status="DRAFT",
                actor=admin,
                change_summary="r3",
            )
            db.commit()
            draft_ids = [rev2.id, rev3.id]
            admin_id = admin.id

        barrier = threading.Barrier(2)
        results: list[tuple[str, str]] = []

        def publish(draft_id: str) -> None:
            with self.Session() as db:
                actor = db.get(ControlPlaneUser, admin_id)
                barrier.wait(timeout=5)
                try:
                    published = publish_revision(
                        db,
                        draft_id=draft_id,
                        actor=actor,
                        change_summary=f"publish {draft_id}",
                    )
                    db.commit()
                    results.append(("ok", published.id))
                except Exception as exc:
                    db.rollback()
                    results.append(("error", str(exc)))

        threads = [threading.Thread(target=publish, args=(draft_id,)) for draft_id in draft_ids]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)

        self.assertEqual(len(results), 2)
        with self.Session() as db:
            published = db.query(ControlPlaneConfigRevision).filter_by(status="PUBLISHED").all()
            state = db.get(ControlPlaneState, 1)
        self.assertEqual(len(published), 1)
        self.assertEqual(state.active_revision_id, published[0].id)
        self.assertIn(published[0].id, {value for status, value in results if status == "ok"})

    def test_concurrent_publish_and_rollback_serialize_to_one_published_revision(self) -> None:
        admin = self.create_user("admin", "ADMIN")
        with self.Session() as db:
            rev1 = create_revision(
                db,
                content=config_content(agent_id="agent_r1"),
                status="PUBLISHED",
                actor=admin,
                change_summary="r1",
            )
            db.add(ControlPlaneState(id=1, active_revision_id=rev1.id))
            db.commit()
            rev1_id = rev1.id

            rev2 = create_revision(
                db,
                content=config_content(agent_id="agent_r2"),
                status="DRAFT",
                actor=admin,
                change_summary="r2",
            )
            publish_revision(db, draft_id=rev2.id, actor=admin, change_summary="publish r2")
            db.commit()

            rev3 = create_revision(
                db,
                content=config_content(agent_id="agent_r3"),
                status="DRAFT",
                actor=admin,
                change_summary="r3",
            )
            db.commit()
            rev3_id = rev3.id
            admin_id = admin.id

        barrier = threading.Barrier(2)
        results: list[tuple[str, str]] = []

        def publish_draft() -> None:
            with self.Session() as db:
                actor = db.get(ControlPlaneUser, admin_id)
                barrier.wait(timeout=5)
                try:
                    published = publish_revision(
                        db,
                        draft_id=rev3_id,
                        actor=actor,
                        change_summary="publish r3",
                    )
                    db.commit()
                    results.append(("publish", published.id))
                except Exception as exc:
                    db.rollback()
                    results.append(("publish_error", str(exc)))

        def rollback_revision() -> None:
            with self.Session() as db:
                actor = db.get(ControlPlaneUser, admin_id)
                barrier.wait(timeout=5)
                try:
                    published = rollback_to_revision(
                        db,
                        revision_id=rev1_id,
                        actor=actor,
                        change_summary="rollback r1",
                    )
                    db.commit()
                    results.append(("rollback", published.id))
                except Exception as exc:
                    db.rollback()
                    results.append(("rollback_error", str(exc)))

        threads = [threading.Thread(target=publish_draft), threading.Thread(target=rollback_revision)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)

        self.assertEqual(len(results), 2)
        with self.Session() as db:
            published = db.query(ControlPlaneConfigRevision).filter_by(status="PUBLISHED").all()
            state = db.get(ControlPlaneState, 1)
        self.assertEqual(len(published), 1)
        self.assertEqual(state.active_revision_id, published[0].id)

    def test_concurrent_draft_creation_allocates_unique_revision_numbers(self) -> None:
        admin = self.create_user("admin", "ADMIN")
        with self.Session() as db:
            rev1 = create_revision(
                db,
                content=config_content(),
                status="PUBLISHED",
                actor=admin,
                change_summary="r1",
            )
            db.add(ControlPlaneState(id=1, active_revision_id=rev1.id))
            db.commit()
            rev1_id = rev1.id
            admin_id = admin.id

        barrier = threading.Barrier(2)
        results: list[tuple[str, int | str]] = []

        def create_draft(summary: str) -> None:
            with self.Session() as db:
                actor = db.get(ControlPlaneUser, admin_id)
                barrier.wait(timeout=5)
                try:
                    draft = create_draft_from_revision(
                        db,
                        published_revision_id=rev1_id,
                        actor=actor,
                        change_summary=summary,
                    )
                    db.commit()
                    results.append(("ok", draft.revision_number))
                except Exception as exc:
                    db.rollback()
                    results.append(("error", str(exc)))

        threads = [
            threading.Thread(target=create_draft, args=("draft a",)),
            threading.Thread(target=create_draft, args=("draft b",)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)

        self.assertEqual(len(results), 2)
        numbers = [number for status, number in results if status == "ok"]
        self.assertEqual(len(numbers), 2, results)
        self.assertEqual(len(set(numbers)), 2)


class ControlPlaneToolAnalysisTests(ControlPlaneTestCase):
    def test_oauth_error_configuration_can_be_reconfigured_without_duplicate_server(self) -> None:
        self.create_user("admin", "ADMIN")
        csrf = self.login("admin")
        with self.Session() as db:
            server = MCPServer(
                name="github-mcp",
                server_type="mcp",
                endpoint="https://api.githubcopilot.com/mcp/",
                transport="streamable_http",
                auth_mode="OAUTH",
                credential_ref="oauth/tokens/github.json",
                oauth_config={"requested_scopes": []},
                oauth_status="OAUTH_ERROR",
                oauth_last_error="upstream_oauth_dynamic_registration_unsupported",
                status="active",
            )
            db.add(server)
            db.commit()
            server_id = server.id

        response = self.client.post(
            "/api/v1/control-plane/upstream-oauth/servers",
            json={
                "endpoint": "https://api.githubcopilot.com/mcp/",
                "protocol_version": "2026-07-28",
                "client_id": "github-issued-client",
                "requested_scopes": "repo read:org",
            },
            headers={"x-csrf-token": csrf},
        )

        self.assertEqual(response.status_code, 201, response.text)
        self.assertEqual(response.json()["id"], server_id)
        self.assertEqual(response.json()["oauth_status"], "OAUTH_CONFIGURED")
        self.assertIsNone(response.json()["oauth_last_error"])
        with self.Session() as db:
            stored = db.get(MCPServer, server_id)
            self.assertEqual(stored.oauth_config["client_id"], "github-issued-client")
            self.assertEqual(stored.oauth_config["requested_scopes"], ["repo", "read:org"])
            self.assertEqual(
                db.scalar(
                    select(ControlPlaneAuditEvent).where(
                        ControlPlaneAuditEvent.action == "UPSTREAM_OAUTH_SERVER_RECONFIGURED"
                    )
                ).target_id,
                str(server_id),
            )

    def _seed_tool_analysis_fixture(self) -> tuple[int, int]:
        with self.Session() as db:
            server = MCPServer(
                name="local-mcp",
                server_type="mcp",
                endpoint="http://127.0.0.1:9000/mcp",
                transport="streamable_http",
                status="active",
                security_status="review_required",
            )
            db.add(server)
            db.flush()
            tool = MCPTool(
                server_id=server.id,
                name="read_file",
                title="Read File",
                description="Read a file.",
                current_fingerprint="a" * 64,
                analysis_status="REVIEW_REQUIRED",
                risk_score=40,
                risk_level="medium",
                review_status="REVIEW_REQUIRED",
            )
            db.add(tool)
            db.flush()
            version = ToolObservedVersion(
                tool_id=tool.id,
                server_ref=SERVER_REF,
                tool_name=tool.name,
                fingerprint="a" * 64,
                status="new",
                snapshot={"description": "Read a file.", "input_schema": {}},
                profile_snapshot={"revision": "test"},
                profile_revision="test",
            )
            db.add(version)
            db.flush()
            analysis = ToolAnalysis(
                tool_id=tool.id,
                version_id=version.id,
                fingerprint="a" * 64,
                analysis_context_hash="c" * 64,
                analysis_status="REVIEW_REQUIRED",
                risk_score=40,
                risk_level="medium",
                semantic_flagged="false",
                deterministic_critical_finding="false",
                consistency_status="consistent",
                drift_status="NONE",
                review_status="REVIEW_REQUIRED",
                semantic_scores={"scores": {"normal_tool_description": 0.8}},
                consistency_result={"status": "consistent", "findings": []},
                drift_result={"status": "NONE", "changes": [], "similarity": None},
                model_versions={"semantic": {"name": "mock", "version": "1"}},
                analyzer_revision=ANALYZER_REVISION,
                completed_at=datetime.utcnow(),
            )
            db.add(analysis)
            db.flush()
            db.add(
                ToolAnalysisFinding(
                    analysis_id=analysis.id,
                    code="schema_profile_mismatch",
                    category="consistency",
                    source="profile",
                    severity="MEDIUM",
                    confidence=90,
                    evidence={"field": "path"},
                    recommendation="Review the declared profile.",
                )
            )
            db.commit()
            return tool.id, analysis.id

    def test_tool_findings_route_handles_empty_and_seeded_analyses(self) -> None:
        self.create_user("viewer", "VIEWER")
        viewer_csrf = self.login("viewer")
        with self.Session() as db:
            server = MCPServer(
                name="empty-server",
                server_type="mcp",
                endpoint="http://127.0.0.1:9100/mcp",
                transport="streamable_http",
                status="active",
            )
            db.add(server)
            db.flush()
            empty_tool = MCPTool(server_id=server.id, name="empty_tool")
            db.add(empty_tool)
            db.commit()
            empty_tool_id = empty_tool.id

        empty = self.client.get(
            f"/api/v1/tool-analysis/tools/{empty_tool_id}/findings",
            headers={"x-csrf-token": viewer_csrf},
        )
        self.assertEqual(empty.status_code, 200, empty.text)
        self.assertEqual(empty.json(), [])

        tool_id, _analysis_id = self._seed_tool_analysis_fixture()
        response = self.client.get(
            f"/api/v1/tool-analysis/tools/{tool_id}/findings",
            headers={"x-csrf-token": viewer_csrf},
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual([finding["code"] for finding in response.json()], ["schema_profile_mismatch"])

    def test_tool_findings_route_returns_all_tool_findings_without_cross_tool_leak(self) -> None:
        self.create_user("admin", "ADMIN")
        self.login("admin")
        tool_id, analysis_id = self._seed_tool_analysis_fixture()
        with self.Session() as db:
            tool = db.get(MCPTool, tool_id)
            assert tool is not None
            version = ToolObservedVersion(
                tool_id=tool.id,
                server_ref=SERVER_REF,
                tool_name=tool.name,
                fingerprint="b" * 64,
                status="changed",
                snapshot={"description": "Read a file safely.", "input_schema": {}},
                profile_snapshot={"revision": "test"},
                profile_revision="test",
            )
            db.add(version)
            db.flush()
            second_analysis = ToolAnalysis(
                tool_id=tool.id,
                version_id=version.id,
                fingerprint="b" * 64,
                analysis_context_hash="d" * 64,
                analysis_status="REVIEW_REQUIRED",
                risk_score=60,
                risk_level="medium",
                semantic_flagged="false",
                deterministic_critical_finding="false",
                consistency_status="mismatch",
                drift_status="MEDIUM",
                review_status="REVIEW_REQUIRED",
                semantic_scores={},
                consistency_result={},
                drift_result={"status": "MEDIUM"},
                model_versions={},
                analyzer_revision=ANALYZER_REVISION,
                completed_at=datetime.utcnow(),
            )
            db.add(second_analysis)
            db.flush()
            db.add(
                ToolAnalysisFinding(
                    analysis_id=second_analysis.id,
                    code="schema_description_mismatch",
                    category="consistency",
                    source="schema",
                    severity="MEDIUM",
                    confidence=80,
                    evidence={"field": "destination_url"},
                    recommendation="Review schema capability.",
                )
            )
            other_tool = MCPTool(server_id=tool.server_id, name="other_tool")
            db.add(other_tool)
            db.flush()
            other_version = ToolObservedVersion(
                tool_id=other_tool.id,
                server_ref=SERVER_REF,
                tool_name=other_tool.name,
                fingerprint="e" * 64,
                status="new",
                snapshot={"description": "Other.", "input_schema": {}},
                profile_snapshot={"revision": "test"},
                profile_revision="test",
            )
            db.add(other_version)
            db.flush()
            other_analysis = ToolAnalysis(
                tool_id=other_tool.id,
                version_id=other_version.id,
                fingerprint="e" * 64,
                analysis_context_hash="f" * 64,
                analysis_status="BLOCKED",
                risk_score=100,
                risk_level="critical",
                semantic_flagged="false",
                deterministic_critical_finding="true",
                consistency_status="mismatch",
                drift_status="CRITICAL",
                review_status="BLOCKED",
                semantic_scores={},
                consistency_result={},
                drift_result={},
                model_versions={},
                analyzer_revision=ANALYZER_REVISION,
                completed_at=datetime.utcnow(),
            )
            db.add(other_analysis)
            db.flush()
            db.add(
                ToolAnalysisFinding(
                    analysis_id=other_analysis.id,
                    code="other_tool_finding",
                    category="static",
                    source="description",
                    severity="CRITICAL",
                    confidence=100,
                    evidence={"snippet": "ignored"},
                    recommendation="Block.",
                )
            )
            db.commit()

        response = self.client.get(f"/api/v1/tool-analysis/tools/{tool_id}/findings")
        self.assertEqual(response.status_code, 200, response.text)
        codes = {finding["code"] for finding in response.json()}
        self.assertEqual(codes, {"schema_profile_mismatch", "schema_description_mismatch"})
        self.assertNotIn("other_tool_finding", codes)

        for suffix in ("status", "analyses", "findings", "versions", "baseline", "diff"):
            with self.subTest(suffix=suffix):
                route = f"/api/v1/tool-analysis/tools/{tool_id}/{suffix}"
                route_response = self.client.get(route)
                self.assertNotEqual(route_response.status_code, 500, route_response.text)
                self.assertIn(route_response.status_code, {200, 404})

        detail = self.client.get(f"/api/v1/control-plane/tool-analysis/analyses/{analysis_id}")
        self.assertEqual(detail.status_code, 200, detail.text)

    def test_control_center_read_api_smoke_has_no_500s_for_admin_or_viewer(self) -> None:
        self.create_user("admin", "ADMIN")
        self.create_user("viewer", "VIEWER")
        tool_id, _analysis_id = self._seed_tool_analysis_fixture()
        admin_routes = [
            "/api/v1/health",
            "/api/v1/control-plane/local-runtime/status",
            "/api/v1/servers",
            "/api/v1/tools",
            "/api/v1/policies",
            "/api/v1/runtime/logs",
            "/api/v1/control-plane/tool-analysis/analyses",
            "/api/v1/control-plane/config/revisions",
            "/api/v1/control-plane/config/active",
            "/api/v1/control-plane/emergency-denies",
            "/api/v1/control-plane/audit/events",
            "/api/v1/control-plane/users",
            f"/api/v1/tool-analysis/tools/{tool_id}/status",
            f"/api/v1/tool-analysis/tools/{tool_id}/analyses",
            f"/api/v1/tool-analysis/tools/{tool_id}/findings",
            f"/api/v1/tool-analysis/tools/{tool_id}/versions",
            f"/api/v1/tool-analysis/tools/{tool_id}/baseline",
            f"/api/v1/tool-analysis/tools/{tool_id}/diff",
        ]
        self.login("admin")
        for route in admin_routes:
            with self.subTest(role="ADMIN", route=route):
                response = self.client.get(route)
                self.assertNotEqual(response.status_code, 500, response.text)
                self.assertEqual(response.status_code, 200, response.text)

        self.client = TestClient(app)
        self.login("viewer")
        viewer_routes = [route for route in admin_routes if route != "/api/v1/control-plane/users"]
        for route in viewer_routes:
            with self.subTest(role="VIEWER", route=route):
                response = self.client.get(route)
                self.assertNotEqual(response.status_code, 500, response.text)
                self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(self.client.get("/api/v1/control-plane/users").status_code, 403)

    def test_server_scan_timestamp_and_security_metadata_aggregate_tool_states(self) -> None:
        scenarios = [
            (["APPROVED", "APPROVED"], "approved"),
            (["APPROVED", "REVIEW_REQUIRED"], "review_required"),
            (["APPROVED", "QUARANTINED"], "review_required"),
            (["APPROVED", "ANALYSIS_FAILED"], "analysis_failed"),
            (["APPROVED", "BLOCKED"], "blocked"),
            (["PENDING_ANALYSIS"], "pending_analysis"),
        ]
        for statuses, expected in scenarios:
            with self.subTest(statuses=statuses):
                now = datetime.utcnow()
                with self.Session() as db:
                    server = MCPServer(
                        name=f"server-{expected}-{len(statuses)}",
                        server_type="mcp",
                        endpoint=f"http://127.0.0.1:{9200 + len(statuses)}/mcp/{expected}",
                        transport="streamable_http",
                        status="active",
                        security_status="pending_analysis",
                    )
                    db.add(server)
                    db.flush()
                    for index, status_value in enumerate(statuses):
                        db.add(
                            MCPTool(
                                server_id=server.id,
                                name=f"tool_{index}",
                                analysis_status=status_value,
                            )
                        )
                    db.flush()
                    refresh_server_security_status(db, server.id, scanned_at=now)
                    db.flush()
                    server_id = server.id
                    db.commit()

                with self.Session() as db:
                    stored = db.get(MCPServer, server_id)
                    self.assertEqual(stored.security_status, expected)
                    self.assertEqual(stored.last_scan_at, now)

    def _seed_reviewable_tool(
        self,
        *,
        server_status: str,
        tool_status: str,
        analysis_status: str,
        fingerprint: str,
        last_scan_at: datetime,
    ) -> tuple[int, int]:
        with self.Session() as db:
            port = 9300 if fingerprint.startswith("a") else 9301
            server = MCPServer(
                name=f"review-server-{fingerprint[:4]}",
                server_type="mcp",
                endpoint=f"http://127.0.0.1:{port}/mcp",
                transport="streamable_http",
                status="active",
                security_status=server_status,
                last_scan_at=last_scan_at,
            )
            db.add(server)
            db.flush()
            tool = MCPTool(
                server_id=server.id,
                name="read_file",
                description="Read file.",
                current_fingerprint=fingerprint,
                analysis_status=tool_status,
                review_status=analysis_status,
            )
            db.add(tool)
            db.flush()
            version = ToolObservedVersion(
                tool_id=tool.id,
                server_ref=SERVER_REF,
                tool_name=tool.name,
                fingerprint=fingerprint,
                status="new",
                snapshot={"description": "Read file.", "input_schema": {}},
                profile_snapshot={"revision": "test"},
                profile_revision="test",
            )
            db.add(version)
            db.flush()
            analysis = ToolAnalysis(
                tool_id=tool.id,
                version_id=version.id,
                fingerprint=fingerprint,
                analysis_context_hash="c" * 64,
                analysis_status=analysis_status,
                risk_score=10,
                risk_level="low",
                semantic_flagged="false",
                deterministic_critical_finding="false",
                consistency_status="consistent",
                drift_status="NONE",
                review_status=analysis_status,
                semantic_scores={"scores": {"normal_tool_description": 0.9}},
                consistency_result={"status": "consistent", "findings": []},
                drift_result={"status": "NONE", "changes": [], "similarity": None},
                model_versions={"semantic": {"name": "mock", "version": "1"}},
                analyzer_revision=ANALYZER_REVISION,
                completed_at=datetime.utcnow(),
            )
            db.add(analysis)
            db.commit()
            return server.id, tool.id

    def test_tool_approval_refreshes_parent_server_without_scan_timestamp(self) -> None:
        self.create_user("admin", "ADMIN")
        last_scan_at = datetime(2026, 1, 1, 12, 0, 0)
        server_id, tool_id = self._seed_reviewable_tool(
            server_status="review_required",
            tool_status="REVIEW_REQUIRED",
            analysis_status="REVIEW_REQUIRED",
            fingerprint="a" * 64,
            last_scan_at=last_scan_at,
        )

        csrf = self.login("admin")
        response = self.client.post(
            f"/api/v1/control-plane/tool-analysis/tools/{tool_id}/approve",
            json={"fingerprint": "a" * 64, "justification": "reviewed safe read"},
            headers={"x-csrf-token": csrf},
        )
        self.assertEqual(response.status_code, 200, response.text)

        with self.Session() as db:
            server = db.get(MCPServer, server_id)
            self.assertEqual(server.security_status, "approved")
            self.assertEqual(server.last_scan_at, last_scan_at)

    def test_tool_block_refreshes_parent_server_without_scan_timestamp(self) -> None:
        self.create_user("admin", "ADMIN")
        last_scan_at = datetime(2026, 1, 1, 12, 0, 0)
        server_id, tool_id = self._seed_reviewable_tool(
            server_status="approved",
            tool_status="APPROVED",
            analysis_status="APPROVED",
            fingerprint="b" * 64,
            last_scan_at=last_scan_at,
        )

        csrf = self.login("admin")
        response = self.client.post(
            f"/api/v1/control-plane/tool-analysis/tools/{tool_id}/block",
            json={"fingerprint": "b" * 64, "justification": "blocked after review"},
            headers={"x-csrf-token": csrf},
        )
        self.assertEqual(response.status_code, 200, response.text)

        with self.Session() as db:
            server = db.get(MCPServer, server_id)
            self.assertEqual(server.security_status, "blocked")
            self.assertEqual(server.last_scan_at, last_scan_at)

    def test_admin_can_trigger_governed_discovery_through_backend(self) -> None:
        self.create_user("viewer", "VIEWER")
        admin = self.create_user("admin", "ADMIN")
        discovery_payload = {
            "payload": {
                "server": {
                    "endpoint": "http://127.0.0.1:9000/mcp",
                    "transport": "streamable_http",
                    "protocol_version": "2025-11-25",
                    "auth_mode": "BEARER",
                    "credential_ref": "mcp/vendor/service.token",
                },
                "tools": [
                    {
                        "name": "read_file",
                        "description": "Read a file.",
                        "input_schema": {
                            "type": "object",
                            "properties": {"path": {"type": "string"}},
                            "required": ["path"],
                            "additionalProperties": False,
                        },
                    }
                ],
            },
            "tool_names": ["read_file"],
        }
        with self.Session() as db:
            revision = create_revision(
                db,
                content=config_content(),
                status="PUBLISHED",
                actor=admin,
                change_summary="initial",
            )
            db.add(ControlPlaneState(id=1, active_revision_id=revision.id))
            db.commit()

        class FakeAnalysis:
            analysis_status = "REVIEW_REQUIRED"

        class FakeToolAnalysisService:
            def observe_and_analyze(self, **kwargs):
                kwargs["tool"].analysis_status = "REVIEW_REQUIRED"
                kwargs["tool"].review_status = "REVIEW_REQUIRED"
                return FakeAnalysis()

        viewer_csrf = self.login("viewer")
        viewer_response = self.client.post(
            "/api/v1/inventory/discover-http",
            json={
                "endpoint": "http://127.0.0.1:9000/mcp",
                "auth_mode": "BEARER",
                "credential_ref": "mcp/vendor/service.token",
            },
            headers={"x-csrf-token": viewer_csrf},
        )
        self.assertEqual(viewer_response.status_code, 403)

        self.client = TestClient(app)
        admin_csrf = self.login("admin")
        with (
            patch(
                "app.api.routes_inventory.discover_http_mcp_server",
                return_value=discovery_payload,
            ) as discovery,
            patch(
                "app.api.routes_inventory.ToolAnalysisService",
                return_value=FakeToolAnalysisService(),
            ),
        ):
            response = self.client.post(
                "/api/v1/inventory/discover-http",
                json={
                    "endpoint": "http://127.0.0.1:9000/mcp",
                    "auth_mode": "BEARER",
                    "credential_ref": "mcp/vendor/service.token",
                },
                headers={"x-csrf-token": admin_csrf},
            )

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["total_tools_imported"], 1)
        discovery.assert_called_once()
        self.assertEqual(discovery.call_args.kwargs["auth_mode"], "BEARER")
        self.assertEqual(
            discovery.call_args.kwargs["credential_ref"],
            "mcp/vendor/service.token",
        )
        with self.Session() as db:
            self.assertEqual(db.query(MCPServer).count(), 1)
            self.assertEqual(db.query(MCPTool).count(), 1)
            server = db.query(MCPServer).one()
            self.assertEqual(server.auth_mode, "BEARER")
            self.assertEqual(server.credential_ref, "mcp/vendor/service.token")
            self.assertIsNotNone(server.last_scan_at)
            self.assertGreaterEqual(server.last_scan_at, server.last_seen_at)
            self.assertEqual(server.security_status, "review_required")
            audit_events = db.query(ControlPlaneAuditEvent).all()
            audit_actions = [event.action for event in audit_events]
            discovery_audit = next(
                event for event in audit_events if event.action == "MCP_DISCOVERY_IMPORTED"
            )
        self.assertIn("MCP_DISCOVERY_IMPORTED", audit_actions)
        self.assertNotIn("credential_ref", discovery_audit.after_json)
        self.assertNotIn("service.token", str(discovery_audit.after_json))

    def test_inventory_import_requires_service_token_and_published_config_profile(self) -> None:
        payload = {
            "server": {
                "endpoint": "http://127.0.0.1:9000/mcp",
                "transport": "streamable_http",
                "protocol_version": "2025-11-25",
            },
            "tools": [
                {
                    "name": "read_file",
                    "description": "Read a file.",
                    "input_schema": {
                        "type": "object",
                        "properties": {"path": {"type": "string"}},
                        "required": ["path"],
                        "additionalProperties": False,
                    },
                }
            ],
        }

        self.assertEqual(
            self.client.post("/api/v1/inventory/import-discovery", json=payload).status_code,
            401,
        )
        self.assertEqual(
            self.client.post(
                "/api/v1/inventory/import-discovery",
                json=payload,
                headers={"X-MCP-Discovery-Token": "test-import-token"},
            ).status_code,
            401,
        )

        admin = self.create_user("admin", "ADMIN")
        with self.Session() as db:
            revision = create_revision(
                db,
                content=config_content(),
                status="PUBLISHED",
                actor=admin,
                change_summary="initial",
            )
            db.add(ControlPlaneState(id=1, active_revision_id=revision.id))
            db.commit()

        seen_profiles = []

        class FakeAnalysis:
            analysis_status = "REVIEW_REQUIRED"

        class FakeToolAnalysisService:
            def observe_and_analyze(self, *, profile_snapshot, **kwargs):
                seen_profiles.append(profile_snapshot)
                return FakeAnalysis()

        with patch(
            "app.api.routes_inventory.ToolAnalysisService",
            return_value=FakeToolAnalysisService(),
        ):
            response = self.client.post(
                "/api/v1/inventory/import-discovery",
                json=payload,
                headers=self.service_headers(
                    SERVICE_ID_DISCOVERY,
                    method="POST",
                    path="/api/v1/inventory/import-discovery",
                    payload=payload,
                ),
            )

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(seen_profiles, [None])

    def test_bootstrapped_published_config_allows_initial_discovery_import(self) -> None:
        payload = {
            "server": {
                "endpoint": "http://127.0.0.1:9000/mcp",
                "transport": "streamable_http",
                "protocol_version": "2025-11-25",
            },
            "tools": [
                {
                    "name": "read_file",
                    "description": "Read a file.",
                    "input_schema": {
                        "type": "object",
                        "properties": {"path": {"type": "string"}},
                        "required": ["path"],
                        "additionalProperties": False,
                    },
                },
                {
                    "name": "list_files",
                    "description": "List files.",
                    "input_schema": {
                        "type": "object",
                        "properties": {"path": {"type": "string"}},
                        "additionalProperties": False,
                    },
                },
                {
                    "name": "read_file",
                    "description": "Read a file.",
                    "input_schema": {
                        "type": "object",
                        "properties": {"path": {"type": "string"}},
                        "required": ["path"],
                        "additionalProperties": False,
                    },
                    "upstream_protocol_profile_id": "mcp-modern-2026-07-28-restricted-v1",
                },
            ],
        }
        with self.Session() as db:
            result = ensure_initial_published_configuration(db)
            db.commit()
            self.assertEqual(result.status, "IMPORTED")
            PublishedConfigurationProvider(db).load_active_snapshot()

        seen_profiles = []

        class FakeAnalysis:
            analysis_status = "REVIEW_REQUIRED"

        class FakeToolAnalysisService:
            def observe_and_analyze(self, *, profile_snapshot, **kwargs):
                seen_profiles.append(profile_snapshot)
                kwargs["tool"].analysis_status = "REVIEW_REQUIRED"
                kwargs["tool"].review_status = "REVIEW_REQUIRED"
                return FakeAnalysis()

        with patch(
            "app.api.routes_inventory.ToolAnalysisService",
            return_value=FakeToolAnalysisService(),
        ):
            response = self.client.post(
                "/api/v1/inventory/import-discovery",
                json=payload,
                headers=self.service_headers(
                    SERVICE_ID_DISCOVERY,
                    method="POST",
                    path="/api/v1/inventory/import-discovery",
                    payload=payload,
                ),
            )

        self.assertEqual(response.status_code, 200, response.text)
        self.assertNotEqual(response.json(), {"detail": "published_configuration_unavailable"})
        self.assertEqual(response.json()["total_tools_imported"], 2)
        self.assertEqual(seen_profiles, [None, None, None])

    def test_rediscovery_updates_existing_tool_and_preserves_analysis_history(self) -> None:
        admin = self.create_user("admin", "ADMIN")
        with self.Session() as db:
            revision = create_revision(
                db,
                content=config_content(),
                status="PUBLISHED",
                actor=admin,
                change_summary="initial",
            )
            db.add(ControlPlaneState(id=1, active_revision_id=revision.id))
            db.commit()

        payload = {
            "server": {
                "endpoint": "http://127.0.0.1:9000/mcp",
                "transport": "streamable_http",
                "protocol_version": "2025-11-25",
            },
            "tools": [
                {
                    "name": "read_file",
                    "description": "Read a file.",
                    "input_schema": {
                        "type": "object",
                        "properties": {"path": {"type": "string"}},
                        "required": ["path"],
                        "additionalProperties": False,
                    },
                }
            ],
        }
        observation_counter = {"value": 0}

        class FakeToolAnalysisService:
            def observe_and_analyze(self, *, db, tool, **_kwargs):
                observation_counter["value"] += 1
                fingerprint = f"{observation_counter['value']:064d}"
                tool.current_fingerprint = fingerprint
                tool.analysis_status = "REVIEW_REQUIRED"
                tool.review_status = "REVIEW_REQUIRED"
                version = ToolObservedVersion(
                    tool_id=tool.id,
                    server_ref=SERVER_REF,
                    tool_name=tool.name,
                    fingerprint=fingerprint,
                    status="observed",
                    snapshot={"description": tool.description, "input_schema": tool.input_schema},
                    profile_snapshot={"revision": "test"},
                    profile_revision="test",
                )
                db.add(version)
                db.flush()
                analysis = ToolAnalysis(
                    tool_id=tool.id,
                    version_id=version.id,
                    fingerprint=fingerprint,
                    analysis_context_hash=fingerprint,
                    analysis_status="REVIEW_REQUIRED",
                    risk_score=20,
                    risk_level="low",
                    semantic_flagged="false",
                    deterministic_critical_finding="false",
                    consistency_status="consistent",
                    drift_status="NONE",
                    review_status="REVIEW_REQUIRED",
                    semantic_scores={},
                    consistency_result={},
                    drift_result={},
                    model_versions={},
                    analyzer_revision=ANALYZER_REVISION,
                    completed_at=datetime.utcnow(),
                )
                db.add(analysis)
                db.flush()
                return analysis

        with patch(
            "app.api.routes_inventory.ToolAnalysisService",
            return_value=FakeToolAnalysisService(),
        ):
            first = self.client.post(
                "/api/v1/inventory/import-discovery",
                json=payload,
                headers=self.service_headers(
                    SERVICE_ID_DISCOVERY,
                    method="POST",
                    path="/api/v1/inventory/import-discovery",
                    payload=payload,
                ),
            )
            second = self.client.post(
                "/api/v1/inventory/import-discovery",
                json=payload,
                headers=self.service_headers(
                    SERVICE_ID_DISCOVERY,
                    method="POST",
                    path="/api/v1/inventory/import-discovery",
                    payload=payload,
                ),
            )

        self.assertEqual(first.status_code, 200, first.text)
        self.assertEqual(second.status_code, 200, second.text)
        self.assertEqual(first.json()["server_status"], "created")
        self.assertEqual(second.json()["server_status"], "updated")
        self.assertEqual(second.json()["tools_updated"], 1)
        with self.Session() as db:
            self.assertEqual(db.query(MCPServer).count(), 1)
            self.assertEqual(db.query(MCPTool).count(), 1)
            self.assertEqual(db.query(ToolAnalysis).count(), 2)
            server = db.query(MCPServer).one()
            self.assertIsNotNone(server.last_scan_at)
            self.assertEqual(server.security_status, "review_required")

    def test_admin_approves_and_viewer_cannot_approve(self) -> None:
        self.create_user("admin", "ADMIN")
        self.create_user("viewer", "VIEWER")
        with self.Session() as db:
            server = MCPServer(
                name="approval-server",
                server_type="mcp",
                endpoint="http://127.0.0.1:9302/mcp",
                transport="streamable_http",
                status="active",
                security_status="review_required",
            )
            db.add(server)
            db.flush()
            tool = MCPTool(server_id=server.id, name="read_file", description="Read file.")
            tool.current_fingerprint = "a" * 64
            tool.analysis_status = "REVIEW_REQUIRED"
            db.add(tool)
            db.flush()
            version = ToolObservedVersion(
                tool_id=tool.id,
                server_ref=SERVER_REF,
                tool_name="read_file",
                fingerprint="a" * 64,
                status="new",
                snapshot={"description": "Read file.", "input_schema": {}},
                profile_snapshot={"revision": "test"},
                profile_revision="test",
            )
            db.add(version)
            db.flush()
            analysis = ToolAnalysis(
                tool_id=tool.id,
                version_id=version.id,
                fingerprint="a" * 64,
                analysis_context_hash="c" * 64,
                analysis_status="REVIEW_REQUIRED",
                risk_score=10,
                risk_level="low",
                semantic_flagged="false",
                deterministic_critical_finding="false",
                consistency_status="consistent",
                drift_status="NONE",
                review_status="REVIEW_REQUIRED",
                semantic_scores={"scores": {"normal_tool_description": 0.9}},
                consistency_result={},
                drift_result={"status": "NONE", "changes": [], "similarity": None},
                model_versions={"semantic": {"name": "mock", "version": "1"}},
                analyzer_revision=ANALYZER_REVISION,
                completed_at=datetime.utcnow(),
            )
            db.add(analysis)
            db.commit()
            tool_id = tool.id
            analysis_id = analysis.id

        csrf = self.login("viewer")
        self.assertEqual(
            self.client.get("/api/v1/control-plane/tool-analysis/analyses").status_code,
            200,
        )
        forbidden = self.client.post(
            f"/api/v1/control-plane/tool-analysis/tools/{tool_id}/approve",
            json={"fingerprint": "a" * 64, "justification": "viewer cannot approve"},
            headers={"x-csrf-token": csrf},
        )
        self.assertEqual(forbidden.status_code, 403)

        self.client = TestClient(app)
        csrf = self.login("admin")
        detail = self.client.get(f"/api/v1/control-plane/tool-analysis/analyses/{analysis_id}")
        self.assertEqual(detail.status_code, 200)
        approved = self.client.post(
            f"/api/v1/control-plane/tool-analysis/tools/{tool_id}/approve",
            json={"fingerprint": "a" * 64, "justification": "reviewed safe read"},
            headers={"x-csrf-token": csrf},
        )
        self.assertEqual(approved.status_code, 200, approved.text)

    def test_analysis_failed_cannot_be_approved(self) -> None:
        self.create_user("admin", "ADMIN")
        with self.Session() as db:
            tool = MCPTool(server_id=1, name="read_file", description="Read file.")
            db.add(tool)
            db.flush()
            version = ToolObservedVersion(
                tool_id=tool.id,
                server_ref=SERVER_REF,
                tool_name="read_file",
                fingerprint="b" * 64,
                status="new",
                snapshot={"description": "Read file.", "input_schema": {}},
                profile_snapshot={"revision": "test"},
                profile_revision="test",
            )
            db.add(version)
            db.flush()
            db.add(
                ToolAnalysis(
                    tool_id=tool.id,
                    version_id=version.id,
                    fingerprint="b" * 64,
                    analysis_status="ANALYSIS_FAILED",
                    risk_score=100,
                    risk_level="critical",
                    semantic_flagged="false",
                    deterministic_critical_finding="false",
                    consistency_status="unknown",
                    drift_status="NONE",
                    review_status="ANALYSIS_FAILED",
                    semantic_scores=None,
                    consistency_result=None,
                    drift_result={"status": "NONE", "changes": [], "similarity": None},
                    model_versions={"semantic": {"name": "mock", "version": "unavailable"}},
                    analyzer_revision=ANALYZER_REVISION,
                )
            )
            db.commit()
            tool_id = tool.id
        csrf = self.login("admin")
        response = self.client.post(
            f"/api/v1/control-plane/tool-analysis/tools/{tool_id}/approve",
            json={"fingerprint": "b" * 64, "justification": "must fail approval"},
            headers={"x-csrf-token": csrf},
        )
        self.assertEqual(response.status_code, 400)

    def test_adapter_guidance_and_starter_download_follow_control_plane_roles(self) -> None:
        self.create_user("admin", "ADMIN")
        self.create_user("viewer", "VIEWER")
        with self.Session() as db:
            server = MCPServer(
                name="widget-server",
                server_type="mcp",
                endpoint="http://127.0.0.1:9399/mcp",
                transport="streamable_http",
                status="active",
            )
            db.add(server)
            db.flush()
            tool = MCPTool(
                server_id=server.id,
                name="transmute_widget",
                title="Transmute Widget",
                description="Apply a proprietary transformation to a widget reference.",
                input_schema={
                    "type": "object",
                    "properties": {"widget": {"type": "string", "maxLength": 128}},
                    "required": ["widget"],
                    "additionalProperties": False,
                },
            )
            db.add(tool)
            db.commit()
            tool_id = tool.id

        self.client = TestClient(app)
        unauthenticated = self.client.get(
            f"/api/v1/control-plane/security-packs/tools/{tool_id}/adapter-guidance"
        )
        self.assertEqual(unauthenticated.status_code, 401)

        self.login("viewer")
        guidance = self.client.get(
            f"/api/v1/control-plane/security-packs/tools/{tool_id}/adapter-guidance"
        )
        self.assertEqual(guidance.status_code, 200, guidance.text)
        self.assertEqual(guidance.json()["status"], "NO_COMPATIBLE_TEMPLATE")
        self.assertEqual(guidance.json()["recommended_starter"], "blank")
        viewer_download = self.client.get(
            "/api/v1/control-plane/security-packs/adapters/starters/blank",
            params={"adapter_id": "widget-adapter"},
        )
        self.assertEqual(viewer_download.status_code, 403)

        self.client = TestClient(app)
        self.login("admin")
        download = self.client.get(
            "/api/v1/control-plane/security-packs/adapters/starters/blank",
            params={"adapter_id": "widget-adapter"},
        )
        self.assertEqual(download.status_code, 200, download.text)
        self.assertEqual(download.headers["content-type"], "application/zip")
        self.assertIn("widget-adapter-starter.zip", download.headers["content-disposition"])
        with zipfile.ZipFile(io.BytesIO(download.content)) as package:
            self.assertIn("adapter.py", package.namelist())


if __name__ == "__main__":
    unittest.main()
