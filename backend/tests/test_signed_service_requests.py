import json
import socket
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import uvicorn
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND_DIR = REPO_ROOT / "backend"
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(BACKEND_DIR))

from app.core.config import settings  # noqa: E402
from app.db.database import Base, get_db  # noqa: E402
from app.main import app  # noqa: E402
from app.models.mcp_server import MCPServer  # noqa: E402
from app.models.mcp_tool import MCPTool  # noqa: E402
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
from proxy.backend_client import BackendClient  # noqa: E402


class SignedServiceRequestRouteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)
        self.directory = tempfile.TemporaryDirectory()
        self.service_dir = Path(self.directory.name)
        self.previous_public_keys_path = settings.internal_service_public_keys_path
        self.previous_proxy_key_path = settings.mcp_proxy_service_private_key_path
        self.previous_discovery_key_path = settings.mcp_discovery_service_private_key_path
        self.previous_proxy_key_id = settings.mcp_proxy_service_key_id
        self.previous_discovery_key_id = settings.mcp_discovery_service_key_id
        self.previous_window = settings.internal_service_timestamp_window_seconds
        settings.internal_service_timestamp_window_seconds = 60
        self._configure_service_keys()

        def override_get_db():
            db = self.Session()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = override_get_db
        self.client = TestClient(app)
        self._seed_inventory()

    def tearDown(self) -> None:
        app.dependency_overrides.clear()
        settings.internal_service_public_keys_path = self.previous_public_keys_path
        settings.mcp_proxy_service_private_key_path = self.previous_proxy_key_path
        settings.mcp_discovery_service_private_key_path = self.previous_discovery_key_path
        settings.mcp_proxy_service_key_id = self.previous_proxy_key_id
        settings.mcp_discovery_service_key_id = self.previous_discovery_key_id
        settings.internal_service_timestamp_window_seconds = self.previous_window
        self.directory.cleanup()

    def test_proxy_signature_allows_internal_inventory_and_runtime_logs(self) -> None:
        self.assertEqual(
            self.client.get(
                "/api/v1/internal/inventory/servers",
                headers=self.headers(SERVICE_ID_PROXY, "GET", "/api/v1/internal/inventory/servers"),
            ).status_code,
            200,
        )
        self.assertEqual(
            self.client.get(
                "/api/v1/internal/inventory/tools",
                headers=self.headers(SERVICE_ID_PROXY, "GET", "/api/v1/internal/inventory/tools"),
            ).status_code,
            200,
        )
        payload = self.runtime_log_payload()
        self.assertEqual(
            self.client.post(
                "/api/v1/runtime/logs",
                json=payload,
                headers=self.headers(
                    SERVICE_ID_PROXY,
                    "POST",
                    "/api/v1/runtime/logs",
                    payload=payload,
                ),
            ).status_code,
            200,
        )

    def test_missing_invalid_unknown_and_wrong_key_signatures_are_rejected(self) -> None:
        payload = self.runtime_log_payload()
        self.assertEqual(self.client.post("/api/v1/runtime/logs", json=payload).status_code, 401)

        invalid_headers = self.headers(
            SERVICE_ID_PROXY,
            "POST",
            "/api/v1/runtime/logs",
            payload=payload,
        )
        invalid_headers["X-MCP-Signature"] = "invalid"
        self.assertEqual(
            self.client.post("/api/v1/runtime/logs", json=payload, headers=invalid_headers).status_code,
            401,
        )

        unknown_headers = self.headers(
            SERVICE_ID_PROXY,
            "POST",
            "/api/v1/runtime/logs",
            payload=payload,
        )
        unknown_headers["X-MCP-Service-Id"] = "UNKNOWN_SERVICE"
        self.assertEqual(
            self.client.post("/api/v1/runtime/logs", json=payload, headers=unknown_headers).status_code,
            401,
        )

        wrong_key_headers = self.headers(
            SERVICE_ID_DISCOVERY,
            "POST",
            "/api/v1/runtime/logs",
            payload=payload,
        )
        wrong_key_headers["X-MCP-Service-Id"] = SERVICE_ID_PROXY
        wrong_key_headers["X-MCP-Key-Id"] = "proxy-test"
        self.assertEqual(
            self.client.post("/api/v1/runtime/logs", json=payload, headers=wrong_key_headers).status_code,
            401,
        )

    def test_expired_future_and_replayed_jti_are_rejected(self) -> None:
        payload = self.runtime_log_payload()
        expired = datetime.now(timezone.utc) - timedelta(seconds=120)
        self.assertEqual(
            self.client.post(
                "/api/v1/runtime/logs",
                json=payload,
                headers=self.headers(
                    SERVICE_ID_PROXY,
                    "POST",
                    "/api/v1/runtime/logs",
                    payload=payload,
                    timestamp=expired,
                ),
            ).status_code,
            401,
        )

        future = datetime.now(timezone.utc) + timedelta(seconds=120)
        self.assertEqual(
            self.client.post(
                "/api/v1/runtime/logs",
                json=payload,
                headers=self.headers(
                    SERVICE_ID_PROXY,
                    "POST",
                    "/api/v1/runtime/logs",
                    payload=payload,
                    timestamp=future,
                ),
            ).status_code,
            401,
        )

        replay_headers = self.headers(
            SERVICE_ID_PROXY,
            "POST",
            "/api/v1/runtime/logs",
            payload=payload,
            jti="replayed-jti",
        )
        self.assertEqual(
            self.client.post("/api/v1/runtime/logs", json=payload, headers=replay_headers).status_code,
            200,
        )
        self.assertEqual(
            self.client.post("/api/v1/runtime/logs", json=payload, headers=replay_headers).status_code,
            409,
        )

    def test_body_path_and_method_tampering_are_rejected(self) -> None:
        payload = self.runtime_log_payload()
        tampered_payload = {**payload, "decision": "ALLOW"}
        self.assertEqual(
            self.client.post(
                "/api/v1/runtime/logs",
                json=tampered_payload,
                headers=self.headers(
                    SERVICE_ID_PROXY,
                    "POST",
                    "/api/v1/runtime/logs",
                    payload=payload,
                ),
            ).status_code,
            401,
        )

        self.assertEqual(
            self.client.get(
                "/api/v1/internal/inventory/servers",
                headers=self.headers(
                    SERVICE_ID_PROXY,
                    "GET",
                    "/api/v1/internal/inventory/tools",
                ),
            ).status_code,
            401,
        )

        self.assertEqual(
            self.client.post(
                "/api/v1/runtime/logs",
                json=payload,
                headers=self.headers(
                    SERVICE_ID_PROXY,
                    "GET",
                    "/api/v1/runtime/logs",
                    payload=payload,
                ),
            ).status_code,
            401,
        )

    def test_service_permissions_are_not_interchangeable(self) -> None:
        payload = self.runtime_log_payload()
        self.assertEqual(
            self.client.post(
                "/api/v1/runtime/logs",
                json=payload,
                headers=self.headers(
                    SERVICE_ID_DISCOVERY,
                    "POST",
                    "/api/v1/runtime/logs",
                    payload=payload,
                ),
            ).status_code,
            403,
        )
        self.assertEqual(
            self.client.get(
                "/api/v1/internal/inventory/servers",
                headers=self.headers(
                    SERVICE_ID_DISCOVERY,
                    "GET",
                    "/api/v1/internal/inventory/servers",
                ),
            ).status_code,
            403,
        )

        discovery_payload = self.discovery_payload()
        self.assertEqual(
            self.client.post(
                "/api/v1/inventory/import-discovery",
                json=discovery_payload,
                headers=self.headers(
                    SERVICE_ID_PROXY,
                    "POST",
                    "/api/v1/inventory/import-discovery",
                    payload=discovery_payload,
                ),
            ).status_code,
            403,
        )

    def test_discovery_signature_allows_import_without_shared_token(self) -> None:
        payload = self.discovery_payload()

        class FakeSnapshot:
            content_hash = "c" * 64

            @staticmethod
            def get_tool_security_contract(**_kwargs):
                raise RuntimeError("tool_security_contract_missing")

        class FakeAnalysis:
            analysis_status = "REVIEW_REQUIRED"

        class FakeToolAnalysisService:
            def observe_and_analyze(self, **kwargs):
                return FakeAnalysis()

        with patch(
            "app.api.routes_inventory.PublishedConfigurationProvider"
        ) as provider, patch(
            "app.api.routes_inventory.ToolAnalysisService",
            return_value=FakeToolAnalysisService(),
        ):
            provider.return_value.load_active_snapshot.return_value = FakeSnapshot()
            response = self.client.post(
                "/api/v1/inventory/import-discovery",
                json=payload,
                headers=self.headers(
                    SERVICE_ID_DISCOVERY,
                    "POST",
                    "/api/v1/inventory/import-discovery",
                    payload=payload,
                ),
            )
        self.assertEqual(response.status_code, 200, response.text)

    def test_real_backend_client_uses_signed_internal_inventory_routes(self) -> None:
        server, thread, base_url = self._start_live_backend()
        try:
            client = BackendClient(
                backend_base_url=base_url,
                service_signer=self.signer(SERVICE_ID_PROXY),
            )
            self.assertEqual(client.list_servers()[0]["name"], "srv")
            self.assertEqual(client.list_tools()[0]["name"], "read_file")
        finally:
            server.should_exit = True
            thread.join(timeout=10)

    def _configure_service_keys(self) -> None:
        self.proxy_private_key = ed25519.Ed25519PrivateKey.generate()
        self.discovery_private_key = ed25519.Ed25519PrivateKey.generate()
        self.wrong_private_key = ed25519.Ed25519PrivateKey.generate()
        proxy_path = self.service_dir / "proxy.pem"
        discovery_path = self.service_dir / "discovery.pem"
        proxy_path.write_bytes(private_pem(self.proxy_private_key))
        discovery_path.write_bytes(private_pem(self.discovery_private_key))
        registry_path = self.service_dir / "public.json"
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
                                    "public_key_pem": public_pem(self.proxy_private_key),
                                }
                            ],
                        },
                        SERVICE_ID_DISCOVERY: {
                            "permissions": [PERMISSION_INVENTORY_IMPORT_DISCOVERY],
                            "keys": [
                                {
                                    "key_id": "discovery-test",
                                    "public_key_pem": public_pem(self.discovery_private_key),
                                }
                            ],
                        },
                    }
                }
            ),
            encoding="utf-8",
        )
        self.proxy_private_key_path = proxy_path
        self.discovery_private_key_path = discovery_path
        settings.internal_service_public_keys_path = str(registry_path)
        settings.mcp_proxy_service_key_id = "proxy-test"
        settings.mcp_proxy_service_private_key_path = str(proxy_path)
        settings.mcp_discovery_service_key_id = "discovery-test"
        settings.mcp_discovery_service_private_key_path = str(discovery_path)

    def _seed_inventory(self) -> None:
        with self.Session() as db:
            server = MCPServer(
                name="srv",
                server_type="mcp",
                endpoint="http://127.0.0.1:9000/mcp",
                status="active",
                transport="streamable_http",
            )
            db.add(server)
            db.flush()
            db.add(
                MCPTool(
                    server_id=server.id,
                    name="read_file",
                    input_schema={"type": "object"},
                )
            )
            db.commit()

    def signer(self, service_id: str) -> SignedServiceRequestSigner:
        return SignedServiceRequestSigner(
            ServiceRequestSignerConfig(
                service_id=service_id,
                key_id="proxy-test" if service_id == SERVICE_ID_PROXY else "discovery-test",
                private_key_path=(
                    self.proxy_private_key_path
                    if service_id == SERVICE_ID_PROXY
                    else self.discovery_private_key_path
                ),
            )
        )

    def headers(
        self,
        service_id: str,
        method: str,
        path: str,
        *,
        payload: dict | None = None,
        timestamp: datetime | None = None,
        jti: str | None = None,
    ) -> dict[str, str]:
        return self.signer(service_id).signed_headers(
            method=method,
            path=path,
            body=canonical_json_body(payload),
            timestamp=timestamp,
            jti=jti,
        )

    def runtime_log_payload(self) -> dict:
        return {
            "agent_id": "agent_demo",
            "session_id": "session-1",
            "tool_name": "read_file",
            "status": "blocked",
            "decision": "BLOCK",
            "executed": False,
        }

    def discovery_payload(self) -> dict:
        return {
            "server": {
                "endpoint": "http://127.0.0.1:9000/mcp",
                "transport": "streamable_http",
                "protocol_version": "2025-11-25",
            },
            "tools": [
                {
                    "name": "read_file",
                    "description": "Read a file.",
                    "input_schema": {"type": "object", "additionalProperties": False},
                }
            ],
        }

    def _start_live_backend(self):
        port = free_port()
        config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
        server = uvicorn.Server(config)
        thread = threading.Thread(target=server.run, daemon=True)
        thread.start()
        base_url = f"http://127.0.0.1:{port}"
        deadline = time.time() + 10
        while not server.started and time.time() < deadline:
            time.sleep(0.05)
        self.assertTrue(server.started)
        return server, thread, base_url


def private_pem(key: ed25519.Ed25519PrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def public_pem(key: ed25519.Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


if __name__ == "__main__":
    unittest.main()
