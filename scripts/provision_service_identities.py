from __future__ import annotations

import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

REPO_ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = REPO_ROOT / "backend"
sys.path.insert(0, str(BACKEND_DIR))

from app.core.runtime_paths import RUNTIME_SECRETS_DIR, ensure_runtime_directories  # noqa: E402
from app.services.signed_service_request import (  # noqa: E402
    PERMISSION_INTERNAL_INVENTORY_SERVERS_READ,
    PERMISSION_INTERNAL_INVENTORY_TOOLS_READ,
    PERMISSION_INVENTORY_IMPORT_DISCOVERY,
    PERMISSION_RUNTIME_LOGS_WRITE,
    SERVICE_ID_DISCOVERY,
    SERVICE_ID_PROXY,
)


PROXY_KEY_ID = "mcp-proxy-local"
DISCOVERY_KEY_ID = "mcp-discovery-local"
PROXY_PRIVATE_KEY = RUNTIME_SECRETS_DIR / "mcp-proxy-service-ed25519.pem"
DISCOVERY_PRIVATE_KEY = RUNTIME_SECRETS_DIR / "mcp-discovery-service-ed25519.pem"
PUBLIC_REGISTRY = RUNTIME_SECRETS_DIR / "internal-service-public-keys.json"


def main() -> int:
    ensure_runtime_directories()
    proxy_key = load_or_create_key(PROXY_PRIVATE_KEY)
    discovery_key = load_or_create_key(DISCOVERY_PRIVATE_KEY)
    if private_key_bytes(proxy_key) == private_key_bytes(discovery_key):
        raise RuntimeError("MCP_PROXY and MCP_DISCOVERY service keys must be different.")

    registry = {
        "services": {
            SERVICE_ID_PROXY: {
                "permissions": [
                    PERMISSION_INTERNAL_INVENTORY_SERVERS_READ,
                    PERMISSION_INTERNAL_INVENTORY_TOOLS_READ,
                    PERMISSION_RUNTIME_LOGS_WRITE,
                ],
                "keys": [
                    {
                        "key_id": PROXY_KEY_ID,
                        "public_key_pem": public_pem(proxy_key),
                    }
                ],
            },
            SERVICE_ID_DISCOVERY: {
                "permissions": [PERMISSION_INVENTORY_IMPORT_DISCOVERY],
                "keys": [
                    {
                        "key_id": DISCOVERY_KEY_ID,
                        "public_key_pem": public_pem(discovery_key),
                    }
                ],
            },
        }
    }
    PUBLIC_REGISTRY.write_text(json.dumps(registry, indent=2), encoding="utf-8")
    print(
        json.dumps(
            {
                "proxy_private_key": str(PROXY_PRIVATE_KEY),
                "discovery_private_key": str(DISCOVERY_PRIVATE_KEY),
                "public_registry": str(PUBLIC_REGISTRY),
                "private_keys_different": True,
            },
            indent=2,
        )
    )
    return 0


def load_or_create_key(path: Path) -> ed25519.Ed25519PrivateKey:
    if path.exists():
        return serialization.load_pem_private_key(path.read_bytes(), password=None)
    key = ed25519.Ed25519PrivateKey.generate()
    path.write_bytes(private_key_bytes(key))
    return key


def private_key_bytes(key: ed25519.Ed25519PrivateKey) -> bytes:
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


if __name__ == "__main__":
    raise SystemExit(main())
