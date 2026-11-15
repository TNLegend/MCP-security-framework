from __future__ import annotations

import base64
import json
import os
import sys
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

REPO_ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = REPO_ROOT / "backend"
for import_path in (REPO_ROOT, BACKEND_DIR):
    if str(import_path) not in sys.path:
        sys.path.insert(0, str(import_path))

from app.core.runtime_paths import RUNTIME_SECRETS_DIR, ensure_runtime_directories  # noqa: E402
from app.services.signed_service_request import (  # noqa: E402
    PERMISSION_EMERGENCY_DENY_CHECK,
    PERMISSION_INTERNAL_INVENTORY_SERVERS_READ,
    PERMISSION_INTERNAL_INVENTORY_TOOLS_READ,
    PERMISSION_INVENTORY_IMPORT_DISCOVERY,
    PERMISSION_RUNTIME_LOGS_WRITE,
    PERMISSION_RUNTIME_DISPATCH_ADMIT,
    SERVICE_ID_DISCOVERY,
    SERVICE_ID_PROXY,
)
from common.file_permissions import restrict_private_file, restrict_public_file  # noqa: E402
from common.project_environment import load_project_environment  # noqa: E402


PROXY_KEY_ID = "mcp-proxy-local"
DISCOVERY_KEY_ID = "mcp-discovery-local"
PROXY_ASSERTION_KEY_ID = "proxy-assertion-local"


def provision_service_identities(
    *,
    secret_dir: Path = RUNTIME_SECRETS_DIR,
    proxy_key_id: str = PROXY_KEY_ID,
    discovery_key_id: str = DISCOVERY_KEY_ID,
    proxy_assertion_key_id: str = PROXY_ASSERTION_KEY_ID,
) -> dict[str, Any]:
    secret_dir.mkdir(parents=True, exist_ok=True)
    paths = _identity_paths(secret_dir)

    proxy_key = load_or_create_key(paths["proxy_private_key"])
    discovery_key = load_or_create_key(paths["discovery_private_key"])
    revision_key = load_or_create_key(paths["revision_private_key"])
    assertion_key = load_or_create_key(paths["proxy_assertion_private_key"])
    if private_key_bytes(proxy_key) == private_key_bytes(discovery_key):
        raise RuntimeError("MCP_PROXY and MCP_DISCOVERY service keys must be different.")

    registry = {
        "services": {
            SERVICE_ID_PROXY: {
                "permissions": [
                    PERMISSION_INTERNAL_INVENTORY_SERVERS_READ,
                    PERMISSION_INTERNAL_INVENTORY_TOOLS_READ,
                    PERMISSION_RUNTIME_LOGS_WRITE,
                    PERMISSION_EMERGENCY_DENY_CHECK,
                    PERMISSION_RUNTIME_DISPATCH_ADMIT,
                ],
                "keys": [
                    {
                        "key_id": proxy_key_id,
                        "public_key_pem": public_pem(proxy_key),
                    }
                ],
            },
            SERVICE_ID_DISCOVERY: {
                "permissions": [PERMISSION_INVENTORY_IMPORT_DISCOVERY],
                "keys": [
                    {
                        "key_id": discovery_key_id,
                        "public_key_pem": public_pem(discovery_key),
                    }
                ],
            },
        }
    }
    _write_json(paths["public_registry"], registry)
    _write_public_text(paths["revision_public_key"], public_pem(revision_key))
    _write_json(
        paths["proxy_assertion_public_jwks"],
        {"keys": [public_jwk(assertion_key, proxy_assertion_key_id)]},
    )

    return {
        **{name: str(path) for name, path in paths.items()},
        "private_keys_different": True,
        "status": "ready",
    }


def main() -> int:
    load_project_environment()
    ensure_runtime_directories()
    result = provision_service_identities(
        proxy_key_id=os.getenv("MCP_PROXY_SERVICE_KEY_ID", PROXY_KEY_ID),
        discovery_key_id=os.getenv("MCP_DISCOVERY_SERVICE_KEY_ID", DISCOVERY_KEY_ID),
        proxy_assertion_key_id=os.getenv(
            "PROXY_ASSERTION_KEY_ID",
            PROXY_ASSERTION_KEY_ID,
        ),
    )
    print(json.dumps(result, indent=2))
    return 0


def load_or_create_key(path: Path) -> ed25519.Ed25519PrivateKey:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        try:
            key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        except Exception as exc:
            raise RuntimeError(f"Invalid existing private key file: {path}") from exc
        if not isinstance(key, ed25519.Ed25519PrivateKey):
            raise RuntimeError(f"Existing private key is not Ed25519: {path}")
        restrict_private_file(path)
        return key
    key = ed25519.Ed25519PrivateKey.generate()
    path.write_bytes(private_key_bytes(key))
    restrict_private_file(path)
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
    ).decode("ascii")


def public_jwk(
    key: ed25519.Ed25519PrivateKey,
    key_id: str,
) -> dict[str, str]:
    raw_public_key = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return {
        "kty": "OKP",
        "crv": "Ed25519",
        "kid": key_id,
        "alg": "EdDSA",
        "use": "sig",
        "x": base64.urlsafe_b64encode(raw_public_key).rstrip(b"=").decode("ascii"),
    }


def _identity_paths(secret_dir: Path) -> dict[str, Path]:
    return {
        "proxy_private_key": secret_dir / "mcp-proxy-service-ed25519.pem",
        "discovery_private_key": secret_dir / "mcp-discovery-service-ed25519.pem",
        "public_registry": secret_dir / "internal-service-public-keys.json",
        "revision_private_key": secret_dir / "control-plane-revision-ed25519.pem",
        "revision_public_key": secret_dir / "control-plane-revision-ed25519.pub.pem",
        "proxy_assertion_private_key": secret_dir / "proxy-assertion-private.pem",
        "proxy_assertion_public_jwks": secret_dir / "proxy-assertion-public-jwks.json",
    }


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    _write_public_text(path, json.dumps(payload, indent=2))


def _write_public_text(path: Path, value: str) -> None:
    path.write_text(value, encoding="utf-8")
    restrict_public_file(path)


if __name__ == "__main__":
    raise SystemExit(main())
