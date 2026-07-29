import base64
import json
import sys
import tempfile
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa


REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND_DIR = REPO_ROOT / "backend"

sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(BACKEND_DIR))


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_json(data: dict[str, Any]) -> str:
    return b64url(json.dumps(data, separators=(",", ":")).encode("utf-8"))


def b64url_uint(value: int) -> str:
    length = (value.bit_length() + 7) // 8
    return b64url(value.to_bytes(length, "big"))


def generate_rsa_identity_key(kid: str = "rsa-test-key"):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_numbers = private_key.public_key().public_numbers()
    jwk = {
        "kty": "RSA",
        "kid": kid,
        "alg": "RS256",
        "use": "sig",
        "n": b64url_uint(public_numbers.n),
        "e": b64url_uint(public_numbers.e),
    }
    return private_key, jwk


def generate_ed25519_assertion_key(kid: str = "ed25519-test-key"):
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    jwk = {
        "kty": "OKP",
        "crv": "Ed25519",
        "kid": kid,
        "alg": "EdDSA",
        "use": "sig",
        "x": b64url(public_bytes),
    }
    return private_key, private_pem, jwk


def make_access_token(
    private_key,
    *,
    kid: str = "rsa-test-key",
    issuer: str = "https://issuer.example/",
    audience: str | list[str] = "mcp-security-proxy",
    subject: str | None = "agent-demo",
    token_id: str | None = "token-id-001",
    lifetime_seconds: int = 300,
    issued_offset_seconds: int = 0,
    not_before_offset_seconds: int | None = None,
    algorithm: str = "RS256",
    token_type: str | None = "at+jwt",
    extra_headers: dict[str, Any] | None = None,
    claims_override: dict[str, Any] | None = None,
) -> str:
    now = datetime.now(timezone.utc) + timedelta(seconds=issued_offset_seconds)
    claims: dict[str, Any] = {
        "iss": issuer,
        "aud": audience,
        "exp": int((now + timedelta(seconds=lifetime_seconds)).timestamp()),
        "iat": int(now.timestamp()),
        "jti": token_id,
    }
    if subject is not None:
        claims["sub"] = subject
    if not_before_offset_seconds is not None:
        claims["nbf"] = int(
            (
                datetime.now(timezone.utc)
                + timedelta(seconds=not_before_offset_seconds)
            ).timestamp()
        )
    if claims_override:
        for key, value in claims_override.items():
            if value is _DELETE:
                claims.pop(key, None)
            else:
                claims[key] = value

    headers: dict[str, Any] = {"kid": kid}
    if token_type is not None:
        headers["typ"] = token_type
    if extra_headers:
        headers.update(extra_headers)

    return jwt.encode(claims, private_key, algorithm=algorithm, headers=headers)


def make_unsigned_token(
    *,
    kid: str = "none-key",
    token_type: str = "at+jwt",
) -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode(
        {
            "iss": "https://issuer.example/",
            "aud": "mcp-security-proxy",
            "sub": "agent-demo",
            "exp": int((now + timedelta(minutes=5)).timestamp()),
            "iat": int(now.timestamp()),
            "jti": "unsigned-token",
        },
        key="",
        algorithm="none",
        headers={"kid": kid, "typ": token_type},
    )


def tamper_jwt_payload(token: str, updates: dict[str, Any]) -> str:
    header, payload, signature = token.split(".")
    payload_bytes = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
    data = json.loads(payload_bytes.decode("utf-8"))
    data.update(updates)
    return ".".join((header, b64url_json(data), signature))


def tamper_jwt_header(token: str, updates: dict[str, Any]) -> str:
    header, payload, signature = token.split(".")
    header_bytes = base64.urlsafe_b64decode(header + "=" * (-len(header) % 4))
    data = json.loads(header_bytes.decode("utf-8"))
    for key, value in updates.items():
        if value is _DELETE:
            data.pop(key, None)
        else:
            data[key] = value
    return ".".join((b64url_json(data), payload, signature))


@contextmanager
def temporary_jwks_server(
    jwks: dict[str, Any] | None = None,
    *,
    raw_body: bytes | None = None,
):
    body = raw_body or json.dumps(jwks or {"keys": []}).encode("utf-8")

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: Any) -> None:
            return None

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/jwks.json"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@contextmanager
def temporary_directory():
    with tempfile.TemporaryDirectory() as directory:
        yield Path(directory)


def write_json(path: Path, payload: dict[str, Any]) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def write_text(path: Path, content: str) -> Path:
    path.write_text(content, encoding="utf-8")
    return path


def write_bytes(path: Path, content: bytes) -> Path:
    path.write_bytes(content)
    return path


def runtime_context(**overrides: Any) -> dict[str, Any]:
    context: dict[str, Any] = {
        "subject": {
            "agent_id": "agent-demo",
            "identity_status": "verified",
            "identity_issuer": "https://issuer.example/",
            "identity_binding_revision": "identity-bindings-test-v1",
            "session_status": "active",
            "session_reference": "session-001",
            "role": "unknown",
            "authorization_status": "unknown",
            "authorization_revision": "unresolved",
            "grants": [],
            "allowed_capabilities": [],
            "allowed_scopes": [],
        },
        "server": {
            "id": 1,
            "endpoint": "http://127.0.0.1:9000/mcp",
            "server_ref": "streamable_http:http://127.0.0.1:9000/mcp",
            "known": True,
            "trusted": True,
            "trust_status": "trusted",
            "security_status": "pending_analysis",
        },
        "tool": {
            "id": 1,
            "name": "read_file",
            "profile_status": "resolved",
            "profile_revision": "tool-security-profiles-test-v1",
            "risk_score": 40.0,
            "sensitivity": "medium",
            "capabilities": [],
            "admission_status": "unknown",
            "description_risk_score": 0.0,
            "capability_mismatch": False,
            "drift_status": "unknown",
        },
        "request": {
            "operation": "read",
            "resource_adapter": "filesystem",
            "resource_type": "filesystem.file",
            "resource_scope": "fs.project_workspace",
            "required_capability": "filesystem.read",
            "canonical_resource": "fs.project_workspace:/contracts/contract1.txt",
            "arguments": {"path": "contracts/contract1.txt"},
            "arguments_valid": True,
            "validation_error_codes": [],
            "resource_sensitivity": "internal",
            "resource_resolution_status": "resolved",
            "resource_flags": [],
            "resource_registry_revision": "resource-scopes-test-v1",
            "tool_profile_revision": "tool-security-profiles-test-v1",
            "operation_allowed_on_scope": True,
            "estimated_output_size_mb": 0.001,
        },
        "runtime": {
            "environment": "local",
            "session_id": "session-001",
        },
    }
    deep_update(context, overrides)
    return context


def deep_update(target: dict[str, Any], updates: dict[str, Any]) -> None:
    for key, value in updates.items():
        if isinstance(value, dict) and isinstance(target.get(key), dict):
            deep_update(target[key], value)
        else:
            target[key] = value


class _Delete:
    pass


_DELETE = _Delete()
