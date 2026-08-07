import argparse
import base64
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


REPO_ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = REPO_ROOT / "backend"
sys.path.insert(0, str(BACKEND_DIR))

from app.core.runtime_paths import RUNTIME_SECRETS_DIR, configure_runtime_environment  # noqa: E402

configure_runtime_environment()
DEFAULT_SECRET_DIR = RUNTIME_SECRETS_DIR
DEFAULT_IDP_KEY_ID = "local-idp-rs256-1"


def load_project_env() -> None:
    env_path = REPO_ROOT / ".env"
    if not env_path.exists():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        name, value = stripped.split("=", 1)
        name = name.strip()
        value = value.strip().strip('"').strip("'")
        if name and name not in os.environ:
            os.environ[name] = value


def issue_access_token(
    *,
    subject: str,
    lifetime_seconds: int = 300,
    token_id: str | None = None,
) -> str:
    load_project_env()
    private_key = _load_private_key(_identity_private_key_path())
    now = datetime.now(timezone.utc)
    issuer = os.getenv("AGENT_IDENTITY_ISSUER", "http://127.0.0.1:9100/")
    audience = os.getenv("AGENT_IDENTITY_AUDIENCE", "mcp-security-proxy")
    key_id = os.getenv("AGENT_IDENTITY_KEY_ID", DEFAULT_IDP_KEY_ID)
    token_type = _first_csv_value(
        os.getenv("AGENT_IDENTITY_ACCEPTED_TYPES", "at+jwt"),
        "at+jwt",
    )

    claims = {
        "iss": issuer,
        "aud": audience,
        "sub": subject,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=lifetime_seconds)).timestamp()),
        "jti": token_id or f"local-{datetime.now(timezone.utc).timestamp()}",
    }
    return jwt.encode(
        claims,
        private_key,
        algorithm="RS256",
        headers={"kid": key_id, "typ": token_type},
    )


def ensure_identity_material() -> dict[str, bool]:
    load_project_env()
    key_path = _identity_private_key_path()
    jwks_path = _identity_public_jwks_path()
    key_id = os.getenv("AGENT_IDENTITY_KEY_ID", DEFAULT_IDP_KEY_ID)
    key_path.parent.mkdir(parents=True, exist_ok=True)
    jwks_path.parent.mkdir(parents=True, exist_ok=True)

    if not key_path.exists():
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        key_path.write_bytes(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    private_key = _load_private_key(key_path)
    jwks_path.write_text(
        json.dumps({"keys": [_public_jwk(private_key, key_id)]}, indent=2),
        encoding="utf-8",
    )

    return {
        "identity_signing_key_present": key_path.exists(),
        "public_jwks_present": jwks_path.exists(),
    }


def serve_jwks(*, host: str | None = None, port: int | None = None) -> None:
    load_project_env()
    ensure_identity_material()
    jwks_path = _identity_public_jwks_path()
    parsed = urlparse(os.getenv("AGENT_IDENTITY_JWKS_URL", "http://127.0.0.1:9100/jwks.json"))
    bind_host = host or parsed.hostname or "127.0.0.1"
    bind_port = port or parsed.port or 9100
    if bind_host not in {"127.0.0.1", "localhost"}:
        raise SystemExit("Local identity provider must bind to localhost only.")

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path.split("?", 1)[0] != "/jwks.json":
                self.send_response(404)
                self.end_headers()
                return
            body = jwks_path.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: Any) -> None:
            return None

    server = ThreadingHTTPServer((bind_host, bind_port), Handler)
    print(f"LOCAL_IDENTITY_PROVIDER_LISTENING=http://{bind_host}:{bind_port}/jwks.json")
    try:
        server.serve_forever()
    finally:
        server.server_close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Local lab identity provider.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("ensure-material")

    serve_parser = subparsers.add_parser("serve")
    serve_parser.add_argument("--host", default=None)
    serve_parser.add_argument("--port", type=int, default=None)

    token_parser = subparsers.add_parser("token")
    token_parser.add_argument("--subject", required=True)
    token_parser.add_argument("--lifetime-seconds", type=int, default=300)

    args = parser.parse_args()
    if args.command == "ensure-material":
        result = ensure_identity_material()
        for key, value in result.items():
            print(f"{key}={str(value).lower()}")
        return
    if args.command == "serve":
        serve_jwks(host=args.host, port=args.port)
        return
    if args.command == "token":
        _ = issue_access_token(
            subject=args.subject,
            lifetime_seconds=args.lifetime_seconds,
        )
        print("TOKEN_CREATED=true")
        return


def _identity_private_key_path() -> Path:
    return Path(
        os.getenv(
            "AGENT_IDENTITY_SIGNING_PRIVATE_KEY_PATH",
            str(DEFAULT_SECRET_DIR / "local-idp-private.pem"),
        )
    ).expanduser()


def _identity_public_jwks_path() -> Path:
    return Path(
        os.getenv(
            "AGENT_IDENTITY_PUBLIC_JWKS_PATH",
            str(DEFAULT_SECRET_DIR / "local-idp-public-jwks.json"),
        )
    ).expanduser()


def _load_private_key(path: Path):
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def _public_jwk(private_key, key_id: str) -> dict[str, str]:
    public_numbers = private_key.public_key().public_numbers()
    return {
        "kty": "RSA",
        "kid": key_id,
        "alg": "RS256",
        "use": "sig",
        "n": _b64url_uint(public_numbers.n),
        "e": _b64url_uint(public_numbers.e),
    }


def _b64url_uint(value: int) -> str:
    length = (value.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(value.to_bytes(length, "big")).rstrip(b"=").decode("ascii")


def _first_csv_value(value: str, default: str) -> str:
    for item in value.split(","):
        stripped = item.strip()
        if stripped:
            return stripped
    return default


if __name__ == "__main__":
    main()
