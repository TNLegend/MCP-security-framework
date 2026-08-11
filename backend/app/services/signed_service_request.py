from __future__ import annotations

from base64 import urlsafe_b64decode, urlsafe_b64encode
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from pathlib import Path
import secrets
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.database import get_db
from app.services.identity_replay_store import (
    IdentityReplayError,
    consume_identity_assertion_jti,
)


SERVICE_ID_PROXY = "MCP_PROXY"
SERVICE_ID_DISCOVERY = "MCP_DISCOVERY"

PERMISSION_INTERNAL_INVENTORY_SERVERS_READ = "internal.inventory.servers.read"
PERMISSION_INTERNAL_INVENTORY_TOOLS_READ = "internal.inventory.tools.read"
PERMISSION_RUNTIME_LOGS_WRITE = "runtime.logs.write"
PERMISSION_INVENTORY_IMPORT_DISCOVERY = "inventory.import_discovery"

EMPTY_BODY_SHA256 = sha256(b"").hexdigest()


class SignedServiceRequestError(Exception):
    def __init__(self, code: str, *, status_code: int = status.HTTP_401_UNAUTHORIZED) -> None:
        super().__init__(code)
        self.code = code
        self.status_code = status_code


@dataclass(frozen=True)
class VerifiedServiceRequest:
    service_id: str
    key_id: str
    timestamp: datetime
    jti: str
    permission: str


@dataclass(frozen=True)
class ServiceRequestSignerConfig:
    service_id: str
    key_id: str
    private_key_path: Path


class SignedServiceRequestSigner:
    def __init__(self, config: ServiceRequestSignerConfig) -> None:
        self.config = config
        self._private_key: Ed25519PrivateKey | None = None

    @classmethod
    def for_proxy(cls) -> "SignedServiceRequestSigner":
        return cls(
            ServiceRequestSignerConfig(
                service_id=settings.mcp_proxy_service_id,
                key_id=settings.mcp_proxy_service_key_id,
                private_key_path=Path(settings.mcp_proxy_service_private_key_path),
            )
        )

    @classmethod
    def for_discovery(cls) -> "SignedServiceRequestSigner":
        return cls(
            ServiceRequestSignerConfig(
                service_id=settings.mcp_discovery_service_id,
                key_id=settings.mcp_discovery_service_key_id,
                private_key_path=Path(settings.mcp_discovery_service_private_key_path),
            )
        )

    def signed_headers(
        self,
        *,
        method: str,
        path: str,
        body: bytes | None = None,
        timestamp: datetime | None = None,
        jti: str | None = None,
    ) -> dict[str, str]:
        issued_at = timestamp or datetime.now(timezone.utc)
        token_id = jti or secrets.token_urlsafe(32)
        body_hash = body_sha256(body)
        canonical = canonical_service_request(
            service_id=self.config.service_id,
            key_id=self.config.key_id,
            method=method,
            path=path,
            timestamp=timestamp_header(issued_at),
            jti=token_id,
            body_hash=body_hash,
        )
        signature = self._load_private_key().sign(canonical)
        return {
            "X-MCP-Service-Id": self.config.service_id,
            "X-MCP-Key-Id": self.config.key_id,
            "X-MCP-Timestamp": timestamp_header(issued_at),
            "X-MCP-JTI": token_id,
            "X-MCP-Signature": b64url_encode(signature),
        }

    def _load_private_key(self) -> Ed25519PrivateKey:
        if self._private_key is not None:
            return self._private_key
        try:
            key = serialization.load_pem_private_key(
                self.config.private_key_path.read_bytes(),
                password=None,
            )
        except Exception as exc:
            raise SignedServiceRequestError("service_private_key_unavailable") from exc
        if not isinstance(key, Ed25519PrivateKey):
            raise SignedServiceRequestError("service_private_key_invalid")
        self._private_key = key
        return key


class SignedServiceRequestVerifier:
    def __init__(
        self,
        *,
        public_keys_path: Path | None = None,
        timestamp_window_seconds: int | None = None,
    ) -> None:
        self.public_keys_path = public_keys_path or Path(settings.internal_service_public_keys_path)
        self.timestamp_window_seconds = (
            timestamp_window_seconds or settings.internal_service_timestamp_window_seconds
        )

    def verify(
        self,
        *,
        method: str,
        path: str,
        body: bytes,
        service_id: str | None,
        key_id: str | None,
        timestamp: str | None,
        jti: str | None,
        signature: str | None,
        required_permission: str,
        db: Session,
    ) -> VerifiedServiceRequest:
        if not all([service_id, key_id, timestamp, jti, signature]):
            raise SignedServiceRequestError("service_signature_missing")
        assert service_id is not None
        assert key_id is not None
        assert timestamp is not None
        assert jti is not None
        assert signature is not None
        if not service_id.strip() or not key_id.strip() or not jti.strip():
            raise SignedServiceRequestError("service_signature_malformed")

        issued_at = parse_timestamp(timestamp)
        self._validate_timestamp(issued_at)
        service = self._load_service_registry().get(service_id)
        if service is None:
            raise SignedServiceRequestError("service_unknown")
        permissions = service.get("permissions")
        if not isinstance(permissions, list) or required_permission not in permissions:
            raise SignedServiceRequestError(
                "service_permission_denied",
                status_code=status.HTTP_403_FORBIDDEN,
            )
        public_key = self._select_public_key(service, key_id)

        body_hash = body_sha256(body)
        canonical = canonical_service_request(
            service_id=service_id,
            key_id=key_id,
            method=method,
            path=path,
            timestamp=timestamp,
            jti=jti,
            body_hash=body_hash,
        )
        try:
            public_key.verify(b64url_decode(signature), canonical)
        except (InvalidSignature, ValueError) as exc:
            raise SignedServiceRequestError("service_signature_invalid") from exc

        try:
            consume_identity_assertion_jti(
                issuer=f"service:{service_id}:{key_id}",
                jti=jti,
                expires_at=issued_at + timedelta(seconds=self.timestamp_window_seconds),
                db=db,
            )
        except IdentityReplayError as exc:
            status_code = (
                status.HTTP_409_CONFLICT
                if exc.code == "identity_assertion_replayed"
                else status.HTTP_401_UNAUTHORIZED
            )
            raise SignedServiceRequestError(exc.code, status_code=status_code) from exc

        return VerifiedServiceRequest(
            service_id=service_id,
            key_id=key_id,
            timestamp=issued_at,
            jti=jti,
            permission=required_permission,
        )

    def _validate_timestamp(self, issued_at: datetime) -> None:
        now = datetime.now(timezone.utc)
        window = timedelta(seconds=self.timestamp_window_seconds)
        if issued_at < now - window:
            raise SignedServiceRequestError("service_signature_expired")
        if issued_at > now + window:
            raise SignedServiceRequestError("service_signature_not_yet_valid")

    def _load_service_registry(self) -> dict[str, dict[str, Any]]:
        try:
            payload = json.loads(self.public_keys_path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise SignedServiceRequestError("service_key_registry_unavailable") from exc
        services = payload.get("services") if isinstance(payload, dict) else None
        if isinstance(services, dict):
            return services
        if isinstance(services, list):
            return {
                service["service_id"]: service
                for service in services
                if isinstance(service, dict) and isinstance(service.get("service_id"), str)
            }
        raise SignedServiceRequestError("service_key_registry_invalid")

    def _select_public_key(self, service: dict[str, Any], key_id: str) -> Ed25519PublicKey:
        keys = service.get("keys")
        if not isinstance(keys, list):
            raise SignedServiceRequestError("service_key_unknown")
        for key in keys:
            if not isinstance(key, dict) or key.get("key_id") != key_id:
                continue
            pem = key.get("public_key_pem")
            if not isinstance(pem, str) or not pem.strip():
                raise SignedServiceRequestError("service_key_unknown")
            try:
                public_key = serialization.load_pem_public_key(pem.encode("utf-8"))
            except Exception as exc:
                raise SignedServiceRequestError("service_key_unknown") from exc
            if not isinstance(public_key, Ed25519PublicKey):
                raise SignedServiceRequestError("service_key_unknown")
            return public_key
        raise SignedServiceRequestError("service_key_unknown")


def require_internal_service_permission(required_permission: str):
    async def dependency(
        request: Request,
        db: Session = Depends(get_db),
        service_id: str | None = Header(default=None, alias="X-MCP-Service-Id"),
        key_id: str | None = Header(default=None, alias="X-MCP-Key-Id"),
        timestamp: str | None = Header(default=None, alias="X-MCP-Timestamp"),
        jti: str | None = Header(default=None, alias="X-MCP-JTI"),
        signature: str | None = Header(default=None, alias="X-MCP-Signature"),
    ) -> VerifiedServiceRequest:
        body = await request.body()
        path = request.url.path
        if request.url.query:
            path = f"{path}?{request.url.query}"
        try:
            return SignedServiceRequestVerifier().verify(
                method=request.method,
                path=path,
                body=body,
                service_id=service_id,
                key_id=key_id,
                timestamp=timestamp,
                jti=jti,
                signature=signature,
                required_permission=required_permission,
                db=db,
            )
        except SignedServiceRequestError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.code) from exc

    return dependency


def canonical_json_body(payload: dict[str, Any] | None) -> bytes | None:
    if payload is None:
        return None
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def body_sha256(body: bytes | None) -> str:
    if not body:
        return EMPTY_BODY_SHA256
    try:
        parsed = json.loads(body.decode("utf-8"))
    except Exception:
        canonical = body
    else:
        canonical = json.dumps(parsed, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return sha256(canonical).hexdigest()


def canonical_service_request(
    *,
    service_id: str,
    key_id: str,
    method: str,
    path: str,
    timestamp: str,
    jti: str,
    body_hash: str,
) -> bytes:
    fields = [
        "mcp-service-request-v1",
        service_id,
        key_id,
        method.upper(),
        path,
        timestamp,
        jti,
        body_hash,
    ]
    return "\n".join(fields).encode("utf-8")


def timestamp_header(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SignedServiceRequestError("service_timestamp_invalid") from exc
    if parsed.tzinfo is None:
        raise SignedServiceRequestError("service_timestamp_invalid")
    return parsed.astimezone(timezone.utc)


def b64url_encode(data: bytes) -> str:
    return urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return urlsafe_b64decode((value + padding).encode("ascii"))
