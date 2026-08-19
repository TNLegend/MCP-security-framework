from __future__ import annotations

import base64
import hashlib
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from app.core.runtime_paths import RUNTIME_SECRETS_DIR
from common.canonical_json import canonical_json_bytes


REVISION_SIGNATURE_CONTEXT = "mcp-security-framework/control-plane-revision/v1"
REVISION_SIGNATURE_ALGORITHM = "Ed25519"
REVISION_SIGNATURE_VERSION = "1"
REVISION_PRIVATE_KEY_PATH = RUNTIME_SECRETS_DIR / "control-plane-revision-ed25519.pem"
REVISION_PUBLIC_KEY_PATH = RUNTIME_SECRETS_DIR / "control-plane-revision-ed25519.pub.pem"


class RevisionSignatureError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def revision_signature_payload(
    *,
    revision_id: str,
    revision_number: int,
    schema_version: int,
    content_hash: str,
    previous_revision_hash: str,
) -> dict[str, Any]:
    return {
        "context": REVISION_SIGNATURE_CONTEXT,
        "revision_id": revision_id,
        "revision_number": revision_number,
        "schema_version": schema_version,
        "content_hash": content_hash,
        "previous_revision_hash": previous_revision_hash,
    }


def sign_revision_payload(payload: dict[str, Any]) -> tuple[str, str]:
    key = _load_private_key(REVISION_PRIVATE_KEY_PATH)
    signature = key.sign(canonical_json_bytes(payload))
    return _b64url(signature), revision_key_id(key.public_key())


def verify_revision_payload(
    payload: dict[str, Any],
    *,
    signature: str,
    key_id: str,
    algorithm: str,
    version: str,
) -> None:
    if algorithm != REVISION_SIGNATURE_ALGORITHM or version != REVISION_SIGNATURE_VERSION:
        raise RevisionSignatureError("revision_signature_profile_unsupported")
    key = _load_public_key(REVISION_PUBLIC_KEY_PATH)
    if revision_key_id(key) != key_id:
        raise RevisionSignatureError("revision_signature_key_unknown")
    try:
        key.verify(_b64url_decode(signature), canonical_json_bytes(payload))
    except (InvalidSignature, ValueError) as exc:
        raise RevisionSignatureError("revision_signature_invalid") from exc


def revision_key_id(key: Ed25519PublicKey) -> str:
    public_der = key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return "sha256:" + hashlib.sha256(public_der).hexdigest()


def _load_private_key(path: Path) -> Ed25519PrivateKey:
    try:
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    except Exception as exc:
        raise RevisionSignatureError("revision_signing_key_unavailable") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise RevisionSignatureError("revision_signing_key_invalid")
    return key


def _load_public_key(path: Path) -> Ed25519PublicKey:
    try:
        key = serialization.load_pem_public_key(path.read_bytes())
    except Exception as exc:
        raise RevisionSignatureError("revision_verification_key_unavailable") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise RevisionSignatureError("revision_verification_key_invalid")
    return key


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
