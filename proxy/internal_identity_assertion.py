from datetime import datetime, timedelta, timezone
from pathlib import Path
import secrets
import sys
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization

from proxy.identity_config import ProxyAssertionConfig, REPO_ROOT

try:
    from app.services.identity_context_hash import runtime_context_hash
except ModuleNotFoundError:
    backend_path = Path(__file__).resolve().parents[1] / "backend"
    sys.path.insert(0, str(backend_path))
    from app.services.identity_context_hash import runtime_context_hash


ASSERTION_TYPE = "mcp-identity+jwt"
ASSERTION_ALGORITHM = "EdDSA"


class InternalIdentityAssertionError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class InternalIdentityAssertionSigner:
    def __init__(self, config: ProxyAssertionConfig | None = None) -> None:
        self.config = config or ProxyAssertionConfig.from_env()
        self._private_key = None

    def sign(self, context: dict[str, Any]) -> str:
        private_key = self._load_private_key()
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(seconds=min(self.config.ttl_seconds, 30))
        claims = {
            "iss": self.config.issuer,
            "aud": self.config.audience,
            "sub": context["subject"]["agent_id"],
            "iat": int(now.timestamp()),
            "nbf": int(now.timestamp()),
            "exp": int(expires_at.timestamp()),
            "jti": secrets.token_urlsafe(32),
            "sid": context["runtime"]["session_id"],
            "ctx_hash": runtime_context_hash(context),
            "identity_binding_revision": context["subject"][
                "identity_binding_revision"
            ],
            "session_reference": context["subject"]["session_reference"],
            "tool_profile_revision": context["tool"]["profile_revision"],
            "resource_registry_revision": context["request"][
                "resource_registry_revision"
            ],
            "control_plane_revision_id": context["runtime"][
                "control_plane_revision_id"
            ],
            "control_plane_content_hash": context["runtime"][
                "control_plane_content_hash"
            ],
        }
        headers = {
            "typ": ASSERTION_TYPE,
            "kid": self.config.key_id,
            "alg": ASSERTION_ALGORITHM,
        }
        return jwt.encode(
            claims,
            private_key,
            algorithm=ASSERTION_ALGORITHM,
            headers=headers,
        )

    def _load_private_key(self):
        if self._private_key is not None:
            return self._private_key

        key_path = self.config.private_key_path
        try:
            resolved = key_path.resolve()
            repo_root = REPO_ROOT.resolve()
            if resolved == repo_root or repo_root in resolved.parents:
                raise InternalIdentityAssertionError("identity_assertion_key_unavailable")
            key_data = key_path.read_bytes()
            private_key = serialization.load_pem_private_key(
                key_data,
                password=None,
            )
        except InternalIdentityAssertionError:
            raise
        except Exception as exc:
            raise InternalIdentityAssertionError(
                "identity_assertion_key_unavailable"
            ) from exc

        self._private_key = private_key
        return private_key
