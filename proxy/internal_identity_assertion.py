from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import secrets
import sys
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization

from common.project_paths import is_path_within
from proxy.identity_config import ProxyAssertionConfig, REPO_ROOT

try:
    from app.services.identity_context_hash import runtime_context_hash
except ModuleNotFoundError:
    backend_path = Path(__file__).resolve().parents[1] / "backend"
    sys.path.insert(0, str(backend_path))
    from app.services.identity_context_hash import runtime_context_hash


ASSERTION_TYPE = "mcp-identity+jwt"
ASSERTION_ALGORITHM = "EdDSA"
from common.project_paths import runtime_data_root
RUNTIME_SECRETS_ROOT = runtime_data_root(REPO_ROOT) / "secrets"


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
            trusted_path = validate_private_key_path(key_path)
            key_data = trusted_path.read_bytes()
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


def validate_private_key_path(
    key_path: Path,
    *,
    project_root: Path = REPO_ROOT,
    runtime_secrets_root: Path = RUNTIME_SECRETS_ROOT,
) -> Path:
    candidate = key_path.expanduser()
    if not candidate.is_absolute():
        candidate = project_root / candidate
    lexical_path = Path(os.path.abspath(candidate))
    resolved_path = lexical_path.resolve(strict=False)
    lexical_project_root = Path(os.path.abspath(project_root.expanduser()))
    lexical_runtime_root = Path(os.path.abspath(runtime_secrets_root.expanduser()))
    resolved_project_root = project_root.resolve(strict=False)
    resolved_runtime_root = runtime_secrets_root.resolve(strict=False)

    lexical_in_runtime = (
        lexical_path == lexical_runtime_root
        or lexical_runtime_root in lexical_path.parents
    )
    lexical_in_project = (
        lexical_path == lexical_project_root
        or lexical_project_root in lexical_path.parents
    )
    if lexical_in_runtime and is_path_within(
        resolved_path,
        resolved_runtime_root,
    ):
        return resolved_path
    if lexical_in_project or is_path_within(
        resolved_path,
        resolved_project_root,
    ):
        raise InternalIdentityAssertionError("identity_assertion_key_unavailable")
    return resolved_path
