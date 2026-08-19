from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import re


PROJECT_ROOT = Path(__file__).resolve().parents[1]
UPSTREAM_SECRET_DIR = PROJECT_ROOT / ".runtime" / "secrets" / "upstream"

AUTH_MODE_NONE = "NONE"
AUTH_MODE_BEARER = "BEARER"
UPSTREAM_AUTH_MODES = frozenset({AUTH_MODE_NONE, AUTH_MODE_BEARER})
_SECRET_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$")
_BEARER_TOKEN_RE = re.compile(r"^[A-Za-z0-9._~+/-]+=*$")
MAX_UPSTREAM_SECRET_BYTES = 4096


class UpstreamAuthError(ValueError):
    """Safe failure for invalid or unavailable framework-held upstream auth."""


def validate_upstream_auth_config(
    auth_mode: str | None,
    credential_ref: str | None,
) -> tuple[str, str | None]:
    mode = auth_mode or AUTH_MODE_NONE
    if mode not in UPSTREAM_AUTH_MODES:
        raise UpstreamAuthError("upstream_auth_mode_invalid")
    if mode == AUTH_MODE_NONE:
        if credential_ref not in (None, ""):
            raise UpstreamAuthError("upstream_credential_ref_unexpected")
        return mode, None
    if not isinstance(credential_ref, str) or not _valid_secret_ref(credential_ref):
        raise UpstreamAuthError("upstream_credential_ref_invalid")
    return mode, credential_ref


def resolve_upstream_bearer_token(
    auth_mode: str | None,
    credential_ref: str | None,
) -> str | None:
    mode, reference = validate_upstream_auth_config(auth_mode, credential_ref)
    if mode == AUTH_MODE_NONE:
        return None
    assert reference is not None
    root = UPSTREAM_SECRET_DIR.resolve()
    candidate = UPSTREAM_SECRET_DIR.joinpath(*reference.split("/"))
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise UpstreamAuthError("upstream_credential_unavailable") from exc
    if candidate.is_symlink() or not resolved.is_relative_to(root) or not resolved.is_file():
        raise UpstreamAuthError("upstream_credential_unavailable")
    try:
        raw = resolved.read_bytes()
    except OSError as exc:
        raise UpstreamAuthError("upstream_credential_unavailable") from exc
    if not raw or len(raw) > MAX_UPSTREAM_SECRET_BYTES:
        raise UpstreamAuthError("upstream_credential_invalid")
    try:
        token = raw.decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise UpstreamAuthError("upstream_credential_invalid") from exc
    if not token or not _BEARER_TOKEN_RE.fullmatch(token):
        raise UpstreamAuthError("upstream_credential_invalid")
    return token


def upstream_auth_context_hash(auth_mode: str, bearer_token: str | None) -> str:
    material = f"{auth_mode}\x00{bearer_token or ''}".encode("utf-8")
    return sha256(material).hexdigest()


def _valid_secret_ref(reference: str) -> bool:
    return (
        bool(_SECRET_REF_RE.fullmatch(reference))
        and "//" not in reference
        and all(segment not in {"", ".", ".."} for segment in reference.split("/"))
    )
