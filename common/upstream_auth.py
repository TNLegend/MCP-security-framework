from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import re

from filelock import FileLock

from common.security_topology import local_security_authority_supported


PROJECT_ROOT = Path(__file__).resolve().parents[1]
from common.project_paths import runtime_data_root
UPSTREAM_SECRET_DIR = runtime_data_root(PROJECT_ROOT) / "secrets" / "upstream"

AUTH_MODE_NONE = "NONE"
AUTH_MODE_BEARER = "BEARER"
AUTH_MODE_OAUTH = "OAUTH"
UPSTREAM_AUTH_MODES = frozenset({AUTH_MODE_NONE, AUTH_MODE_BEARER, AUTH_MODE_OAUTH})
_SECRET_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$")
_BEARER_TOKEN_RE = re.compile(r"^[A-Za-z0-9._~+/-]+=*$")
MAX_UPSTREAM_SECRET_BYTES = 4096
MAX_UPSTREAM_TOKEN_BUNDLE_BYTES = 24_576


class UpstreamAuthError(ValueError):
    """Safe failure for invalid or unavailable framework-held upstream auth."""


def _require_local_credential_authority() -> None:
    if not local_security_authority_supported():
        raise UpstreamAuthError("upstream_credential_topology_unsupported")


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
    *,
    oauth_config: dict | None = None,
) -> str | None:
    mode, reference = validate_upstream_auth_config(auth_mode, credential_ref)
    if mode == AUTH_MODE_NONE:
        return None
    assert reference is not None
    if mode == AUTH_MODE_OAUTH:
        from common.upstream_oauth import resolve_oauth_access_token

        return resolve_oauth_access_token(
            credential_ref=reference,
            oauth_config=oauth_config,
        )
    return read_upstream_secret(reference, token_only=True)


def read_upstream_secret(reference: str, *, token_only: bool = False) -> str:
    _require_local_credential_authority()
    resolved = _resolved_secret_path(reference)
    try:
        raw = resolved.read_bytes()
    except OSError as exc:
        raise UpstreamAuthError("upstream_credential_unavailable") from exc
    if not raw or len(raw) > MAX_UPSTREAM_SECRET_BYTES:
        raise UpstreamAuthError("upstream_credential_invalid")
    try:
        value = raw.decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise UpstreamAuthError("upstream_credential_invalid") from exc
    if not value or (token_only and not _BEARER_TOKEN_RE.fullmatch(value)):
        raise UpstreamAuthError("upstream_credential_invalid")
    return value


def oauth_credential_lock(reference: str) -> FileLock:
    """Stable inter-process lock for token refresh/revocation by credential.

    The lock file is intentionally never deleted: deleting lock files would
    permit two independent lock inodes and break mutual exclusion.
    """
    _require_local_credential_authority()
    if not _valid_secret_ref(reference):
        raise UpstreamAuthError("upstream_credential_ref_invalid")
    lock_root = UPSTREAM_SECRET_DIR / ".locks"
    root = UPSTREAM_SECRET_DIR.resolve()
    lock_root.mkdir(parents=True, exist_ok=True)
    if lock_root.is_symlink() or not lock_root.resolve().is_relative_to(root):
        raise UpstreamAuthError("upstream_credential_ref_invalid")
    lock_path = lock_root / f"{sha256(reference.encode('utf-8')).hexdigest()}.lock"
    if lock_path.is_symlink():
        raise UpstreamAuthError("upstream_credential_ref_invalid")
    return FileLock(str(lock_path), timeout=20)


def read_upstream_token_bundle(reference: str) -> dict:
    _require_local_credential_authority()
    resolved = _resolved_secret_path(reference)
    try:
        raw = resolved.read_bytes()
    except OSError as exc:
        raise UpstreamAuthError("upstream_credential_unavailable") from exc
    if not raw or len(raw) > MAX_UPSTREAM_TOKEN_BUNDLE_BYTES:
        raise UpstreamAuthError("upstream_credential_invalid")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise UpstreamAuthError("upstream_credential_invalid")
    if not isinstance(value, dict):
        raise UpstreamAuthError("upstream_credential_invalid")
    return value


def write_upstream_token_bundle(reference: str, bundle: dict) -> None:
    _require_local_credential_authority()
    if not isinstance(bundle, dict):
        raise UpstreamAuthError("upstream_credential_invalid")
    root = UPSTREAM_SECRET_DIR.resolve()
    target = UPSTREAM_SECRET_DIR.joinpath(*reference.split("/"))
    if not _valid_secret_ref(reference) or not target.resolve(strict=False).is_relative_to(root):
        raise UpstreamAuthError("upstream_credential_ref_invalid")
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.parent.is_symlink() or not target.parent.resolve().is_relative_to(root):
        raise UpstreamAuthError("upstream_credential_ref_invalid")
    temporary = target.with_suffix(f"{target.suffix}.tmp")
    try:
        temporary.write_text(json.dumps(bundle, separators=(",", ":")), encoding="utf-8")
        temporary.replace(target)
    except OSError as exc:
        raise UpstreamAuthError("upstream_credential_unavailable") from exc


def write_upstream_secret(reference: str, value: str) -> None:
    _require_local_credential_authority()
    if (
        not _valid_secret_ref(reference)
        or not isinstance(value, str)
        or not value.strip()
        or len(value.encode("utf-8")) > MAX_UPSTREAM_SECRET_BYTES
        or any(ord(character) < 32 for character in value)
    ):
        raise UpstreamAuthError("upstream_credential_invalid")
    root = UPSTREAM_SECRET_DIR.resolve()
    target = UPSTREAM_SECRET_DIR.joinpath(*reference.split("/"))
    if not target.resolve(strict=False).is_relative_to(root):
        raise UpstreamAuthError("upstream_credential_ref_invalid")
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.parent.is_symlink() or not target.parent.resolve().is_relative_to(root):
        raise UpstreamAuthError("upstream_credential_ref_invalid")
    temporary = target.with_suffix(f"{target.suffix}.tmp")
    try:
        temporary.write_text(value, encoding="utf-8")
        temporary.replace(target)
    except OSError as exc:
        raise UpstreamAuthError("upstream_credential_unavailable") from exc


def delete_upstream_secret(reference: str) -> None:
    _require_local_credential_authority()
    if not _valid_secret_ref(reference):
        raise UpstreamAuthError("upstream_credential_ref_invalid")
    candidate = UPSTREAM_SECRET_DIR.joinpath(*reference.split("/"))
    if not candidate.exists() and not candidate.is_symlink():
        return
    resolved = _resolved_secret_path(reference)
    try:
        resolved.unlink()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise UpstreamAuthError("upstream_credential_unavailable") from exc


def _resolved_secret_path(reference: str) -> Path:
    if not _valid_secret_ref(reference):
        raise UpstreamAuthError("upstream_credential_ref_invalid")
    root = UPSTREAM_SECRET_DIR.resolve()
    candidate = UPSTREAM_SECRET_DIR.joinpath(*reference.split("/"))
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise UpstreamAuthError("upstream_credential_unavailable") from exc
    if candidate.is_symlink() or not resolved.is_relative_to(root) or not resolved.is_file():
        raise UpstreamAuthError("upstream_credential_unavailable")
    return resolved


def upstream_auth_context_hash(auth_mode: str, bearer_token: str | None) -> str:
    material = f"{auth_mode}\x00{bearer_token or ''}".encode("utf-8")
    return sha256(material).hexdigest()


def _valid_secret_ref(reference: str) -> bool:
    return (
        bool(_SECRET_REF_RE.fullmatch(reference))
        and "//" not in reference
        and all(segment not in {"", ".", ".."} for segment in reference.split("/"))
    )
