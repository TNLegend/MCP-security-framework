from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from hashlib import sha256
import json
from pathlib import Path
import re
import secrets
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from common.mcp_endpoint import MCPEndpointValidationError, parse_mcp_endpoint, validate_mcp_endpoint
from common.upstream_auth import (
    UpstreamAuthError,
    read_upstream_secret,
    read_upstream_token_bundle,
    write_upstream_token_bundle,
)


MAX_OAUTH_RESPONSE_BYTES = 262_144
MAX_OAUTH_TOKEN_BYTES = 8_192
OAUTH_CLOCK_SKEW_SECONDS = 60
OAUTH_ATTEMPT_TTL_SECONDS = 600
OAUTH_USER_AGENT = "MCP-Security-Framework/1.0"
_SCOPE_RE = re.compile(r"^[A-Za-z0-9:._/-]{1,128}$")
_STATE_RE = re.compile(r"^[A-Za-z0-9_-]{32,256}$")


class UpstreamOAuthError(UpstreamAuthError):
    """Safe failure for a framework-owned upstream OAuth connection."""


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: N802
        return None


OAUTH_OPENER = build_opener(_NoRedirectHandler)


def normalize_requested_scopes(value: str | None) -> list[str]:
    if value is None or not value.strip():
        return []
    scopes = value.split()
    if len(scopes) > 50 or any(not _SCOPE_RE.fullmatch(scope) for scope in scopes):
        raise UpstreamOAuthError("upstream_oauth_scopes_invalid")
    return list(dict.fromkeys(scopes))


def create_oauth_attempt(
    *,
    attempt_directory: Path,
    server_id: int,
    actor_user_id: str,
    redirect_uri: str,
    authorization_endpoint: str,
    token_endpoint: str,
    client_id: str,
    client_secret_ref: str | None,
    resource: str,
    scopes: list[str],
) -> tuple[str, str, datetime]:
    state = secrets.token_urlsafe(32)
    code_verifier = secrets.token_urlsafe(64)
    expires_at = _utcnow() + timedelta(seconds=OAUTH_ATTEMPT_TTL_SECONDS)
    payload = {
        "server_id": server_id,
        "actor_user_id": actor_user_id,
        "redirect_uri": redirect_uri,
        "authorization_endpoint": authorization_endpoint,
        "token_endpoint": token_endpoint,
        "client_id": client_id,
        "client_secret_ref": client_secret_ref,
        "resource": resource,
        "scopes": scopes,
        "code_verifier": code_verifier,
        "expires_at": expires_at.isoformat(),
    }
    _write_attempt(attempt_directory, state, payload)
    challenge = base64.urlsafe_b64encode(sha256(code_verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
    query: dict[str, str] = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "resource": resource,
    }
    if scopes:
        query["scope"] = " ".join(scopes)
    return state, f"{authorization_endpoint}?{urlencode(query)}", expires_at


def consume_oauth_attempt(*, attempt_directory: Path, state: str) -> dict[str, Any]:
    if not isinstance(state, str) or not _STATE_RE.fullmatch(state):
        raise UpstreamOAuthError("upstream_oauth_state_invalid")
    path = _attempt_path(attempt_directory, state)
    root = attempt_directory.resolve()
    try:
        resolved = path.resolve(strict=True)
        if path.is_symlink() or not resolved.is_relative_to(root) or not resolved.is_file():
            raise OSError
        raw = resolved.read_bytes()
        resolved.unlink()
    except OSError as exc:
        raise UpstreamOAuthError("upstream_oauth_state_invalid") from exc
    try:
        payload = json.loads(raw.decode("utf-8"))
        expires_at = datetime.fromisoformat(str(payload["expires_at"]))
    except (KeyError, TypeError, ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise UpstreamOAuthError("upstream_oauth_state_invalid") from exc
    if expires_at <= _utcnow():
        raise UpstreamOAuthError("upstream_oauth_state_expired")
    required = {
        "server_id",
        "actor_user_id",
        "redirect_uri",
        "authorization_endpoint",
        "token_endpoint",
        "client_id",
        "resource",
        "scopes",
        "code_verifier",
    }
    if not required <= set(payload) or not isinstance(payload["server_id"], int):
        raise UpstreamOAuthError("upstream_oauth_state_invalid")
    return payload


def discover_oauth_configuration(
    *,
    mcp_endpoint: str,
    client_id: str | None,
    requested_scopes: list[str],
) -> dict[str, Any]:
    if client_id is not None and not _valid_client_id(client_id):
        raise UpstreamOAuthError("upstream_oauth_client_id_invalid")
    resource = canonical_resource_uri(mcp_endpoint)
    challenge_metadata_url, challenge_scopes = _discover_challenge(mcp_endpoint)
    metadata = _discover_protected_resource_metadata(
        mcp_endpoint,
        challenge_metadata_url,
    )
    authorization_servers = metadata.get("authorization_servers")
    if not isinstance(authorization_servers, list) or not authorization_servers:
        raise UpstreamOAuthError("upstream_oauth_authorization_server_missing")
    authorization_server = _validated_authorization_server(authorization_servers[0])
    authorization_metadata = _discover_authorization_server_metadata(authorization_server)
    authorization_endpoint = _validated_oauth_endpoint(
        authorization_metadata.get("authorization_endpoint"),
        "upstream_oauth_authorization_endpoint_invalid",
    )
    token_endpoint = _validated_oauth_endpoint(
        authorization_metadata.get("token_endpoint"),
        "upstream_oauth_token_endpoint_invalid",
    )
    challenge_methods = authorization_metadata.get("code_challenge_methods_supported")
    if not isinstance(challenge_methods, list) or "S256" not in challenge_methods:
        raise UpstreamOAuthError("upstream_oauth_pkce_s256_unsupported")
    advertised_scopes = metadata.get("scopes_supported")
    if advertised_scopes is not None and (
        not isinstance(advertised_scopes, list)
        or any(not isinstance(scope, str) or not _SCOPE_RE.fullmatch(scope) for scope in advertised_scopes)
    ):
        raise UpstreamOAuthError("upstream_oauth_metadata_invalid")
    scopes = requested_scopes or challenge_scopes or list(advertised_scopes or [])
    if advertised_scopes and requested_scopes and not set(requested_scopes) <= set(advertised_scopes):
        raise UpstreamOAuthError("upstream_oauth_scope_not_supported")
    configuration = {
        "authorization_server": authorization_server,
        "authorization_endpoint": authorization_endpoint,
        "token_endpoint": token_endpoint,
        "resource": resource,
        "scopes": scopes,
        "scope_source": "requested" if requested_scopes else ("challenge" if challenge_scopes else "metadata"),
    }
    if client_id is not None:
        configuration["client_id"] = client_id
    registration_endpoint = authorization_metadata.get("registration_endpoint")
    if registration_endpoint is not None:
        configuration["registration_endpoint"] = _validated_oauth_endpoint(
            registration_endpoint,
            "upstream_oauth_registration_endpoint_invalid",
        )
    return configuration


def register_dynamic_oauth_client(
    *,
    registration_endpoint: str,
    redirect_uri: str,
    scopes: list[str],
) -> dict[str, str]:
    _validate_oauth_fetch_url(registration_endpoint, require_https_for_remote=True)
    _validate_oauth_fetch_url(redirect_uri, require_https_for_remote=True)
    payload: dict[str, Any] = {
        "client_name": "MCP Security Framework",
        "redirect_uris": [redirect_uri],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
    }
    if scopes:
        payload["scope"] = " ".join(scopes)
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    request = Request(
        registration_endpoint,
        data=body,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": OAUTH_USER_AGENT,
        },
        method="POST",
    )
    try:
        with OAUTH_OPENER.open(request, timeout=15) as response:
            raw = response.read(MAX_OAUTH_RESPONSE_BYTES + 1)
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        raise UpstreamOAuthError("upstream_oauth_dynamic_registration_failed") from exc
    if len(raw) > MAX_OAUTH_RESPONSE_BYTES:
        raise UpstreamOAuthError("upstream_oauth_dynamic_registration_response_too_large")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise UpstreamOAuthError("upstream_oauth_dynamic_registration_response_invalid") from exc
    if not isinstance(value, dict) or not _valid_client_id(value.get("client_id")):
        raise UpstreamOAuthError("upstream_oauth_dynamic_registration_response_invalid")
    result = {"client_id": value["client_id"]}
    client_secret = value.get("client_secret")
    if client_secret is not None:
        if not isinstance(client_secret, str) or not client_secret or len(client_secret) > MAX_OAUTH_TOKEN_BYTES:
            raise UpstreamOAuthError("upstream_oauth_dynamic_registration_response_invalid")
        result["client_secret"] = client_secret
    return result


def exchange_authorization_code(
    *,
    code: str,
    attempt: dict[str, Any],
    credential_ref: str,
) -> dict[str, Any]:
    if not isinstance(code, str) or not code or len(code) > MAX_OAUTH_TOKEN_BYTES:
        raise UpstreamOAuthError("upstream_oauth_code_invalid")
    response = _request_token(
        token_endpoint=str(attempt["token_endpoint"]),
        client_id=str(attempt["client_id"]),
        client_secret_ref=attempt.get("client_secret_ref"),
        payload={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": str(attempt["redirect_uri"]),
            "code_verifier": str(attempt["code_verifier"]),
            "resource": str(attempt["resource"]),
        },
    )
    bundle = _token_bundle(response, resource=str(attempt["resource"]), scopes=attempt.get("scopes") or [])
    write_upstream_token_bundle(credential_ref, bundle)
    return bundle


def resolve_oauth_access_token(
    *,
    credential_ref: str,
    oauth_config: dict[str, Any] | None,
) -> str:
    if not isinstance(oauth_config, dict):
        raise UpstreamOAuthError("upstream_oauth_configuration_invalid")
    bundle = read_upstream_token_bundle(credential_ref)
    expires_at = _bundle_expiry(bundle)
    if expires_at > _utcnow() + timedelta(seconds=OAUTH_CLOCK_SKEW_SECONDS):
        return _token_value(bundle, "access_token")
    refresh_token = bundle.get("refresh_token")
    if not isinstance(refresh_token, str) or not refresh_token:
        raise UpstreamOAuthError("upstream_oauth_reauthorization_required")
    response = _request_token(
        token_endpoint=_validated_oauth_endpoint(
            oauth_config.get("token_endpoint"),
            "upstream_oauth_token_endpoint_invalid",
        ),
        client_id=_oauth_config_string(oauth_config, "client_id"),
        client_secret_ref=oauth_config.get("client_secret_ref"),
        payload={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "resource": _oauth_config_string(oauth_config, "resource"),
        },
    )
    refreshed = _token_bundle(
        response,
        resource=_oauth_config_string(oauth_config, "resource"),
        scopes=oauth_config.get("scopes") or [],
        previous_refresh_token=refresh_token,
    )
    write_upstream_token_bundle(credential_ref, refreshed)
    return _token_value(refreshed, "access_token")


def canonical_resource_uri(endpoint: str) -> str:
    try:
        parsed = validate_mcp_endpoint(endpoint)
    except MCPEndpointValidationError as exc:
        raise UpstreamOAuthError(str(exc)) from exc
    scheme = parsed.parsed.scheme.lower()
    hostname = parsed.hostname
    default_port = 443 if scheme == "https" else 80
    authority = hostname if parsed.port == default_port else f"{hostname}:{parsed.port}"
    return urlunsplit((scheme, authority, parsed.parsed.path or "/", parsed.parsed.query, ""))


def _discover_challenge(endpoint: str) -> tuple[str | None, list[str]]:
    request = Request(
        endpoint,
        headers={"Accept": "application/json", "User-Agent": OAUTH_USER_AGENT},
        method="GET",
    )
    try:
        with OAUTH_OPENER.open(request, timeout=10) as response:
            headers = response.headers
    except HTTPError as exc:
        headers = exc.headers
    except (URLError, TimeoutError):
        return None, []
    header = headers.get("WWW-Authenticate") if headers else None
    if not isinstance(header, str):
        return None, []
    metadata_match = re.search(r'resource_metadata="([^"\\]+)"', header, flags=re.IGNORECASE)
    scope_match = re.search(r'scope="([^"\\]*)"', header, flags=re.IGNORECASE)
    scopes = normalize_requested_scopes(scope_match.group(1) if scope_match else None)
    return (metadata_match.group(1) if metadata_match else None), scopes


def _discover_protected_resource_metadata(endpoint: str, challenged_url: str | None) -> dict[str, Any]:
    candidates = [challenged_url] if challenged_url else []
    parsed = urlsplit(endpoint)
    endpoint_path = (parsed.path or "/").rstrip("/")
    endpoint_metadata = urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            f"{endpoint_path}/.well-known/oauth-protected-resource",
            "",
            "",
        )
    )
    path_metadata = urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            "/.well-known/oauth-protected-resource" + (parsed.path or "/"),
            "",
            "",
        )
    )
    root_metadata = urlunsplit(
        (parsed.scheme, parsed.netloc, "/.well-known/oauth-protected-resource", "", "")
    )
    for candidate in [*candidates, endpoint_metadata, path_metadata, root_metadata]:
        if not candidate:
            continue
        try:
            metadata = _fetch_json(candidate, require_https_for_remote=True)
        except UpstreamOAuthError:
            continue
        if isinstance(metadata, dict):
            return metadata
    raise UpstreamOAuthError("upstream_oauth_protected_resource_metadata_unavailable")


def _discover_authorization_server_metadata(issuer: str) -> dict[str, Any]:
    parsed = urlsplit(issuer)
    path = parsed.path.strip("/")
    base = f"{parsed.scheme}://{parsed.netloc}"
    candidates = (
        [f"{base}/.well-known/oauth-authorization-server/{path}", f"{base}/.well-known/openid-configuration/{path}", f"{issuer}/.well-known/openid-configuration"]
        if path
        else [f"{base}/.well-known/oauth-authorization-server", f"{base}/.well-known/openid-configuration"]
    )
    for candidate in candidates:
        try:
            metadata = _fetch_json(candidate, require_https_for_remote=True)
        except UpstreamOAuthError:
            continue
        if isinstance(metadata, dict):
            return metadata
    raise UpstreamOAuthError("upstream_oauth_authorization_metadata_unavailable")


def _fetch_json(url: str, *, require_https_for_remote: bool) -> dict[str, Any]:
    _validate_oauth_fetch_url(url, require_https_for_remote=require_https_for_remote)
    request = Request(
        url,
        headers={"Accept": "application/json", "User-Agent": OAUTH_USER_AGENT},
        method="GET",
    )
    try:
        with OAUTH_OPENER.open(request, timeout=10) as response:
            raw = response.read(MAX_OAUTH_RESPONSE_BYTES + 1)
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        raise UpstreamOAuthError("upstream_oauth_metadata_fetch_failed") from exc
    if len(raw) > MAX_OAUTH_RESPONSE_BYTES:
        raise UpstreamOAuthError("upstream_oauth_metadata_too_large")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise UpstreamOAuthError("upstream_oauth_metadata_invalid") from exc
    if not isinstance(value, dict):
        raise UpstreamOAuthError("upstream_oauth_metadata_invalid")
    return value


def _request_token(
    *,
    token_endpoint: str,
    client_id: str,
    client_secret_ref: object,
    payload: dict[str, str],
) -> dict[str, Any]:
    _validate_oauth_fetch_url(token_endpoint, require_https_for_remote=True)
    form = {"client_id": client_id, **payload}
    if isinstance(client_secret_ref, str) and client_secret_ref:
        form["client_secret"] = read_upstream_secret(client_secret_ref)
    body = urlencode(form).encode("ascii")
    request = Request(
        token_endpoint,
        data=body,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": OAUTH_USER_AGENT,
        },
        method="POST",
    )
    try:
        with OAUTH_OPENER.open(request, timeout=15) as response:
            raw = response.read(MAX_OAUTH_RESPONSE_BYTES + 1)
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        raise UpstreamOAuthError("upstream_oauth_token_exchange_failed") from exc
    if len(raw) > MAX_OAUTH_RESPONSE_BYTES:
        raise UpstreamOAuthError("upstream_oauth_token_response_too_large")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise UpstreamOAuthError("upstream_oauth_token_response_invalid") from exc
    if not isinstance(value, dict):
        raise UpstreamOAuthError("upstream_oauth_token_response_invalid")
    return value


def _token_bundle(
    response: dict[str, Any],
    *,
    resource: str,
    scopes: list[str],
    previous_refresh_token: str | None = None,
) -> dict[str, Any]:
    access_token = _token_value(response, "access_token")
    expires_in = response.get("expires_in")
    if isinstance(expires_in, bool) or not isinstance(expires_in, (int, float)) or not 1 <= expires_in <= 604800:
        raise UpstreamOAuthError("upstream_oauth_token_expiry_invalid")
    refresh_token = response.get("refresh_token", previous_refresh_token)
    if refresh_token is not None:
        refresh_token = _validate_token_value(refresh_token, "refresh_token")
    return {
        "version": 1,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "expires_at": (_utcnow() + timedelta(seconds=expires_in)).isoformat(),
        "resource": resource,
        "scopes": scopes,
    }


def _bundle_expiry(bundle: dict[str, Any]) -> datetime:
    try:
        value = datetime.fromisoformat(str(bundle["expires_at"]))
    except (KeyError, TypeError, ValueError) as exc:
        raise UpstreamOAuthError("upstream_oauth_token_invalid") from exc
    return value


def _token_value(source: dict[str, Any], name: str) -> str:
    try:
        return _validate_token_value(source[name], name)
    except KeyError as exc:
        raise UpstreamOAuthError("upstream_oauth_token_invalid") from exc


def _validate_token_value(value: Any, name: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > MAX_OAUTH_TOKEN_BYTES
        or any(character.isspace() or ord(character) < 32 for character in value)
    ):
        raise UpstreamOAuthError(f"upstream_oauth_{name}_invalid")
    return value


def _validated_authorization_server(value: Any) -> str:
    if not isinstance(value, str):
        raise UpstreamOAuthError("upstream_oauth_authorization_server_invalid")
    return _validated_oauth_endpoint(value, "upstream_oauth_authorization_server_invalid")


def _validated_oauth_endpoint(value: Any, error_code: str) -> str:
    if not isinstance(value, str):
        raise UpstreamOAuthError(error_code)
    try:
        _validate_oauth_fetch_url(value, require_https_for_remote=True)
    except UpstreamOAuthError as exc:
        raise UpstreamOAuthError(error_code) from exc
    return value


def _validate_oauth_fetch_url(value: str, *, require_https_for_remote: bool) -> None:
    try:
        parsed = validate_mcp_endpoint(value)
    except MCPEndpointValidationError as exc:
        raise UpstreamOAuthError("upstream_oauth_endpoint_invalid") from exc
    if parsed.parsed.query or parsed.parsed.fragment:
        raise UpstreamOAuthError("upstream_oauth_endpoint_invalid")
    if require_https_for_remote and parsed.parsed.scheme.lower() != "https" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
        raise UpstreamOAuthError("upstream_oauth_https_required")


def _oauth_config_string(config: dict[str, Any], key: str) -> str:
    value = config.get(key)
    if not isinstance(value, str) or not value:
        raise UpstreamOAuthError("upstream_oauth_configuration_invalid")
    return value


def _valid_client_id(value: str) -> bool:
    return (
        isinstance(value, str)
        and 1 <= len(value) <= 2048
        and not any(character.isspace() or ord(character) < 32 for character in value)
    )


def _utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def _attempt_path(directory: Path, state: str) -> Path:
    return directory / f"{sha256(state.encode('ascii')).hexdigest()}.json"


def _write_attempt(directory: Path, state: str, payload: dict[str, Any]) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    root = directory.resolve()
    target = _attempt_path(directory, state)
    if not target.resolve(strict=False).is_relative_to(root):
        raise UpstreamOAuthError("upstream_oauth_state_invalid")
    temporary = target.with_suffix(".tmp")
    try:
        temporary.write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")
        temporary.replace(target)
    except OSError as exc:
        raise UpstreamOAuthError("upstream_oauth_state_unavailable") from exc
