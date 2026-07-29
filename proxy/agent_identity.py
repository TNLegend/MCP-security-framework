from dataclasses import dataclass
from datetime import datetime, timezone
import json
from typing import Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

import jwt

from proxy.identity_config import AgentIdentityConfig


DEFAULT_MAX_ACCESS_TOKEN_BYTES = 16_384
MAX_ACCESS_TOKEN_BYTES = DEFAULT_MAX_ACCESS_TOKEN_BYTES
MAX_JWKS_BYTES = 262_144
MAX_JWKS_KEYS = 20


class AgentIdentityError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class VerifiedExternalIdentity:
    issuer: str
    subject: str
    audience: tuple[str, ...]
    client_id: str | None
    token_id: str
    issued_at: datetime
    expires_at: datetime


class AgentIdentityVerifier(Protocol):
    def verify(self, access_token: str) -> VerifiedExternalIdentity:
        ...


class JWTJWKSAgentIdentityVerifier:
    def __init__(self, config: AgentIdentityConfig | None = None) -> None:
        self.config = config or AgentIdentityConfig.from_env()
        self._cached_jwks: dict | None = None
        self._cache_expires_at = 0.0

    def verify(self, access_token: str) -> VerifiedExternalIdentity:
        self._validate_token_shape(access_token)
        header = self._safe_header(access_token)
        key = self._select_key(header["kid"])

        try:
            claims = jwt.decode(
                access_token,
                key=key.key,
                algorithms=list(self.config.allowed_algorithms),
                issuer=self.config.issuer,
                audience=self.config.audience,
                leeway=self.config.clock_skew_seconds,
                options={
                    "require": ["iss", "sub", "aud", "exp", "iat", "jti"],
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_iat": True,
                    "verify_aud": True,
                    "verify_iss": True,
                },
            )
        except jwt.ExpiredSignatureError as exc:
            raise AgentIdentityError("agent_access_token_expired") from exc
        except jwt.ImmatureSignatureError as exc:
            raise AgentIdentityError("agent_access_token_not_yet_valid") from exc
        except jwt.InvalidIssuerError as exc:
            raise AgentIdentityError("agent_access_token_issuer_invalid") from exc
        except jwt.InvalidAudienceError as exc:
            raise AgentIdentityError("agent_access_token_audience_invalid") from exc
        except jwt.InvalidSignatureError as exc:
            raise AgentIdentityError("agent_access_token_signature_invalid") from exc
        except jwt.MissingRequiredClaimError as exc:
            if getattr(exc, "claim", None) == "aud":
                raise AgentIdentityError("agent_access_token_audience_invalid") from exc
            if getattr(exc, "claim", None) == "iss":
                raise AgentIdentityError("agent_access_token_issuer_invalid") from exc
            raise AgentIdentityError("agent_access_token_malformed") from exc
        except jwt.PyJWTError as exc:
            raise AgentIdentityError("agent_access_token_malformed") from exc

        subject = claims.get("sub")
        token_id = claims.get("jti")
        issued_at = claims.get("iat")
        expires_at = claims.get("exp")
        if not isinstance(subject, str) or not subject.strip():
            raise AgentIdentityError("agent_access_token_malformed")
        if not isinstance(token_id, str) or not token_id.strip():
            raise AgentIdentityError("agent_access_token_malformed")
        if not isinstance(issued_at, int) or not isinstance(expires_at, int):
            raise AgentIdentityError("agent_access_token_malformed")

        now = datetime.now(timezone.utc).timestamp()
        if issued_at > now + self.config.clock_skew_seconds:
            raise AgentIdentityError("agent_access_token_not_yet_valid")

        audience = claims.get("aud")
        if isinstance(audience, str):
            audience_tuple = (audience,)
        elif isinstance(audience, list) and all(isinstance(item, str) for item in audience):
            audience_tuple = tuple(audience)
        else:
            raise AgentIdentityError("agent_access_token_audience_invalid")
        if not audience_tuple:
            raise AgentIdentityError("agent_access_token_audience_invalid")

        return VerifiedExternalIdentity(
            issuer=str(claims["iss"]),
            subject=subject,
            audience=audience_tuple,
            client_id=claims.get("client_id") if isinstance(claims.get("client_id"), str) else None,
            token_id=token_id,
            issued_at=datetime.fromtimestamp(issued_at, timezone.utc),
            expires_at=datetime.fromtimestamp(expires_at, timezone.utc),
        )

    def _validate_token_shape(self, access_token: str) -> None:
        if not access_token:
            raise AgentIdentityError("agent_access_token_missing")
        if not isinstance(access_token, str):
            raise AgentIdentityError("agent_access_token_malformed")
        max_token_bytes = self.config.token_max_size_bytes or DEFAULT_MAX_ACCESS_TOKEN_BYTES
        if len(access_token.encode("utf-8")) > max_token_bytes:
            raise AgentIdentityError("agent_access_token_too_large")
        if access_token.count(".") != 2:
            raise AgentIdentityError("agent_access_token_malformed")

    def _safe_header(self, access_token: str) -> dict:
        try:
            header = jwt.get_unverified_header(access_token)
        except jwt.PyJWTError as exc:
            raise AgentIdentityError("agent_access_token_malformed") from exc

        token_type = header.get("typ")
        if token_type not in self.config.accepted_types:
            raise AgentIdentityError("agent_access_token_type_invalid")

        algorithm = header.get("alg")
        if algorithm == "none" or algorithm not in self.config.allowed_algorithms:
            raise AgentIdentityError("agent_access_token_algorithm_invalid")

        kid = header.get("kid")
        if not isinstance(kid, str) or not kid.strip():
            raise AgentIdentityError("agent_access_token_key_unknown")

        return {"kid": kid, "alg": algorithm, "typ": token_type}

    def _select_key(self, kid: str):
        jwks = self._get_jwks(refresh=False)
        key_data = self._find_jwk(jwks, kid)
        if key_data is None:
            jwks = self._get_jwks(refresh=True)
            key_data = self._find_jwk(jwks, kid)
        if key_data is None:
            raise AgentIdentityError("agent_access_token_key_unknown")
        try:
            return jwt.PyJWK.from_dict(key_data)
        except Exception as exc:
            raise AgentIdentityError("agent_access_token_key_unknown") from exc

    def _get_jwks(self, *, refresh: bool) -> dict:
        import time

        now = time.time()
        if (
            not refresh
            and self._cached_jwks is not None
            and self._cache_expires_at > now
        ):
            return self._cached_jwks

        self._validate_jwks_url()
        request = Request(self.config.jwks_url, headers={"Accept": "application/json"})
        try:
            with urlopen(request, timeout=self.config.http_timeout_seconds) as response:
                raw_body = response.read(MAX_JWKS_BYTES + 1)
        except (HTTPError, URLError, TimeoutError) as exc:
            raise AgentIdentityError("agent_access_token_key_unknown") from exc

        if len(raw_body) > MAX_JWKS_BYTES:
            raise AgentIdentityError("agent_access_token_key_unknown")

        try:
            jwks = json.loads(raw_body.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise AgentIdentityError("agent_access_token_key_unknown") from exc

        self._validate_jwks_document(jwks)
        self._cached_jwks = jwks
        self._cache_expires_at = now + self.config.jwks_cache_ttl_seconds
        return jwks

    def _validate_jwks_url(self) -> None:
        parsed = urlparse(self.config.jwks_url)
        if parsed.scheme == "https":
            return
        if parsed.scheme == "http":
            local = parsed.hostname in {"127.0.0.1", "localhost"}
            environment = self.config.environment.lower()
            if local and environment in {"local", "test"}:
                return
        raise AgentIdentityError("agent_access_token_key_unknown")

    def _validate_jwks_document(self, jwks: object) -> None:
        if not isinstance(jwks, dict):
            raise AgentIdentityError("agent_access_token_key_unknown")
        keys = jwks.get("keys")
        if not isinstance(keys, list) or len(keys) > MAX_JWKS_KEYS:
            raise AgentIdentityError("agent_access_token_key_unknown")
        for key in keys:
            if not isinstance(key, dict):
                raise AgentIdentityError("agent_access_token_key_unknown")
            if not isinstance(key.get("kid"), str) or not key["kid"].strip():
                raise AgentIdentityError("agent_access_token_key_unknown")

    def _find_jwk(self, jwks: dict, kid: str) -> dict | None:
        for key in jwks.get("keys", []):
            if isinstance(key, dict) and key.get("kid") == kid:
                return key
        return None
