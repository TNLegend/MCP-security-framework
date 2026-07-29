from dataclasses import dataclass
from datetime import datetime, timezone
import hmac
import json
from pathlib import Path
from typing import Any

import jwt

from app.core.config import settings
from app.services.identity_context_hash import runtime_context_hash


ASSERTION_TYPE = "mcp-identity+jwt"
ASSERTION_ALGORITHM = "EdDSA"
MAX_ASSERTION_BYTES = 16_384
MAX_ASSERTION_JWKS_BYTES = 262_144
MAX_ASSERTION_JWKS_KEYS = 20


class InternalIdentityAssertionError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class VerifiedInternalIdentityAssertion:
    issuer: str
    subject: str
    audience: tuple[str, ...]
    token_id: str
    session_id: str
    binding_revision: str
    issued_at: datetime
    expires_at: datetime


class InternalIdentityAssertionVerifier:
    def __init__(
        self,
        *,
        jwks_path: Path | None = None,
        expected_issuer: str | None = None,
        expected_audience: str | None = None,
        max_ttl_seconds: int | None = None,
        clock_skew_seconds: int | None = None,
    ) -> None:
        self.jwks_path = jwks_path or Path(settings.backend_assertion_jwks_path)
        self.expected_issuer = (
            expected_issuer or settings.backend_assertion_expected_issuer
        )
        self.expected_audience = (
            expected_audience or settings.backend_assertion_expected_audience
        )
        self.max_ttl_seconds = (
            max_ttl_seconds or settings.backend_assertion_max_ttl_seconds
        )
        self.clock_skew_seconds = (
            clock_skew_seconds or settings.backend_assertion_clock_skew_seconds
        )

    def verify(
        self,
        *,
        assertion: str | None,
        context: dict[str, Any],
    ) -> VerifiedInternalIdentityAssertion:
        self._validate_assertion_shape(assertion)
        assert assertion is not None
        header = self._safe_header(assertion)
        key = self._select_key(header["kid"])

        try:
            claims = jwt.decode(
                assertion,
                key=key.key,
                algorithms=[ASSERTION_ALGORITHM],
                issuer=self.expected_issuer,
                audience=self.expected_audience,
                leeway=self.clock_skew_seconds,
                options={
                    "require": [
                        "iss",
                        "aud",
                        "sub",
                        "iat",
                        "nbf",
                        "exp",
                        "jti",
                        "sid",
                        "ctx_hash",
                        "identity_binding_revision",
                        "session_reference",
                        "tool_profile_revision",
                        "resource_registry_revision",
                    ],
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_iat": True,
                    "verify_aud": True,
                    "verify_iss": True,
                },
            )
        except jwt.ExpiredSignatureError as exc:
            raise InternalIdentityAssertionError("identity_assertion_expired") from exc
        except jwt.ImmatureSignatureError as exc:
            raise InternalIdentityAssertionError(
                "identity_assertion_not_yet_valid"
            ) from exc
        except jwt.InvalidIssuerError as exc:
            raise InternalIdentityAssertionError(
                "identity_assertion_issuer_invalid"
            ) from exc
        except jwt.InvalidAudienceError as exc:
            raise InternalIdentityAssertionError(
                "identity_assertion_audience_invalid"
            ) from exc
        except jwt.InvalidSignatureError as exc:
            raise InternalIdentityAssertionError(
                "identity_assertion_signature_invalid"
            ) from exc
        except jwt.PyJWTError as exc:
            raise InternalIdentityAssertionError("identity_assertion_malformed") from exc

        self._validate_claims(claims, context)
        audience = claims["aud"]
        audience_tuple = (audience,) if isinstance(audience, str) else tuple(audience)
        return VerifiedInternalIdentityAssertion(
            issuer=claims["iss"],
            subject=claims["sub"],
            audience=audience_tuple,
            token_id=claims["jti"],
            session_id=claims["sid"],
            binding_revision=claims["identity_binding_revision"],
            issued_at=datetime.fromtimestamp(claims["iat"], timezone.utc),
            expires_at=datetime.fromtimestamp(claims["exp"], timezone.utc),
        )

    def _validate_assertion_shape(self, assertion: str | None) -> None:
        if not assertion:
            raise InternalIdentityAssertionError("identity_assertion_missing")
        if not isinstance(assertion, str):
            raise InternalIdentityAssertionError("identity_assertion_malformed")
        if len(assertion.encode("utf-8")) > MAX_ASSERTION_BYTES:
            raise InternalIdentityAssertionError("identity_assertion_too_large")
        if assertion.count(".") != 2:
            raise InternalIdentityAssertionError("identity_assertion_malformed")

    def _safe_header(self, assertion: str) -> dict[str, str]:
        try:
            header = jwt.get_unverified_header(assertion)
        except jwt.PyJWTError as exc:
            raise InternalIdentityAssertionError("identity_assertion_malformed") from exc

        if header.get("typ") != ASSERTION_TYPE:
            raise InternalIdentityAssertionError("identity_assertion_type_invalid")
        if header.get("alg") != ASSERTION_ALGORITHM:
            raise InternalIdentityAssertionError("identity_assertion_algorithm_invalid")
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid.strip():
            raise InternalIdentityAssertionError("identity_assertion_key_unknown")
        return {"kid": kid}

    def _select_key(self, kid: str):
        jwks = self._load_jwks()
        for key_data in jwks["keys"]:
            if key_data.get("kid") == kid:
                try:
                    return jwt.PyJWK.from_dict(key_data)
                except Exception as exc:
                    raise InternalIdentityAssertionError(
                        "identity_assertion_key_unknown"
                    ) from exc
        raise InternalIdentityAssertionError("identity_assertion_key_unknown")

    def _load_jwks(self) -> dict[str, Any]:
        try:
            raw_body = self.jwks_path.read_bytes()
        except OSError as exc:
            raise InternalIdentityAssertionError(
                "identity_assertion_key_unknown"
            ) from exc
        if len(raw_body) > MAX_ASSERTION_JWKS_BYTES:
            raise InternalIdentityAssertionError("identity_assertion_key_unknown")
        try:
            jwks = json.loads(raw_body.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise InternalIdentityAssertionError(
                "identity_assertion_key_unknown"
            ) from exc
        if not isinstance(jwks, dict):
            raise InternalIdentityAssertionError("identity_assertion_key_unknown")
        keys = jwks.get("keys")
        if not isinstance(keys, list) or len(keys) > MAX_ASSERTION_JWKS_KEYS:
            raise InternalIdentityAssertionError("identity_assertion_key_unknown")
        for key in keys:
            if not isinstance(key, dict):
                raise InternalIdentityAssertionError("identity_assertion_key_unknown")
            if not isinstance(key.get("kid"), str) or not key["kid"].strip():
                raise InternalIdentityAssertionError("identity_assertion_key_unknown")
        return jwks

    def _validate_claims(self, claims: dict[str, Any], context: dict[str, Any]) -> None:
        for key in (
            "iss",
            "sub",
            "jti",
            "sid",
            "ctx_hash",
            "identity_binding_revision",
            "session_reference",
            "tool_profile_revision",
            "resource_registry_revision",
        ):
            if not isinstance(claims.get(key), str) or not claims[key].strip():
                raise InternalIdentityAssertionError("identity_assertion_malformed")
        if not isinstance(claims.get("iat"), int) or not isinstance(claims.get("exp"), int):
            raise InternalIdentityAssertionError("identity_assertion_malformed")
        if claims["exp"] - claims["iat"] > self.max_ttl_seconds:
            raise InternalIdentityAssertionError("identity_assertion_ttl_invalid")
        if claims["sid"] != context["runtime"]["session_id"]:
            raise InternalIdentityAssertionError("identity_assertion_session_mismatch")
        if claims["sub"] != context["subject"]["agent_id"]:
            raise InternalIdentityAssertionError("identity_assertion_subject_mismatch")
        if (
            claims["identity_binding_revision"]
            != context["subject"]["identity_binding_revision"]
        ):
            raise InternalIdentityAssertionError("identity_assertion_request_mismatch")
        if claims["session_reference"] != context["subject"]["session_reference"]:
            raise InternalIdentityAssertionError("identity_assertion_session_mismatch")
        if claims["tool_profile_revision"] != context["tool"]["profile_revision"]:
            raise InternalIdentityAssertionError("identity_assertion_request_mismatch")
        if (
            claims["resource_registry_revision"]
            != context["request"]["resource_registry_revision"]
        ):
            raise InternalIdentityAssertionError("identity_assertion_request_mismatch")
        expected_hash = runtime_context_hash(context)
        if not hmac.compare_digest(claims["ctx_hash"], expected_hash):
            raise InternalIdentityAssertionError("identity_assertion_request_mismatch")
