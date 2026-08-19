import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
from unittest.mock import patch

import jwt

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND_DIR = REPO_ROOT / "backend"

sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(BACKEND_DIR))

from identity_test_helpers import (
    _DELETE,
    generate_rsa_identity_key,
    make_access_token,
    make_unsigned_token,
    tamper_jwt_header,
    temporary_jwks_server,
)
from proxy.agent_identity import (
    MAX_ACCESS_TOKEN_BYTES,
    AgentIdentityError,
    JWTJWKSAgentIdentityVerifier,
    VerifiedExternalIdentity,
)
from proxy.identity_config import AgentIdentityConfig


ISSUER = "https://issuer.example/"
AUDIENCE = "mcp-security-proxy"


def identity_config(
    jwks_url: str,
    *,
    issuer: str = ISSUER,
    audience: str = AUDIENCE,
    algorithms: tuple[str, ...] = ("RS256",),
    accepted_types: tuple[str, ...] = ("at+jwt",),
    environment: str = "test",
    timeout: float = 2.0,
    skew: int = 0,
) -> AgentIdentityConfig:
    return AgentIdentityConfig(
        provider="jwt_jwks",
        issuer=issuer,
        audience=audience,
        jwks_url=jwks_url,
        allowed_algorithms=algorithms,
        accepted_types=accepted_types,
        clock_skew_seconds=skew,
        http_timeout_seconds=timeout,
        jwks_cache_ttl_seconds=300,
        environment=environment,
    )


class AgentIdentityJWTTests(unittest.TestCase):
    def setUp(self) -> None:
        self.private_key, self.jwk = generate_rsa_identity_key("rsa-main")

    def verifier(self, jwks_url: str, **kwargs) -> JWTJWKSAgentIdentityVerifier:
        return JWTJWKSAgentIdentityVerifier(identity_config(jwks_url, **kwargs))

    def valid_token(self, **kwargs) -> str:
        params = {
            "kid": "rsa-main",
            "issuer": ISSUER,
            "audience": AUDIENCE,
        }
        params.update(kwargs)
        return make_access_token(
            self.private_key,
            **params,
        )

    def assert_token_error(self, token, expected_code: str, *, jwks=None, **config) -> None:
        with temporary_jwks_server(jwks or {"keys": [self.jwk]}) as url:
            with self.assertRaises(AgentIdentityError) as raised:
                self.verifier(url, **config).verify(token)
        self.assertEqual(raised.exception.code, expected_code)
        if token:
            self.assertNotIn(str(token), str(raised.exception))

    def test_valid_token_returns_verified_external_identity(self) -> None:
        token = self.valid_token()

        with temporary_jwks_server({"keys": [self.jwk]}) as url:
            identity = self.verifier(url).verify(token)

        self.assertIsInstance(identity, VerifiedExternalIdentity)
        self.assertEqual(identity.issuer, ISSUER)
        self.assertEqual(identity.subject, "agent-demo")
        self.assertEqual(identity.audience, (AUDIENCE,))
        self.assertEqual(identity.token_id, "token-id-001")

    def test_valid_token_with_client_id_preserves_safe_client_id(self) -> None:
        token = self.valid_token(claims_override={"client_id": "client-demo"})

        with temporary_jwks_server({"keys": [self.jwk]}) as url:
            identity = self.verifier(url).verify(token)

        self.assertEqual(identity.client_id, "client-demo")

    def test_valid_token_with_audience_list_is_accepted(self) -> None:
        token = self.valid_token(audience=[AUDIENCE, "other-audience"])

        with temporary_jwks_server({"keys": [self.jwk]}) as url:
            identity = self.verifier(url).verify(token)

        self.assertEqual(identity.audience, (AUDIENCE, "other-audience"))

    def test_unknown_kid_refreshes_jwks_for_key_rotation(self) -> None:
        rotated_private_key, rotated_jwk = generate_rsa_identity_key("rsa-rotated")
        token = make_access_token(
            rotated_private_key,
            kid="rsa-rotated",
            issuer=ISSUER,
            audience=AUDIENCE,
        )
        verifier = self.verifier("http://127.0.0.1:1/jwks.json")
        with patch.object(
            verifier,
            "_get_jwks",
            side_effect=[{"keys": [self.jwk]}, {"keys": [rotated_jwk]}],
        ) as get_jwks:
            identity = verifier.verify(token)

        self.assertEqual(identity.subject, "agent-demo")
        self.assertEqual(get_jwks.call_count, 2)
        self.assertFalse(get_jwks.call_args_list[0].kwargs["refresh"])
        self.assertTrue(get_jwks.call_args_list[1].kwargs["refresh"])

    def test_header_jku_is_ignored_and_configured_jwks_is_used(self) -> None:
        token = self.valid_token(
            extra_headers={"jku": "https://attacker.example/jwks.json"}
        )

        with temporary_jwks_server({"keys": [self.jwk]}) as url:
            identity = self.verifier(url).verify(token)

        self.assertEqual(identity.subject, "agent-demo")

    def test_header_x5u_is_ignored_and_configured_jwks_is_used(self) -> None:
        token = self.valid_token(
            extra_headers={"x5u": "https://attacker.example/cert.pem"}
        )

        with temporary_jwks_server({"keys": [self.jwk]}) as url:
            identity = self.verifier(url).verify(token)

        self.assertEqual(identity.subject, "agent-demo")

    def test_http_jwks_localhost_is_allowed_in_local_environment(self) -> None:
        token = self.valid_token()

        with temporary_jwks_server({"keys": [self.jwk]}) as url:
            identity = self.verifier(url, environment="local").verify(token)

        self.assertEqual(identity.subject, "agent-demo")

    def test_http_jwks_localhost_is_allowed_in_test_environment(self) -> None:
        token = self.valid_token()

        with temporary_jwks_server({"keys": [self.jwk]}) as url:
            identity = self.verifier(url, environment="test").verify(token)

        self.assertEqual(identity.subject, "agent-demo")

    def test_http_jwks_remote_is_rejected_in_production(self) -> None:
        token = self.valid_token()

        with self.assertRaises(AgentIdentityError) as raised:
            self.verifier(
                "http://identity.example/jwks.json",
                environment="production",
            ).verify(token)

        self.assertEqual(raised.exception.code, "agent_access_token_key_unknown")


def _make_error_test(name, token_factory, expected_code, jwks_factory=None, config=None):
    def test(self) -> None:
        token = token_factory(self)
        jwks = jwks_factory(self) if jwks_factory else {"keys": [self.jwk]}
        self.assert_token_error(token, expected_code, jwks=jwks, **(config or {}))

    test.__name__ = name
    return test


ERROR_CASES = [
    (
        "test_missing_token_is_rejected",
        lambda self: None,
        "agent_access_token_missing",
    ),
    (
        "test_empty_token_is_rejected",
        lambda self: "",
        "agent_access_token_missing",
    ),
    (
        "test_too_large_token_is_rejected",
        lambda self: "a" * (MAX_ACCESS_TOKEN_BYTES + 1),
        "agent_access_token_too_large",
    ),
    (
        "test_malformed_token_is_rejected",
        lambda self: "not-a-jwt",
        "agent_access_token_malformed",
    ),
    (
        "test_signature_invalid_is_rejected",
        lambda self: make_access_token(
            generate_rsa_identity_key("other")[0],
            kid="rsa-main",
            issuer=ISSUER,
            audience=AUDIENCE,
        ),
        "agent_access_token_signature_invalid",
    ),
    (
        "test_alg_none_is_rejected",
        lambda self: make_unsigned_token(kid="rsa-main"),
        "agent_access_token_algorithm_invalid",
    ),
    (
        "test_disallowed_algorithm_is_rejected",
        lambda self: self.valid_token(extra_headers={"alg": "RS512"}),
        "agent_access_token_algorithm_invalid",
    ),
    (
        "test_missing_typ_is_rejected",
        lambda self: tamper_jwt_header(self.valid_token(), {"typ": _DELETE}),
        "agent_access_token_type_invalid",
    ),
    (
        "test_wrong_typ_is_rejected",
        lambda self: self.valid_token(token_type="JWT"),
        "agent_access_token_type_invalid",
    ),
    (
        "test_missing_kid_is_rejected",
        lambda self: tamper_jwt_header(self.valid_token(), {"kid": _DELETE}),
        "agent_access_token_key_unknown",
    ),
    (
        "test_unknown_kid_is_rejected",
        lambda self: make_access_token(
            self.private_key,
            kid="unknown-kid",
            issuer=ISSUER,
            audience=AUDIENCE,
        ),
        "agent_access_token_key_unknown",
    ),
    (
        "test_wrong_issuer_is_rejected",
        lambda self: self.valid_token(issuer="https://other-issuer.example/"),
        "agent_access_token_issuer_invalid",
    ),
    (
        "test_wrong_audience_is_rejected",
        lambda self: self.valid_token(audience="other-audience"),
        "agent_access_token_audience_invalid",
    ),
    (
        "test_missing_subject_is_rejected",
        lambda self: self.valid_token(subject=None),
        "agent_access_token_malformed",
    ),
    (
        "test_empty_subject_is_rejected",
        lambda self: self.valid_token(subject=""),
        "agent_access_token_malformed",
    ),
    (
        "test_missing_exp_is_rejected",
        lambda self: self.valid_token(claims_override={"exp": _DELETE}),
        "agent_access_token_malformed",
    ),
    (
        "test_expired_token_is_rejected",
        lambda self: self.valid_token(lifetime_seconds=-30),
        "agent_access_token_expired",
    ),
    (
        "test_not_yet_valid_token_is_rejected",
        lambda self: self.valid_token(not_before_offset_seconds=60),
        "agent_access_token_not_yet_valid",
    ),
    (
        "test_future_iat_is_rejected",
        lambda self: self.valid_token(issued_offset_seconds=60),
        "agent_access_token_not_yet_valid",
    ),
    (
        "test_missing_iat_is_rejected",
        lambda self: self.valid_token(claims_override={"iat": _DELETE}),
        "agent_access_token_malformed",
    ),
    (
        "test_missing_jti_is_rejected",
        lambda self: self.valid_token(token_id=None),
        "agent_access_token_malformed",
    ),
    (
        "test_empty_jti_is_rejected",
        lambda self: self.valid_token(token_id=""),
        "agent_access_token_malformed",
    ),
    (
        "test_empty_audience_is_rejected",
        lambda self: self.valid_token(audience=[]),
        "agent_access_token_audience_invalid",
    ),
    (
        "test_non_string_audience_item_is_rejected",
        lambda self: self.valid_token(audience=[AUDIENCE, 123]),
        "agent_access_token_audience_invalid",
    ),
    (
        "test_jwks_without_key_is_rejected",
        lambda self: self.valid_token(),
        "agent_access_token_key_unknown",
        lambda self: {"keys": []},
    ),
    (
        "test_jwks_invalid_json_is_rejected",
        lambda self: self.valid_token(),
        "agent_access_token_key_unknown",
        lambda self: {"keys": "not-a-list"},
    ),
    (
        "test_jwks_too_many_keys_is_rejected",
        lambda self: self.valid_token(),
        "agent_access_token_key_unknown",
        lambda self: {"keys": [{"kid": f"key-{index}"} for index in range(21)]},
    ),
]


for case in ERROR_CASES:
    name, token_factory, expected, *rest = case
    setattr(
        AgentIdentityJWTTests,
        name,
        _make_error_test(
            name,
            token_factory,
            expected,
            rest[0] if rest else None,
        ),
    )


class AgentIdentityJWKSDocumentTests(unittest.TestCase):
    def test_jwks_body_too_large_is_rejected(self) -> None:
        private_key, jwk = generate_rsa_identity_key("rsa-main")
        token = make_access_token(
            private_key,
            kid="rsa-main",
            issuer=ISSUER,
            audience=AUDIENCE,
        )
        with temporary_jwks_server(raw_body=b"{" + b"a" * 262_144 + b"}") as url:
            verifier = JWTJWKSAgentIdentityVerifier(identity_config(url))
            with self.assertRaises(AgentIdentityError) as raised:
                verifier.verify(token)

        self.assertEqual(raised.exception.code, "agent_access_token_key_unknown")
        self.assertNotIn(token, str(raised.exception))

    def test_jwks_document_must_be_an_object(self) -> None:
        private_key, _ = generate_rsa_identity_key("rsa-main")
        token = make_access_token(
            private_key,
            kid="rsa-main",
            issuer=ISSUER,
            audience=AUDIENCE,
        )
        with temporary_jwks_server(raw_body=b"[]") as url:
            verifier = JWTJWKSAgentIdentityVerifier(identity_config(url))
            with self.assertRaises(AgentIdentityError) as raised:
                verifier.verify(token)

        self.assertEqual(raised.exception.code, "agent_access_token_key_unknown")

    def test_jwks_key_entries_must_be_objects(self) -> None:
        private_key, _ = generate_rsa_identity_key("rsa-main")
        token = make_access_token(
            private_key,
            kid="rsa-main",
            issuer=ISSUER,
            audience=AUDIENCE,
        )
        with temporary_jwks_server({"keys": ["not-a-key"]}) as url:
            verifier = JWTJWKSAgentIdentityVerifier(identity_config(url))
            with self.assertRaises(AgentIdentityError) as raised:
                verifier.verify(token)

        self.assertEqual(raised.exception.code, "agent_access_token_key_unknown")


if __name__ == "__main__":
    unittest.main()
