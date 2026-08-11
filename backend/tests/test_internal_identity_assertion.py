import copy
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import jwt

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND_DIR = REPO_ROOT / "backend"

sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(BACKEND_DIR))

from app.services.identity_context_hash import runtime_context_hash
from app.services.internal_identity_assertion import (
    ASSERTION_ALGORITHM,
    ASSERTION_TYPE,
    MAX_ASSERTION_BYTES,
    InternalIdentityAssertionError as BackendAssertionError,
    InternalIdentityAssertionVerifier,
    VerifiedInternalIdentityAssertion,
)
from identity_test_helpers import (
    _DELETE,
    generate_ed25519_assertion_key,
    runtime_context,
    tamper_jwt_header,
    tamper_jwt_payload,
    temporary_directory,
    write_bytes,
    write_json,
)
from proxy.identity_config import ProxyAssertionConfig
from proxy.internal_identity_assertion import (
    InternalIdentityAssertionError as ProxyAssertionError,
    InternalIdentityAssertionSigner,
)


ASSERTION_ISSUER = "mcp-security-proxy"
ASSERTION_AUDIENCE = "mcp-security-backend"


class InternalIdentityAssertionTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_context = temporary_directory()
        self.directory = self.temp_context.__enter__()
        self.private_key, self.private_pem, self.jwk = generate_ed25519_assertion_key(
            "ed-main"
        )
        self.private_key_path = write_bytes(self.directory / "ed-main.pem", self.private_pem)
        self.jwks_path = write_json(self.directory / "assertion-jwks.json", {"keys": [self.jwk]})

    def tearDown(self) -> None:
        self.temp_context.__exit__(None, None, None)

    def signer(self, *, key_id: str = "ed-main", key_path: Path | None = None):
        return InternalIdentityAssertionSigner(
            ProxyAssertionConfig(
                issuer=ASSERTION_ISSUER,
                audience=ASSERTION_AUDIENCE,
                private_key_path=key_path or self.private_key_path,
                key_id=key_id,
                max_ttl_seconds=30,
            )
        )

    def verifier(
        self,
        *,
        jwks_path: Path | None = None,
        issuer: str = ASSERTION_ISSUER,
        audience: str = ASSERTION_AUDIENCE,
        max_ttl: int = 30,
        skew: int = 0,
    ):
        return InternalIdentityAssertionVerifier(
            jwks_path=jwks_path or self.jwks_path,
            expected_issuer=issuer,
            expected_audience=audience,
            max_ttl_seconds=max_ttl,
            clock_skew_seconds=skew,
        )

    def sign(self, context: dict[str, Any] | None = None) -> str:
        return self.signer().sign(context or runtime_context())

    def manual_assertion(
        self,
        context: dict[str, Any],
        *,
        claims_override: dict[str, Any] | None = None,
        headers_override: dict[str, Any] | None = None,
        private_key=None,
        kid: str = "ed-main",
    ) -> str:
        now = datetime.now(timezone.utc)
        claims: dict[str, Any] = {
            "iss": ASSERTION_ISSUER,
            "aud": ASSERTION_AUDIENCE,
            "sub": context["subject"]["agent_id"],
            "iat": int(now.timestamp()),
            "nbf": int(now.timestamp()),
            "exp": int((now + timedelta(seconds=30)).timestamp()),
            "jti": "manual-jti-001",
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
        if claims_override:
            for key, value in claims_override.items():
                if value is _DELETE:
                    claims.pop(key, None)
                else:
                    claims[key] = value

        headers: dict[str, Any] = {
            "typ": ASSERTION_TYPE,
            "kid": kid,
            "alg": ASSERTION_ALGORITHM,
        }
        if headers_override:
            for key, value in headers_override.items():
                if value is _DELETE:
                    headers.pop(key, None)
                else:
                    headers[key] = value

        return jwt.encode(
            claims,
            private_key or self.private_key,
            algorithm=ASSERTION_ALGORITHM,
            headers=headers,
        )

    def assert_assertion_error(
        self,
        assertion: str | None,
        expected_code: str,
        *,
        context: dict[str, Any] | None = None,
        verifier: InternalIdentityAssertionVerifier | None = None,
    ) -> None:
        with self.assertRaises(BackendAssertionError) as raised:
            (verifier or self.verifier()).verify(
                assertion=assertion,
                context=context or runtime_context(),
            )
        self.assertEqual(raised.exception.code, expected_code)
        self.assertNotIn(str(assertion), str(raised.exception))

    def test_valid_assertion_is_verified(self) -> None:
        context = runtime_context()
        assertion = self.sign(context)

        verified = self.verifier().verify(assertion=assertion, context=context)

        self.assertIsInstance(verified, VerifiedInternalIdentityAssertion)
        self.assertEqual(verified.issuer, ASSERTION_ISSUER)
        self.assertEqual(verified.subject, "agent-demo")
        self.assertEqual(verified.session_id, "session-001")
        self.assertEqual(verified.binding_revision, "identity-bindings-test-v1")

    def test_signer_refuses_private_key_inside_repository(self) -> None:
        repo_key_path = Path(__file__).resolve()

        with self.assertRaises(ProxyAssertionError) as raised:
            self.signer(key_path=repo_key_path).sign(runtime_context())

        self.assertEqual(raised.exception.code, "identity_assertion_key_unavailable")

    def test_assertion_uses_expected_compact_header(self) -> None:
        assertion = self.sign(runtime_context())
        header = jwt.get_unverified_header(assertion)

        self.assertEqual(header["typ"], ASSERTION_TYPE)
        self.assertEqual(header["alg"], ASSERTION_ALGORITHM)
        self.assertEqual(header["kid"], "ed-main")

    def test_previous_rotation_key_is_accepted_while_in_jwks(self) -> None:
        previous_private, previous_pem, previous_jwk = generate_ed25519_assertion_key(
            "ed-previous"
        )
        previous_path = write_bytes(self.directory / "ed-previous.pem", previous_pem)
        jwks_path = write_json(
            self.directory / "rotated-jwks.json",
            {"keys": [self.jwk, previous_jwk]},
        )
        context = runtime_context()
        assertion = self.signer(key_id="ed-previous", key_path=previous_path).sign(
            context
        )

        verified = self.verifier(jwks_path=jwks_path).verify(
            assertion=assertion,
            context=context,
        )

        self.assertEqual(verified.subject, "agent-demo")

    def test_removed_rotation_key_is_rejected(self) -> None:
        _, previous_pem, _ = generate_ed25519_assertion_key("ed-previous")
        previous_path = write_bytes(self.directory / "ed-previous.pem", previous_pem)
        assertion = self.signer(key_id="ed-previous", key_path=previous_path).sign(
            runtime_context()
        )

        self.assert_assertion_error(assertion, "identity_assertion_key_unknown")

    def test_non_lab_scope_is_hashable_and_verifiable(self) -> None:
        context = runtime_context(
            request={
                "resource_scope": "fs.windows.user_documents",
                "canonical_resource": "documents/contracts/report.txt",
                "arguments": {"path": "documents/contracts/report.txt"},
            }
        )
        assertion = self.sign(context)

        verified = self.verifier().verify(assertion=assertion, context=context)

        self.assertEqual(verified.subject, "agent-demo")

    def test_canonical_hash_is_deterministic_for_equivalent_context(self) -> None:
        context = runtime_context()
        reordered = {
            "runtime": copy.deepcopy(context["runtime"]),
            "request": copy.deepcopy(context["request"]),
            "tool": copy.deepcopy(context["tool"]),
            "server": copy.deepcopy(context["server"]),
            "subject": copy.deepcopy(context["subject"]),
        }

        self.assertEqual(runtime_context_hash(context), runtime_context_hash(reordered))


def _make_assertion_error_test(name, assertion_factory, expected_code):
    def test(self) -> None:
        context = runtime_context()
        assertion = assertion_factory(self, context)
        self.assert_assertion_error(assertion, expected_code, context=context)

    test.__name__ = name
    return test


def tamper_jwt_signature(token: str) -> str:
    header, payload, signature = token.split(".")
    replacement = "A" if signature[0] != "A" else "B"
    return ".".join((header, payload, replacement + signature[1:]))


now = datetime.now(timezone.utc)
ASSERTION_ERROR_CASES = [
    (
        "test_missing_assertion_is_rejected",
        lambda self, context: None,
        "identity_assertion_missing",
    ),
    (
        "test_malformed_assertion_is_rejected",
        lambda self, context: "not-a-jwt",
        "identity_assertion_malformed",
    ),
    (
        "test_too_large_assertion_is_rejected",
        lambda self, context: "a" * (MAX_ASSERTION_BYTES + 1),
        "identity_assertion_too_large",
    ),
    (
        "test_signature_altered_is_rejected",
        lambda self, context: tamper_jwt_signature(self.sign(context)),
        "identity_assertion_signature_invalid",
    ),
    (
        "test_payload_altered_is_rejected",
        lambda self, context: tamper_jwt_payload(
            self.sign(context),
            {"sub": "attacker"},
        ),
        "identity_assertion_signature_invalid",
    ),
    (
        "test_algorithm_in_header_must_be_eddsa",
        lambda self, context: tamper_jwt_header(self.sign(context), {"alg": "HS256"}),
        "identity_assertion_algorithm_invalid",
    ),
    (
        "test_type_in_header_must_match",
        lambda self, context: tamper_jwt_header(self.sign(context), {"typ": "JWT"}),
        "identity_assertion_type_invalid",
    ),
    (
        "test_missing_kid_is_rejected",
        lambda self, context: tamper_jwt_header(self.sign(context), {"kid": _DELETE}),
        "identity_assertion_key_unknown",
    ),
    (
        "test_unknown_kid_is_rejected",
        lambda self, context: self.manual_assertion(context, kid="unknown-kid"),
        "identity_assertion_key_unknown",
    ),
    (
        "test_wrong_issuer_is_rejected",
        lambda self, context: self.manual_assertion(
            context,
            claims_override={"iss": "other-issuer"},
        ),
        "identity_assertion_issuer_invalid",
    ),
    (
        "test_wrong_audience_is_rejected",
        lambda self, context: self.manual_assertion(
            context,
            claims_override={"aud": "other-audience"},
        ),
        "identity_assertion_audience_invalid",
    ),
    (
        "test_expired_assertion_is_rejected",
        lambda self, context: self.manual_assertion(
            context,
            claims_override={
                "iat": int((now - timedelta(seconds=60)).timestamp()),
                "nbf": int((now - timedelta(seconds=60)).timestamp()),
                "exp": int((now - timedelta(seconds=30)).timestamp()),
            },
        ),
        "identity_assertion_expired",
    ),
    (
        "test_future_nbf_is_rejected",
        lambda self, context: self.manual_assertion(
            context,
            claims_override={"nbf": int((now + timedelta(seconds=60)).timestamp())},
        ),
        "identity_assertion_not_yet_valid",
    ),
    (
        "test_future_iat_is_rejected",
        lambda self, context: self.manual_assertion(
            context,
            claims_override={"iat": int((now + timedelta(seconds=60)).timestamp())},
        ),
        "identity_assertion_not_yet_valid",
    ),
    (
        "test_ttl_above_maximum_is_rejected",
        lambda self, context: self.manual_assertion(
            context,
            claims_override={
                "iat": int(now.timestamp()),
                "nbf": int(now.timestamp()),
                "exp": int((now + timedelta(seconds=300)).timestamp()),
            },
        ),
        "identity_assertion_ttl_invalid",
    ),
    (
        "test_missing_jti_is_rejected",
        lambda self, context: self.manual_assertion(
            context,
            claims_override={"jti": _DELETE},
        ),
        "identity_assertion_malformed",
    ),
    (
        "test_empty_jti_is_rejected",
        lambda self, context: self.manual_assertion(
            context,
            claims_override={"jti": ""},
        ),
        "identity_assertion_malformed",
    ),
]


for case_name, factory, code in ASSERTION_ERROR_CASES:
    setattr(
        InternalIdentityAssertionTestCase,
        case_name,
        _make_assertion_error_test(case_name, factory, code),
    )


def _make_context_mismatch_test(name, mutator):
    def test(self) -> None:
        context = runtime_context()
        assertion = self.sign(context)
        changed = runtime_context()
        mutator(changed)

        self.assert_assertion_error(
            assertion,
            "identity_assertion_request_mismatch",
            context=changed,
        )

    test.__name__ = name
    return test


CONTEXT_MISMATCH_CASES = [
    (
        "test_context_hash_detects_argument_change",
        lambda context: context["request"]["arguments"].update({"path": ".env"}),
    ),
    (
        "test_context_hash_detects_canonical_resource_change",
        lambda context: context["request"].update({"canonical_resource": ".env"}),
    ),
    (
        "test_context_hash_detects_required_capability_change",
        lambda context: context["request"].update({"required_capability": "filesystem.list"}),
    ),
    (
        "test_context_hash_detects_resource_scope_change",
        lambda context: context["request"].update({"resource_scope": "sensitive"}),
    ),
    (
        "test_context_hash_detects_tool_change",
        lambda context: context["tool"].update({"name": "list_files"}),
    ),
    (
        "test_context_hash_detects_server_change",
        lambda context: context["server"].update({"id": 2}),
    ),
    (
        "test_context_hash_detects_environment_change",
        lambda context: context["runtime"].update({"environment": "prod"}),
    ),
    (
        "test_context_hash_detects_binding_revision_change",
        lambda context: context["subject"].update(
            {"identity_binding_revision": "identity-bindings-test-v2"}
        ),
    ),
    (
        "test_context_hash_detects_operation_change",
        lambda context: context["request"].update({"operation": "list"}),
    ),
    (
        "test_context_hash_detects_output_estimate_change",
        lambda context: context["request"].update({"estimated_output_size_mb": 5.0}),
    ),
]


for case_name, mutator in CONTEXT_MISMATCH_CASES:
    setattr(
        InternalIdentityAssertionTestCase,
        case_name,
        _make_context_mismatch_test(case_name, mutator),
    )


class InternalIdentityAssertionDirectMismatchTests(InternalIdentityAssertionTestCase):
    def test_session_mismatch_has_specific_code(self) -> None:
        context = runtime_context()
        assertion = self.sign(context)
        changed = runtime_context(runtime={"session_id": "other-session"})

        self.assert_assertion_error(
            assertion,
            "identity_assertion_session_mismatch",
            context=changed,
        )

    def test_subject_mismatch_has_specific_code(self) -> None:
        context = runtime_context()
        assertion = self.sign(context)
        changed = runtime_context(subject={"agent_id": "other-agent"})

        self.assert_assertion_error(
            assertion,
            "identity_assertion_subject_mismatch",
            context=changed,
        )


if __name__ == "__main__":
    unittest.main()
