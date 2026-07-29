import time
import unittest
from pathlib import Path

from identity_test_helpers import temporary_directory, write_text
from proxy.identity_binding import (
    IdentityBinding,
    IdentityBindingDocument,
    IdentityBindingError,
    IdentityBindingResolver,
    ResolvedIdentityBinding,
)


REPO_ROOT = Path(__file__).resolve().parents[2]


def binding_yaml(*entries: str, revision: str = "identity-bindings-test-v1") -> str:
    body = "\n".join(entries)
    return f"revision: {revision}\nbindings:\n{body}\n"


class IdentityBindingModelTests(unittest.TestCase):
    def test_exact_binding_document_is_accepted(self) -> None:
        document = IdentityBindingDocument.model_validate(
            {
                "revision": "identity-bindings-test-v1",
                "bindings": [
                    {
                        "issuer": "https://issuer.example/",
                        "subject": "external-agent-123",
                        "agent_id": "internal-agent-123",
                    }
                ],
            }
        )

        self.assertEqual(document.bindings[0].agent_id, "internal-agent-123")

    def test_binding_rejects_empty_issuer(self) -> None:
        with self.assertRaises(ValueError):
            IdentityBinding.model_validate(
                {
                    "issuer": "",
                    "subject": "external-agent-123",
                    "agent_id": "internal-agent-123",
                }
            )

    def test_binding_rejects_empty_subject(self) -> None:
        with self.assertRaises(ValueError):
            IdentityBinding.model_validate(
                {
                    "issuer": "https://issuer.example/",
                    "subject": "",
                    "agent_id": "internal-agent-123",
                }
            )

    def test_binding_rejects_empty_agent_id(self) -> None:
        with self.assertRaises(ValueError):
            IdentityBinding.model_validate(
                {
                    "issuer": "https://issuer.example/",
                    "subject": "external-agent-123",
                    "agent_id": "",
                }
            )

    def test_binding_rejects_wildcard_values(self) -> None:
        for field_name in ("issuer", "subject", "agent_id"):
            with self.subTest(field_name=field_name):
                payload = {
                    "issuer": "https://issuer.example/",
                    "subject": "external-agent-123",
                    "agent_id": "internal-agent-123",
                }
                payload[field_name] = "*"
                with self.assertRaises(ValueError):
                    IdentityBinding.model_validate(payload)

    def test_binding_rejects_unknown_fields(self) -> None:
        with self.assertRaises(ValueError):
            IdentityBinding.model_validate(
                {
                    "issuer": "https://issuer.example/",
                    "subject": "external-agent-123",
                    "agent_id": "internal-agent-123",
                    "role": "admin",
                }
            )

    def test_binding_rejects_invalid_agent_id_format(self) -> None:
        with self.assertRaises(ValueError):
            IdentityBinding.model_validate(
                {
                    "issuer": "https://issuer.example/",
                    "subject": "external-agent-123",
                    "agent_id": "Invalid Agent",
                }
            )

    def test_document_rejects_duplicate_issuer_subject(self) -> None:
        with self.assertRaises(ValueError):
            IdentityBindingDocument.model_validate(
                {
                    "revision": "identity-bindings-test-v1",
                    "bindings": [
                        {
                            "issuer": "https://issuer.example/",
                            "subject": "external-agent-123",
                            "agent_id": "agent-one",
                        },
                        {
                            "issuer": "https://issuer.example/",
                            "subject": "external-agent-123",
                            "agent_id": "agent-two",
                        },
                    ],
                }
            )

    def test_document_allows_same_subject_from_different_issuers(self) -> None:
        document = IdentityBindingDocument.model_validate(
            {
                "revision": "identity-bindings-test-v1",
                "bindings": [
                    {
                        "issuer": "https://issuer-one.example/",
                        "subject": "external-agent-123",
                        "agent_id": "agent-one",
                    },
                    {
                        "issuer": "https://issuer-two.example/",
                        "subject": "external-agent-123",
                        "agent_id": "agent-two",
                    },
                ],
            }
        )

        self.assertEqual(len(document.bindings), 2)

    def test_document_rejects_too_many_bindings(self) -> None:
        with self.assertRaises(ValueError):
            IdentityBindingDocument.model_validate(
                {
                    "revision": "identity-bindings-test-v1",
                    "bindings": [
                        {
                            "issuer": f"https://issuer-{index}.example/",
                            "subject": f"subject-{index}",
                            "agent_id": f"agent-{index}",
                        }
                        for index in range(1001)
                    ],
                }
            )


class IdentityBindingResolverTests(unittest.TestCase):
    def test_permanent_lab_bindings_are_configured(self) -> None:
        resolver = IdentityBindingResolver(
            REPO_ROOT / "policies" / "identity_bindings.yaml"
        )
        expected = {
            "service-account-agent-demo": "agent-demo",
            "service-account-llm-agent-demo": "llm-agent-demo",
            "service-account-contract-reader": "agent-contract-reader",
            "service-account-list-only": "agent-list-only",
            "service-account-no-access": "agent-no-access",
        }

        for subject, agent_id in expected.items():
            with self.subTest(subject=subject):
                resolved = resolver.resolve(
                    issuer="http://127.0.0.1:9100/",
                    subject=subject,
                )
                self.assertEqual(resolved.agent_id, agent_id)
                self.assertEqual(resolved.revision, "identity-bindings-v1")

    def test_resolver_returns_exact_issuer_subject_binding(self) -> None:
        with temporary_directory() as directory:
            path = write_text(
                directory / "bindings.yaml",
                binding_yaml(
                    "  - issuer: https://issuer.example/\n"
                    "    subject: external-agent-123\n"
                    "    agent_id: internal-agent-123"
                ),
            )
            resolved = IdentityBindingResolver(path).resolve(
                issuer="https://issuer.example/",
                subject="external-agent-123",
            )

        self.assertEqual(
            resolved,
            ResolvedIdentityBinding(
                agent_id="internal-agent-123",
                revision="identity-bindings-test-v1",
            ),
        )

    def test_resolver_is_case_sensitive_for_issuer_and_subject(self) -> None:
        with temporary_directory() as directory:
            path = write_text(
                directory / "bindings.yaml",
                binding_yaml(
                    "  - issuer: https://issuer.example/\n"
                    "    subject: External-Agent\n"
                    "    agent_id: internal-agent"
                ),
            )
            resolver = IdentityBindingResolver(path)

            with self.assertRaises(IdentityBindingError) as raised:
                resolver.resolve(
                    issuer="https://issuer.example/",
                    subject="external-agent",
                )

        self.assertEqual(raised.exception.code, "agent_identity_binding_not_found")

    def test_resolver_does_not_fallback_to_claimed_agent(self) -> None:
        with temporary_directory() as directory:
            path = write_text(
                directory / "bindings.yaml",
                binding_yaml(
                    "  - issuer: https://issuer.example/\n"
                    "    subject: external-agent\n"
                    "    agent_id: trusted-agent"
                ),
            )
            resolver = IdentityBindingResolver(path)

            with self.assertRaises(IdentityBindingError) as raised:
                resolver.resolve(
                    issuer="https://issuer.example/",
                    subject="claimed-agent",
                )

        self.assertEqual(raised.exception.code, "agent_identity_binding_not_found")

    def test_resolver_reports_missing_file_as_unavailable(self) -> None:
        with temporary_directory() as directory:
            with self.assertRaises(IdentityBindingError) as raised:
                IdentityBindingResolver(directory / "missing.yaml").resolve(
                    issuer="https://issuer.example/",
                    subject="external-agent",
                )

        self.assertEqual(raised.exception.code, "agent_identity_binding_unavailable")

    def test_resolver_reports_invalid_yaml_as_unavailable_without_yaml_content(self) -> None:
        with temporary_directory() as directory:
            path = write_text(directory / "bindings.yaml", "revision: [")

            with self.assertRaises(IdentityBindingError) as raised:
                IdentityBindingResolver(path).resolve(
                    issuer="https://issuer.example/",
                    subject="external-agent",
                )

        self.assertEqual(raised.exception.code, "agent_identity_binding_unavailable")
        self.assertNotIn("revision", str(raised.exception))

    def test_resolver_reports_duplicate_bindings_as_unavailable(self) -> None:
        with temporary_directory() as directory:
            path = write_text(
                directory / "bindings.yaml",
                binding_yaml(
                    "  - issuer: https://issuer.example/\n"
                    "    subject: external-agent\n"
                    "    agent_id: agent-one",
                    "  - issuer: https://issuer.example/\n"
                    "    subject: external-agent\n"
                    "    agent_id: agent-two",
                ),
            )

            with self.assertRaises(IdentityBindingError) as raised:
                IdentityBindingResolver(path).resolve(
                    issuer="https://issuer.example/",
                    subject="external-agent",
                )

        self.assertEqual(raised.exception.code, "agent_identity_binding_unavailable")

    def test_resolver_cache_is_invalidated_by_file_metadata_change(self) -> None:
        with temporary_directory() as directory:
            path = write_text(
                directory / "bindings.yaml",
                binding_yaml(
                    "  - issuer: https://issuer.example/\n"
                    "    subject: external-agent\n"
                    "    agent_id: agent-one",
                    revision="identity-bindings-test-v1",
                ),
            )
            resolver = IdentityBindingResolver(path)
            first = resolver.resolve(
                issuer="https://issuer.example/",
                subject="external-agent",
            )

            time.sleep(0.01)
            write_text(
                path,
                binding_yaml(
                    "  - issuer: https://issuer.example/\n"
                    "    subject: external-agent\n"
                    "    agent_id: agent-two",
                    revision="identity-bindings-test-v2",
                ),
            )
            second = resolver.resolve(
                issuer="https://issuer.example/",
                subject="external-agent",
            )

        self.assertEqual(first.agent_id, "agent-one")
        self.assertEqual(second.agent_id, "agent-two")
        self.assertEqual(second.revision, "identity-bindings-test-v2")


if __name__ == "__main__":
    unittest.main()
