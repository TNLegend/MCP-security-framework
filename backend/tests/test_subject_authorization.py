import os
import sys
import tempfile
import time
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND_DIR = REPO_ROOT / "backend"

sys.path.insert(0, str(BACKEND_DIR))

from app.services.subject_authorization import (  # noqa: E402
    MAX_GRANTS_PER_SUBJECT,
    MAX_SCOPES_PER_GRANT,
    MAX_SUBJECTS,
    SubjectAuthorizationError,
    SubjectAuthorizationResolver,
)


VALID_DOCUMENT = """revision: subject-authorizations-v1
subjects:
  agent-demo:
    role: legal_agent
    grants:
      - capability: filesystem.read
        scopes:
          - contracts
      - capability: filesystem.list
        scopes:
          - lab_root
  agent-contract-reader:
    role: contract_reader
    grants:
      - capability: filesystem.read
        scopes:
          - contracts
  agent-list-only:
    role: file_lister
    grants:
      - capability: filesystem.list
        scopes:
          - lab_root
  agent-no-access:
    role: restricted
    grants: []
"""


class SubjectAuthorizationResolverTests(unittest.TestCase):
    def write_document(self, content: str = VALID_DOCUMENT) -> Path:
        directory = Path(tempfile.mkdtemp())
        path = directory / "agent_authorizations.yaml"
        path.write_text(content, encoding="utf-8")
        return path

    def assert_error_code(self, content: str, expected_code: str) -> None:
        path = self.write_document(content)
        resolver = SubjectAuthorizationResolver(path)

        with self.assertRaises(SubjectAuthorizationError) as ctx:
            resolver.resolve("agent-demo")

        self.assertEqual(ctx.exception.code, expected_code)
        self.assertNotIn(str(path), str(ctx.exception))
        self.assertNotIn("agent-demo", str(ctx.exception))

    def test_valid_file_resolves_agent_demo(self) -> None:
        resolved = SubjectAuthorizationResolver(self.write_document()).resolve("agent-demo")

        self.assertEqual(resolved.authorization_status, "resolved")
        self.assertEqual(resolved.role, "legal_agent")
        self.assertEqual(resolved.authorization_revision, "subject-authorizations-v1")
        self.assertEqual(resolved.allowed_capabilities, ("filesystem.read", "filesystem.list"))

    def test_contract_reader_is_resolved(self) -> None:
        resolved = SubjectAuthorizationResolver(self.write_document()).resolve(
            "agent-contract-reader"
        )

        self.assertEqual(resolved.role, "contract_reader")
        self.assertEqual(resolved.grants[0].capability, "filesystem.read")

    def test_list_only_is_resolved(self) -> None:
        resolved = SubjectAuthorizationResolver(self.write_document()).resolve(
            "agent-list-only"
        )

        self.assertEqual(resolved.role, "file_lister")
        self.assertEqual(resolved.grants[0].scopes, ("lab_root",))

    def test_no_access_agent_is_resolved_with_empty_grants(self) -> None:
        resolved = SubjectAuthorizationResolver(self.write_document()).resolve(
            "agent-no-access"
        )

        self.assertEqual(resolved.authorization_status, "resolved")
        self.assertEqual(resolved.grants, ())
        self.assertEqual(resolved.allowed_capabilities, ())

    def test_unknown_agent_gets_no_grants(self) -> None:
        resolved = SubjectAuthorizationResolver(self.write_document()).resolve(
            "unknown-agent"
        )

        self.assertEqual(resolved.authorization_status, "unknown")
        self.assertEqual(resolved.role, "unknown")
        self.assertEqual(resolved.grants, ())

    def test_missing_file_has_safe_error(self) -> None:
        resolver = SubjectAuthorizationResolver(Path(tempfile.mkdtemp()) / "missing.yaml")

        with self.assertRaises(SubjectAuthorizationError) as ctx:
            resolver.resolve("agent-demo")

        self.assertEqual(ctx.exception.code, "subject_authorization_file_missing")

    def test_unreadable_path_has_safe_error(self) -> None:
        resolver = SubjectAuthorizationResolver(Path(tempfile.mkdtemp()))

        with self.assertRaises(SubjectAuthorizationError) as ctx:
            resolver.resolve("agent-demo")

        self.assertEqual(ctx.exception.code, "subject_authorization_file_unreadable")

    def test_invalid_yaml_has_safe_error(self) -> None:
        self.assert_error_code("revision: [", "subject_authorization_invalid_yaml")

    def test_non_object_document_is_rejected(self) -> None:
        self.assert_error_code("- not\n- object\n", "subject_authorization_invalid_document")

    def test_extra_field_is_rejected(self) -> None:
        self.assert_error_code(
            VALID_DOCUMENT + "unexpected: true\n",
            "subject_authorization_invalid_document",
        )

    def test_missing_revision_is_rejected(self) -> None:
        self.assert_error_code(
            "subjects: {}\n",
            "subject_authorization_invalid_document",
        )

    def test_empty_subject_id_is_rejected(self) -> None:
        self.assert_error_code(
            "revision: subject-authorizations-v1\nsubjects:\n  \"\": {role: legal_agent, grants: []}\n",
            "subject_authorization_invalid_document",
        )

    def test_empty_role_is_rejected(self) -> None:
        self.assert_error_code(
            "revision: subject-authorizations-v1\nsubjects:\n  agent-demo: {role: \"\", grants: []}\n",
            "subject_authorization_invalid_document",
        )

    def test_empty_capability_is_rejected(self) -> None:
        self.assert_error_code(
            "revision: subject-authorizations-v1\nsubjects:\n  agent-demo:\n    role: legal_agent\n    grants:\n      - capability: \"\"\n        scopes: [contracts]\n",
            "subject_authorization_invalid_document",
        )

    def test_empty_scope_is_rejected(self) -> None:
        self.assert_error_code(
            "revision: subject-authorizations-v1\nsubjects:\n  agent-demo:\n    role: legal_agent\n    grants:\n      - capability: filesystem.read\n        scopes: [\"\"]\n",
            "subject_authorization_invalid_document",
        )

    def test_invalid_capability_is_rejected(self) -> None:
        self.assert_error_code(
            "revision: subject-authorizations-v1\nsubjects:\n  agent-demo:\n    role: legal_agent\n    grants:\n      - capability: Filesystem.Read\n        scopes: [contracts]\n",
            "subject_authorization_invalid_document",
        )

    def test_invalid_scope_is_rejected(self) -> None:
        self.assert_error_code(
            "revision: subject-authorizations-v1\nsubjects:\n  agent-demo:\n    role: legal_agent\n    grants:\n      - capability: filesystem.read\n        scopes: [Contracts]\n",
            "subject_authorization_invalid_document",
        )

    def test_duplicate_grant_is_rejected(self) -> None:
        self.assert_error_code(
            "revision: subject-authorizations-v1\nsubjects:\n  agent-demo:\n    role: legal_agent\n    grants:\n      - capability: filesystem.read\n        scopes: [contracts]\n      - capability: filesystem.read\n        scopes: [lab_root]\n",
            "subject_authorization_duplicate_grant",
        )

    def test_duplicate_scope_is_rejected(self) -> None:
        self.assert_error_code(
            "revision: subject-authorizations-v1\nsubjects:\n  agent-demo:\n    role: legal_agent\n    grants:\n      - capability: filesystem.read\n        scopes: [contracts, contracts]\n",
            "subject_authorization_duplicate_grant",
        )

    def test_too_many_subjects_is_rejected(self) -> None:
        subjects = "\n".join(f"  agent-{index}: {{role: legal_agent, grants: []}}" for index in range(MAX_SUBJECTS + 1))
        self.assert_error_code(
            f"revision: subject-authorizations-v1\nsubjects:\n{subjects}\n",
            "subject_authorization_limits_exceeded",
        )

    def test_too_many_grants_is_rejected(self) -> None:
        grants = "\n".join(
            f"      - capability: capability.{index}\n        scopes: [contracts]"
            for index in range(MAX_GRANTS_PER_SUBJECT + 1)
        )
        self.assert_error_code(
            f"revision: subject-authorizations-v1\nsubjects:\n  agent-demo:\n    role: legal_agent\n    grants:\n{grants}\n",
            "subject_authorization_limits_exceeded",
        )

    def test_too_many_scopes_is_rejected(self) -> None:
        scopes = ", ".join(f"scope-{index}" for index in range(MAX_SCOPES_PER_GRANT + 1))
        self.assert_error_code(
            f"revision: subject-authorizations-v1\nsubjects:\n  agent-demo:\n    role: legal_agent\n    grants:\n      - capability: filesystem.read\n        scopes: [{scopes}]\n",
            "subject_authorization_limits_exceeded",
        )

    def test_resolver_returns_immutable_structures(self) -> None:
        resolved = SubjectAuthorizationResolver(self.write_document()).resolve("agent-demo")

        with self.assertRaises(AttributeError):
            resolved.grants[0].scopes += ("other",)

    def test_cache_is_invalidated_after_file_change(self) -> None:
        path = self.write_document()
        resolver = SubjectAuthorizationResolver(path)
        first = resolver.resolve("agent-demo")
        time.sleep(0.01)
        path.write_text(VALID_DOCUMENT.replace("legal_agent", "updated_role"), encoding="utf-8")
        os.utime(path, None)
        second = resolver.resolve("agent-demo")

        self.assertEqual(first.role, "legal_agent")
        self.assertEqual(second.role, "updated_role")

    def test_error_does_not_contain_yaml_content(self) -> None:
        secret_content = "secret-agent"
        path = self.write_document(
            f"revision: subject-authorizations-v1\nsubjects:\n  {secret_content}: {{role: \"\", grants: []}}\n"
        )
        resolver = SubjectAuthorizationResolver(path)

        with self.assertRaises(SubjectAuthorizationError) as ctx:
            resolver.resolve("agent-demo")

        self.assertNotIn(secret_content, str(ctx.exception))

    def test_error_does_not_contain_absolute_path(self) -> None:
        path = self.write_document("revision: [")
        resolver = SubjectAuthorizationResolver(path)

        with self.assertRaises(SubjectAuthorizationError) as ctx:
            resolver.resolve("agent-demo")

        self.assertNotIn(str(path), str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
