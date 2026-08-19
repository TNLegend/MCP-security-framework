from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path
import sys
import unittest

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool


ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend"
for path in (str(ROOT), str(BACKEND)):
    if path not in sys.path:
        sys.path.insert(0, path)

import app.models  # noqa: E402,F401
from app.db.database import Base  # noqa: E402
from app.models.control_plane import (  # noqa: E402
    ControlPlaneConfigRevision,
    ControlPlaneState,
    ControlPlaneUser,
    EmergencyDeny,
)
from app.models.trusted_agent_session import TrustedAgentSession  # noqa: E402
from app.schemas.control_plane import ControlPlaneConfigContent  # noqa: E402
from app.services.config_v2_migration import create_v2_migration_draft  # noqa: E402
from app.services.control_plane_config import (  # noqa: E402
    create_revision,
    publish_revision,
    rollback_to_revision,
)
from app.services.emergency_deny import (  # noqa: E402
    EmergencyDenyError,
    check_emergency_deny,
)
from app.services.published_configuration import (  # noqa: E402
    PublishedConfigurationError,
    PublishedConfigurationProvider,
)
from proxy.identity_binding import IdentityBinding, IdentityBindingDocument  # noqa: E402
from proxy.resource_registry import ResourceScopeDocument  # noqa: E402
from proxy.tool_security_profiles import ToolSecurityProfileDocument  # noqa: E402
from app.services.subject_authorization import SubjectAuthorizationDocument  # noqa: E402


def v2_content() -> ControlPlaneConfigContent:
    return ControlPlaneConfigContent(
        schema_version=2,
        identity_bindings=IdentityBindingDocument(revision="id-v2", bindings=[]),
        agent_authorizations=SubjectAuthorizationDocument(revision="auth-v2", subjects={}),
        supported_schema_profile="supported-json-schema-v1",
        capability_catalog_version="1",
        resource_type_registry_version="1",
        tool_security_contracts=(),
        authority_resource_scopes=(),
        adapter_resolutions=(),
        tool_observation_approvals=(),
        authority_contexts={},
    )


def v1_content() -> ControlPlaneConfigContent:
    return ControlPlaneConfigContent(
        schema_version=1,
        identity_bindings=IdentityBindingDocument(revision="id-v1", bindings=[]),
        agent_authorizations=SubjectAuthorizationDocument(revision="auth-v1", subjects={}),
        tool_security_profiles=ToolSecurityProfileDocument(revision="tools-v1", bindings=[]),
        resource_scopes=ResourceScopeDocument(revision="scopes-v1", filesystem_scopes={}),
    )


class RevisionIntegrityAndEmergencyDenyTests(unittest.TestCase):
    def setUp(self) -> None:
        engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(engine)
        self.Session = sessionmaker(bind=engine, expire_on_commit=False)
        with self.Session() as db:
            self.admin = ControlPlaneUser(
                username="admin",
                password_hash="unused",
                role="ADMIN",
                enabled=True,
            )
            db.add(self.admin)
            db.commit()
            db.refresh(self.admin)

    def _publish(self, db, content=None, summary="publish v2"):
        draft = create_revision(
            db,
            content=content or v2_content(),
            status="DRAFT",
            actor=self.admin,
            change_summary=summary,
        )
        published = publish_revision(
            db,
            draft_id=draft.id,
            actor=self.admin,
            change_summary=summary,
        )
        db.commit()
        return published

    def test_v2_publish_is_signed_and_tampering_fails_closed(self) -> None:
        with self.Session() as db:
            revision = self._publish(db)
            self.assertEqual(PublishedConfigurationProvider(db).load_active_snapshot().revision_id, revision.id)
            self.assertEqual(revision.signature_algorithm, "Ed25519")
            original_signature = revision.signature
            replacement = "A" if original_signature[0] != "A" else "B"
            revision.signature = replacement + original_signature[1:]
            db.commit()
            with self.assertRaises(PublishedConfigurationError):
                PublishedConfigurationProvider(db).load_active_snapshot()
            revision.signature = original_signature
            original_key_id = revision.signature_key_id
            revision.signature_key_id = "sha256:" + "0" * 64
            db.commit()
            with self.assertRaises(PublishedConfigurationError):
                PublishedConfigurationProvider(db).load_active_snapshot()
            revision.signature_key_id = original_key_id
            revision.content_hash = "f" * 64
            db.commit()
            with self.assertRaises(PublishedConfigurationError):
                PublishedConfigurationProvider(db).load_active_snapshot()

    def test_direct_reactivation_is_rejected_and_rollback_creates_successor(self) -> None:
        with self.Session() as db:
            first = self._publish(db, summary="first")
            second = self._publish(db, summary="second")
            successor = rollback_to_revision(
                db,
                revision_id=first.id,
                actor=self.admin,
                change_summary="restore first content",
            )
            db.commit()
            self.assertGreater(successor.revision_number, second.revision_number)
            self.assertEqual(successor.previous_revision_hash, second.content_hash)
            self.assertEqual(PublishedConfigurationProvider(db).load_active_snapshot().revision_id, successor.id)

            successor.status = "ARCHIVED"
            first.status = "PUBLISHED"
            db.get(ControlPlaneState, 1).active_revision_id = first.id
            db.commit()
            with self.assertRaisesRegex(PublishedConfigurationError, "active_config_rollback_detected"):
                PublishedConfigurationProvider(db).load_active_snapshot()

    def test_active_revision_verifies_signed_predecessor_chain(self) -> None:
        with self.Session() as db:
            first = self._publish(db, summary="signed predecessor")
            second = self._publish(db, summary="signed successor")
            self.assertEqual(
                PublishedConfigurationProvider(db).load_active_snapshot().revision_id,
                second.id,
            )
            first.content = {**first.content, "policy_settings": {"rules": {"tampered": {"enabled": True, "severity": "LOW"}}}}
            db.commit()
            with self.assertRaisesRegex(
                PublishedConfigurationError,
                "revision_chain_predecessor_hash_mismatch",
            ):
                PublishedConfigurationProvider(db).load_active_snapshot()

    def test_identity_change_revokes_sessions_but_grant_change_does_not(self) -> None:
        binding = IdentityBinding(
            issuer="https://issuer.example",
            subject="subject-1",
            agent_id="agent-one",
        )
        initial = v2_content().model_copy(
            update={
                "identity_bindings": IdentityBindingDocument(
                    revision="identity-1",
                    bindings=[binding],
                ),
                "agent_authorizations": SubjectAuthorizationDocument.model_validate(
                    {
                        "revision": "auth-1",
                        "subjects": {
                            "agent-one": {"role": "operator", "grants": []}
                        },
                    }
                ),
            }
        )
        with self.Session() as db:
            self._publish(db, initial, "initial identity")
            now = datetime.utcnow()
            session = TrustedAgentSession(
                session_reference="session-1",
                token_hash="token-hash-1",
                agent_id="agent-one",
                identity_issuer=binding.issuer,
                identity_subject=binding.subject,
                identity_binding_revision="identity-1",
                expires_at=now + timedelta(hours=1),
                last_seen_at=now,
            )
            db.add(session)
            db.commit()

            grant_only = initial.model_copy(
                update={
                    "agent_authorizations": SubjectAuthorizationDocument.model_validate(
                        {
                            "revision": "auth-2",
                            "subjects": {
                                "agent-one": {
                                    "role": "operator",
                                    "grants": [
                                        {"capability": "system.ping", "scopes": []}
                                    ],
                                },
                                "agent-two": {"role": "operator", "grants": []},
                            },
                        }
                    )
                }
            )
            self._publish(db, grant_only, "grant-only change")
            db.refresh(session)
            self.assertIsNone(session.revoked_at)

            changed_binding = grant_only.model_copy(
                update={
                    "identity_bindings": IdentityBindingDocument(
                        revision="identity-3",
                        bindings=[binding.model_copy(update={"agent_id": "agent-two"})],
                    )
                }
            )
            self._publish(db, changed_binding, "binding change")
            db.refresh(session)
            self.assertIsNotNone(session.revoked_at)
            self.assertEqual(session.revocation_reason, "identity_binding_changed")

    def test_v1_migration_creates_new_draft_without_rewriting_history(self) -> None:
        with self.Session() as db:
            source = self._publish(db, v1_content(), "publish legacy")
            original_content = dict(source.content)
            original_hash = source.content_hash
            draft = create_v2_migration_draft(
                db,
                source_revision_id=source.id,
                actor=self.admin,
                change_summary="explicit v2 migration",
            )
            db.commit()
            self.assertEqual(draft.status, "DRAFT")
            self.assertEqual(draft.schema_version, 2)
            self.assertEqual(source.content, original_content)
            self.assertEqual(source.content_hash, original_hash)

    def test_v2_cutover_blocks_new_v1_publish_and_direct_v1_rollback(self) -> None:
        with self.Session() as db:
            legacy = self._publish(db, v1_content(), "initial legacy before cutover")
            first_v2 = self._publish(db, v2_content(), "first v2 cutover")
            legacy_id = legacy.id
            legacy_hash = legacy.content_hash
            first_v2_number = first_v2.revision_number

            stale_v1_draft = create_revision(
                db,
                content=v1_content(),
                status="DRAFT",
                actor=self.admin,
                parent_revision_id=legacy_id,
                change_summary="attempt legacy publish after cutover",
            )
            with self.assertRaisesRegex(
                Exception,
                "schema_v1_publish_after_v2_cutover_refused",
            ):
                publish_revision(
                    db,
                    draft_id=stale_v1_draft.id,
                    actor=self.admin,
                    change_summary="must refuse v1 after cutover",
                )
            db.rollback()

            with self.assertRaisesRegex(
                Exception,
                "rollback_to_v1_requires_explicit_v2_migration",
            ):
                rollback_to_revision(
                    db,
                    revision_id=legacy_id,
                    actor=self.admin,
                    change_summary="must migrate instead",
                )
            db.rollback()

            historical = PublishedConfigurationProvider(db).load_snapshot(
                legacy_id,
                expected_content_hash=legacy_hash,
                allow_archived=True,
            )
            self.assertEqual(historical.schema_version, 1)

            migration = create_v2_migration_draft(
                db,
                source_revision_id=legacy_id,
                actor=self.admin,
                change_summary="migrate historical legacy to v2",
            )
            restored = publish_revision(
                db,
                draft_id=migration.id,
                actor=self.admin,
                change_summary="publish migrated v2 successor",
            )
            db.commit()
            self.assertEqual(restored.schema_version, 2)
            self.assertGreater(restored.revision_number, first_v2_number)
            self.assertEqual(
                PublishedConfigurationProvider(db).load_active_snapshot().revision_id,
                restored.id,
            )

    def test_emergency_deny_targets_ttl_and_store_failure(self) -> None:
        with self.Session() as db:
            deny = EmergencyDeny(
                target_type="server_tool",
                target_value="mail-a",
                target_secondary_value="send_email",
                reason="Incident containment",
                created_by=self.admin.id,
                expires_at=datetime.utcnow() + timedelta(minutes=5),
            )
            expired = EmergencyDeny(
                target_type="global",
                reason="Expired containment",
                created_by=self.admin.id,
                expires_at=datetime.utcnow() - timedelta(seconds=1),
            )
            db.add_all([deny, expired])
            db.commit()
            self.assertEqual(
                check_emergency_deny(
                    db,
                    agent_id="agent",
                    framework_session_id="session",
                    server_ref="mail-a",
                    tool_name="send_email",
                ),
                deny.id,
            )
            self.assertIsNone(
                check_emergency_deny(
                    db,
                    agent_id="agent",
                    framework_session_id="session",
                    server_ref="mail-b",
                    tool_name="send_email",
                )
            )
            target_cases = (
                ("global", None, None, "any-agent", "any-session", "mail-z", "tool"),
                ("agent_id", "target-agent", None, "target-agent", "session-z", "mail-z", "tool"),
                (
                    "framework_session_id",
                    "target-session",
                    None,
                    "agent-z",
                    "target-session",
                    "mail-z",
                    "tool",
                ),
                ("server_ref", "mail-z", None, "agent-z", "session-z", "mail-z", "tool"),
            )
            for target_type, value, secondary, agent, session_ref, server_ref, tool_name in target_cases:
                with self.subTest(target_type=target_type):
                    candidate = EmergencyDeny(
                        target_type=target_type,
                        target_value=value,
                        target_secondary_value=secondary,
                        reason="Target-specific incident containment",
                        created_by=self.admin.id,
                        expires_at=datetime.utcnow() + timedelta(minutes=5),
                    )
                    db.add(candidate)
                    db.commit()
                    self.assertEqual(
                        check_emergency_deny(
                            db,
                            agent_id=agent,
                            framework_session_id=session_ref,
                            server_ref=server_ref,
                            tool_name=tool_name,
                        ),
                        candidate.id,
                    )
                    db.delete(candidate)
                    db.commit()

        class BrokenSession:
            def scalars(self, _statement):
                raise RuntimeError("database unavailable")

        with self.assertRaisesRegex(EmergencyDenyError, "emergency_deny_store_unavailable"):
            check_emergency_deny(
                BrokenSession(),
                agent_id="agent",
                framework_session_id="session",
                server_ref="mail-a",
                tool_name="send_email",
            )


if __name__ == "__main__":
    unittest.main()
