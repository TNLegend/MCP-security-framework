from __future__ import annotations

from datetime import datetime
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
from app.models.control_plane import ControlPlaneUser  # noqa: E402
from app.models.mcp_server import MCPServer  # noqa: E402
from app.models.mcp_tool import MCPTool  # noqa: E402
from app.models.tool_analysis import (  # noqa: E402
    ToolAnalysis,
    ToolAnalysisFinding,
    ToolObservationReviewApproval,
    ToolObservedVersion,
    ToolProtocolObservation,
)
from app.schemas.control_plane import AuthorityContext, ControlPlaneConfigContent  # noqa: E402
from app.services.control_plane_config import (  # noqa: E402
    ControlPlaneConfigError,
    create_draft_from_revision,
    create_revision,
    patch_draft_revision,
    publish_revision,
    rollback_to_revision,
    validate_revision,
)
from app.services.published_configuration import PublishedConfigurationProvider  # noqa: E402
from app.services.subject_authorization import SubjectAuthorizationDocument  # noqa: E402
from app.services.tool_observation_approval import (  # noqa: E402
    approve_tool_observation,
    evidence_bundle_for_observation,
)
from common.canonical_json import sha256_canonical_json  # noqa: E402
from proxy.identity_binding import IdentityBindingDocument  # noqa: E402
from proxy.protocol_profiles import LEGACY_PROFILE_ID, MODERN_PROFILE_ID  # noqa: E402
from proxy.tool_security_v2 import (  # noqa: E402
    AuthorityResourceScope,
    ResourceBinding,
    ScopeMatchMode,
    ToolEffect,
    ToolSecurityContract,
    validate_contract_for_schema,
)


class V2ApprovalGateTests(unittest.TestCase):
    def setUp(self) -> None:
        engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(engine)
        self.Session = sessionmaker(bind=engine, expire_on_commit=False)

    def test_profile_specific_approval_and_edit_after_approve_gate(self) -> None:
        with self.Session() as db:
            admin = ControlPlaneUser(
                username="admin",
                password_hash="unused",
                role="ADMIN",
                enabled=True,
            )
            server = MCPServer(
                name="mail",
                server_type="mcp",
                status="active",
                endpoint="http://127.0.0.1:9900/mcp",
                transport="streamable_http",
            )
            db.add_all([admin, server])
            db.flush()
            schema = {
                "type": "object",
                "properties": {
                    "recipient": {"type": "string", "maxLength": 254},
                    "subject": {"type": "string", "maxLength": 200},
                    "body": {"type": "string", "maxLength": 10000},
                },
                "required": ["recipient", "subject", "body"],
                "additionalProperties": False,
            }
            tool = MCPTool(
                server_id=server.id,
                name="send_email",
                description="Send an email to one explicit recipient.",
                input_schema=schema,
                status="REVIEW_REQUIRED",
            )
            db.add(tool)
            db.flush()
            fingerprint = "a" * 64
            version = ToolObservedVersion(
                tool_id=tool.id,
                server_ref="mail-a",
                tool_name=tool.name,
                fingerprint=fingerprint,
                snapshot={"name": tool.name, "input_schema": schema},
                profile_snapshot=None,
                profile_revision="v2",
            )
            db.add(version)
            db.flush()
            analysis = ToolAnalysis(
                tool_id=tool.id,
                version_id=version.id,
                fingerprint=fingerprint,
                analysis_status="REVIEW_REQUIRED",
                risk_score=20,
                risk_level="low",
                semantic_flagged="false",
                deterministic_critical_finding="false",
                consistency_status="consistent",
                drift_status="NONE",
                review_status="REVIEW_REQUIRED",
                semantic_scores={"normal_tool_description": 0.91},
                consistency_result={"status": "consistent", "findings": []},
                drift_result={"status": "NONE", "changes": []},
                model_versions={"semantic": "test", "embedding": "test"},
                analyzer_revision="v1",
                completed_at=datetime.utcnow(),
            )
            db.add(analysis)
            db.flush()
            observation = ToolProtocolObservation(
                tool_id=tool.id,
                server_ref="mail-a",
                upstream_protocol_profile_id=LEGACY_PROFILE_ID,
                tool_name=tool.name,
                canonical_tool_definition={
                    "tool_name": tool.name,
                    "description": tool.description,
                    "input_schema": schema,
                    "output_schema": {},
                    "annotations": {},
                },
                tool_fingerprint=fingerprint,
                analysis_state="REVIEW_REQUIRED",
                analysis_id=analysis.id,
            )
            db.add(observation)
            tool.current_fingerprint = fingerprint
            db.flush()

            empty = ControlPlaneConfigContent(
                schema_version=2,
                identity_bindings=IdentityBindingDocument(revision="id-v2", bindings=[]),
                agent_authorizations=SubjectAuthorizationDocument(revision="auth-v2", subjects={}),
                supported_schema_profile="supported-json-schema-v1",
                capability_catalog_version="2",
                resource_type_registry_version="2",
                tool_security_contracts=(),
                authority_resource_scopes=(),
                adapter_resolutions=(),
                tool_observation_approvals=(),
                authority_contexts={},
            )
            draft = create_revision(
                db,
                content=empty,
                status="DRAFT",
                actor=admin,
                change_summary="create v2 draft",
            )
            contract = ToolSecurityContract(
                server_ref="mail-a",
                tool_name="send_email",
                effects=(
                    ToolEffect(
                        effect_id="mail.send",
                        capability="message.send",
                        resource_bindings=(
                            ResourceBinding(path=("recipient",), resource_type="email_address"),
                        ),
                    ),
                ),
                unbound_arguments=(("subject",), ("body",)),
            )
            approval = approve_tool_observation(
                db,
                observation_id=observation.id,
                contract=contract,
                admin_id=admin.id,
                revision_id=draft.id,
            )
            self.assertEqual(analysis.analysis_status, "REVIEW_REQUIRED")
            self.assertEqual(analysis.review_status, "REVIEW_REQUIRED")
            self.assertEqual(observation.analysis_state, "REVIEW_REQUIRED")
            self.assertNotEqual(tool.analysis_status, "APPROVED")
            self.assertFalse(tool.approved_fingerprint_match)
            self.assertEqual(
                approval.evidence_bundle_hash,
                sha256_canonical_json(evidence_bundle_for_observation(db, observation)),
            )
            analysis.deterministic_critical_finding = "true"
            with self.assertRaisesRegex(ValueError, "critical_finding_cannot_be_approved"):
                approve_tool_observation(
                    db,
                    observation_id=observation.id,
                    contract=contract,
                    admin_id=admin.id,
                    revision_id=draft.id,
                )
            analysis.deterministic_critical_finding = "false"
            content = ControlPlaneConfigContent.model_validate(
                {
                    "schema_version": 2,
                    "identity_bindings": {"revision": "id-v2", "bindings": []},
                    "agent_authorizations": {
                        "revision": "auth-v2",
                        "subjects": {
                            "agent": {
                                "role": "operator",
                                "grants": [{"capability": "message.send", "scopes": ["mail.alice"]}],
                            }
                        },
                    },
                    "policy_settings": {"rules": {}},
                    "supported_schema_profile": "supported-json-schema-v1",
                    "capability_catalog_version": "2",
                    "resource_type_registry_version": "2",
                    "tool_security_contracts": [contract.model_dump(mode="json")],
                    "authority_resource_scopes": [
                        AuthorityResourceScope(
                            scope_id="mail.alice",
                            authority="mail-a",
                            resource_type="email_address",
                            canonical_value="alice@example.com",
                            match_mode=ScopeMatchMode.SELF,
                        ).model_dump(mode="json")
                    ],
                    "adapter_resolutions": [
                        value.model_dump(mode="json")
                        for value in validate_contract_for_schema(contract, schema)
                    ],
                    "tool_observation_approvals": [approval.model_dump(mode="json")],
                    "authority_contexts": {"mail-a": AuthorityContext().model_dump(mode="json")},
                }
            )
            patch_draft_revision(
                db,
                draft_id=draft.id,
                content=content,
                actor=admin,
                change_summary="bind exact reviewed artifacts",
            )
            review_record = db.query(ToolObservationReviewApproval).one()
            review_record.active = False
            with self.assertRaisesRegex(ControlPlaneConfigError, "approval_review_record_missing"):
                validate_revision(
                    db,
                    revision_id=draft.id,
                    actor=admin,
                    change_summary="fabricated approval must fail",
                )
            review_record.active = True
            validate_revision(db, revision_id=draft.id, actor=admin, change_summary="validate")
            published = publish_revision(db, draft_id=draft.id, actor=admin, change_summary="publish")
            db.commit()
            snapshot = PublishedConfigurationProvider(db).load_active_snapshot()
            self.assertEqual(
                snapshot.get_tool_observation_approval(
                    server_ref="mail-a",
                    upstream_protocol_profile_id=LEGACY_PROFILE_ID,
                    tool_fingerprint=fingerprint,
                ).tool_observation_id,
                observation.id,
            )
            with self.assertRaises(Exception):
                snapshot.get_tool_observation_approval(
                    server_ref="mail-a",
                    upstream_protocol_profile_id=MODERN_PROFILE_ID,
                    tool_fingerprint=fingerprint,
                )

            newer_analysis = ToolAnalysis(
                tool_id=tool.id,
                version_id=version.id,
                fingerprint=fingerprint,
                analysis_status="APPROVED",
                risk_score=0,
                risk_level="info",
                semantic_flagged="false",
                deterministic_critical_finding="false",
                consistency_status="consistent",
                drift_status="NONE",
                review_status="APPROVED",
                semantic_scores={"normal_tool_description": 0.95},
                consistency_result={"status": "consistent", "findings": []},
                drift_result={"status": "NONE", "changes": []},
                model_versions={"semantic": "test", "embedding": "test"},
                analyzer_revision="v1",
                completed_at=datetime.utcnow(),
            )
            db.add(newer_analysis)
            db.flush()
            observation.analysis_id = newer_analysis.id
            observation.analysis_state = "APPROVED"
            renewed = create_draft_from_revision(
                db,
                published_revision_id=published.id,
                actor=admin,
                change_summary="renew inherited approval against current evidence",
            )
            renewed_content = ControlPlaneConfigContent.model_validate(renewed.content)
            renewed_approval = renewed_content.tool_observation_approvals[0]
            self.assertNotEqual(
                renewed_approval.evidence_bundle_hash,
                approval.evidence_bundle_hash,
            )
            renewed_review = db.query(ToolObservationReviewApproval).filter(
                ToolObservationReviewApproval.revision_id == renewed.id
            ).one()
            self.assertIsInstance(renewed_review.evidence_bundle, dict)
            self.assertEqual(
                sha256_canonical_json(renewed_review.evidence_bundle),
                renewed_approval.evidence_bundle_hash,
            )
            validate_revision(
                db,
                revision_id=renewed.id,
                actor=admin,
                change_summary="validate re-anchored inherited approval",
            )
            newer_published = publish_revision(
                db,
                draft_id=renewed.id,
                actor=admin,
                change_summary="publish renewed approval",
            )
            rolled_back = rollback_to_revision(
                db,
                revision_id=published.id,
                actor=admin,
                change_summary="rollback approved archived revision",
            )
            rolled_back_content = ControlPlaneConfigContent.model_validate(rolled_back.content)
            self.assertNotEqual(rolled_back.id, published.id)
            self.assertEqual(rolled_back.status, "PUBLISHED")
            self.assertEqual(published.status, "ARCHIVED")
            self.assertEqual(
                rolled_back.previous_revision_hash,
                newer_published.content_hash,
            )
            self.assertEqual(
                rolled_back_content.tool_observation_approvals[0].revision_id,
                rolled_back.id,
            )
            rollback_review = db.query(ToolObservationReviewApproval).filter(
                ToolObservationReviewApproval.revision_id == rolled_back.id,
                ToolObservationReviewApproval.active.is_(True),
            ).one()
            self.assertIsInstance(rollback_review.evidence_bundle, dict)
            self.assertEqual(
                sha256_canonical_json(rollback_review.evidence_bundle),
                rolled_back_content.tool_observation_approvals[0].evidence_bundle_hash,
            )

            changed_contract = contract.model_copy(update={"tool_name": "send_email_v2"})
            changed = content.model_copy(
                update={"tool_security_contracts": (changed_contract,)}
            )
            next_draft = create_revision(
                db,
                content=changed,
                status="DRAFT",
                actor=admin,
                parent_revision_id=published.id,
                change_summary="edit after approval",
            )
            with self.assertRaises((ControlPlaneConfigError, ValueError)):
                validate_revision(
                    db,
                    revision_id=next_draft.id,
                    actor=admin,
                    change_summary="must fail",
                )

    def test_approval_rejects_analysis_failed_and_pending_but_accepts_completed_review(self) -> None:
        with self.Session() as db:
            admin = ControlPlaneUser(
                username="admin",
                password_hash="unused",
                role="ADMIN",
                enabled=True,
            )
            server = MCPServer(
                name="mail",
                server_type="mcp",
                status="active",
                endpoint="http://127.0.0.1:9900/mcp",
                transport="streamable_http",
            )
            db.add_all([admin, server])
            db.flush()
            schema = {
                "type": "object",
                "properties": {
                    "recipient": {"type": "string", "maxLength": 254},
                    "subject": {"type": "string", "maxLength": 200},
                    "body": {"type": "string", "maxLength": 10000},
                },
                "required": ["recipient", "subject", "body"],
                "additionalProperties": False,
            }
            contract = ToolSecurityContract(
                server_ref="mail-a",
                tool_name="send_email",
                effects=(
                    ToolEffect(
                        effect_id="mail.send",
                        capability="message.send",
                        resource_bindings=(
                            ResourceBinding(path=("recipient",), resource_type="email_address"),
                        ),
                    ),
                ),
                unbound_arguments=(("subject",), ("body",)),
            )
            draft = create_revision(
                db,
                content=ControlPlaneConfigContent(
                    schema_version=2,
                    identity_bindings=IdentityBindingDocument(revision="id-v2", bindings=[]),
                    agent_authorizations=SubjectAuthorizationDocument(revision="auth-v2", subjects={}),
                    supported_schema_profile="supported-json-schema-v1",
                    capability_catalog_version="2",
                    resource_type_registry_version="2",
                    tool_security_contracts=(),
                    authority_resource_scopes=(),
                    adapter_resolutions=(),
                    tool_observation_approvals=(),
                    authority_contexts={},
                ),
                status="DRAFT",
                actor=admin,
                change_summary="approval draft",
            )

            def make_observation(status: str, fingerprint: str) -> ToolProtocolObservation:
                tool = MCPTool(
                    server_id=server.id,
                    name="send_email",
                    description="Send email.",
                    input_schema=schema,
                    status=status,
                )
                db.add(tool)
                db.flush()
                version = ToolObservedVersion(
                    tool_id=tool.id,
                    server_ref="mail-a",
                    tool_name=tool.name,
                    fingerprint=fingerprint,
                    snapshot={"name": tool.name, "input_schema": schema},
                    profile_snapshot=None,
                    profile_revision="v2",
                )
                db.add(version)
                db.flush()
                analysis = ToolAnalysis(
                    tool_id=tool.id,
                    version_id=version.id,
                    fingerprint=fingerprint,
                    analysis_status=status,
                    risk_score=10,
                    risk_level="low",
                    semantic_flagged="true" if status == "REVIEW_REQUIRED" else "false",
                    deterministic_critical_finding="false",
                    consistency_status="consistent",
                    drift_status="NONE",
                    review_status=status,
                    semantic_scores={"security_bypass": 0.9},
                    consistency_result={"status": "consistent"},
                    drift_result={"status": "NONE"},
                    model_versions={"semantic": "test", "embedding": "test"},
                    analyzer_revision="v1",
                    completed_at=datetime.utcnow() if status != "PENDING_ANALYSIS" else None,
                )
                db.add(analysis)
                db.flush()
                observation = ToolProtocolObservation(
                    tool_id=tool.id,
                    server_ref="mail-a",
                    upstream_protocol_profile_id=MODERN_PROFILE_ID,
                    tool_name=tool.name,
                    canonical_tool_definition={
                        "tool_name": tool.name,
                        "description": tool.description,
                        "input_schema": schema,
                        "output_schema": {},
                        "annotations": {},
                    },
                    tool_fingerprint=fingerprint,
                    analysis_state=status,
                    analysis_id=analysis.id,
                )
                db.add(observation)
                tool.current_fingerprint = fingerprint
                db.flush()
                return observation

            failed = make_observation("ANALYSIS_FAILED", "f" * 64)
            pending = make_observation("PENDING_ANALYSIS", "e" * 64)
            review_required = make_observation("REVIEW_REQUIRED", "d" * 64)

            with self.assertRaisesRegex(ValueError, "tool_observation_not_approvable"):
                approve_tool_observation(
                    db,
                    observation_id=failed.id,
                    contract=contract,
                    admin_id=admin.id,
                    revision_id=draft.id,
                )
            with self.assertRaisesRegex(ValueError, "tool_observation_not_approvable"):
                approve_tool_observation(
                    db,
                    observation_id=pending.id,
                    contract=contract,
                    admin_id=admin.id,
                    revision_id=draft.id,
                )
            approval = approve_tool_observation(
                db,
                observation_id=review_required.id,
                contract=contract,
                admin_id=admin.id,
                revision_id=draft.id,
            )
            self.assertEqual(approval.tool_fingerprint, "d" * 64)


if __name__ == "__main__":
    unittest.main()
