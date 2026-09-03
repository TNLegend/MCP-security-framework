from __future__ import annotations

from datetime import datetime, timezone
import threading
from typing import Any

from sqlalchemy import event, func, select, text, update
from sqlalchemy.orm import Session

from app.models.build_security import BuildAssessment, BuildScanRun
from app.models.control_plane import ControlPlaneConfigRevision, ControlPlaneState, ControlPlaneUser
from app.models.mcp_server import MCPServer
from app.models.tool_analysis import ToolObservationReviewApproval, ToolProtocolObservation
from app.models.trusted_agent_session import TrustedAgentSession
from app.schemas.control_plane import ControlPlaneConfigContent, empty_latest_configuration
from app.services.control_plane_audit import record_control_plane_audit
from app.services.published_configuration import (
    config_content_hash,
    content_model_to_json,
    validate_config_content,
)
from app.services.revision_signing import (
    REVISION_SIGNATURE_ALGORITHM,
    REVISION_SIGNATURE_VERSION,
    revision_signature_payload,
    sign_revision_payload,
)
from app.services.tool_observation_approval import evidence_bundle_for_observation
from common.canonical_json import sha256_canonical_json
from common.mcp_endpoint import server_ref_for_server
from proxy.resource_adapters_v2 import AdapterRegistry
from proxy.tool_security_v2 import (
    CapabilityCatalog,
    ResourceTypeRegistry,
    security_schema_projection,
    validate_contract_for_schema,
)


class ControlPlaneConfigError(ValueError):
    pass


CONFIG_REVISION_LOCK_KEY = 807018002
_CONFIG_PROCESS_LOCK = threading.RLock()
_REVISION_NUMBER_LOCK = threading.Lock()
_LAST_ALLOCATED_REVISION_NUMBER = 0


def _release_config_process_lock(session: Session, transaction) -> None:
    if transaction.parent is not None:
        return
    if session.info.pop("control_plane_config_process_lock_held", False):
        _CONFIG_PROCESS_LOCK.release()


def _acquire_config_process_lock(db: Session) -> None:
    if db.info.get("control_plane_config_process_lock_held"):
        return
    _CONFIG_PROCESS_LOCK.acquire()
    db.info["control_plane_config_process_lock_held"] = True
    event.listen(db, "after_transaction_end", _release_config_process_lock)


def _acquire_config_revision_lock(db: Session) -> None:
    db.expire_on_commit = False
    _acquire_config_process_lock(db)
    bind = db.get_bind()
    if bind.dialect.name == "postgresql":
        db.execute(text("SELECT pg_advisory_xact_lock(:lock_key)"), {"lock_key": CONFIG_REVISION_LOCK_KEY})


def lock_control_plane_state_for_update(db: Session) -> ControlPlaneState:
    _acquire_config_revision_lock(db)
    state = db.get(ControlPlaneState, 1)
    if state is None:
        database_max = int(
            db.scalar(select(func.max(ControlPlaneConfigRevision.revision_number))) or 0
        )
        state = ControlPlaneState(
            id=1,
            last_revision_number=database_max,
        )
        db.add(state)
        db.flush()

    return db.scalars(
        select(ControlPlaneState)
        .where(ControlPlaneState.id == 1)
        .with_for_update()
    ).one()


def create_revision(
    db: Session,
    *,
    content: ControlPlaneConfigContent,
    status: str,
    actor: ControlPlaneUser | None,
    change_summary: str,
    parent_revision_id: str | None = None,
) -> ControlPlaneConfigRevision:
    _acquire_config_revision_lock(db)
    content_json = content_model_to_json(content)
    revision = ControlPlaneConfigRevision(
        revision_number=_next_revision_number(db),
        status=status,
        schema_version=content.schema_version,
        content=content_json,
        content_hash=config_content_hash(content_json),
        created_by=actor.id if actor else None,
        parent_revision_id=parent_revision_id,
        change_summary=change_summary,
    )
    predecessor = None
    if status == "PUBLISHED":
        predecessor = db.scalar(
            select(ControlPlaneConfigRevision)
            .where(
                ControlPlaneConfigRevision.status.in_({"PUBLISHED", "ARCHIVED"})
            )
            .order_by(ControlPlaneConfigRevision.revision_number.desc())
            .limit(1)
        )
    db.add(revision)
    db.flush()
    if status == "PUBLISHED":
        revision.published_by = actor.id if actor else None
        revision.published_at = datetime.utcnow()
        previous_hash = predecessor.content_hash if predecessor is not None else "0" * 64
        payload = revision_signature_payload(
            revision_id=revision.id,
            revision_number=revision.revision_number,
            schema_version=revision.schema_version,
            content_hash=revision.content_hash,
            previous_revision_hash=previous_hash,
        )
        signature, key_id = sign_revision_payload(payload)
        revision.previous_revision_hash = previous_hash
        revision.signature = signature
        revision.signature_key_id = key_id
        revision.signature_algorithm = REVISION_SIGNATURE_ALGORITHM
        revision.signature_version = REVISION_SIGNATURE_VERSION
    db.flush()
    return revision


def create_draft_from_revision(
    db: Session,
    *,
    published_revision_id: str,
    actor: ControlPlaneUser,
    change_summary: str,
) -> ControlPlaneConfigRevision:
    _acquire_config_revision_lock(db)
    parent = db.get(ControlPlaneConfigRevision, published_revision_id)
    if parent is None:
        raise ControlPlaneConfigError("revision_not_found")
    if parent.status != "PUBLISHED":
        raise ControlPlaneConfigError("draft_parent_must_be_published")
    content = validate_config_content(parent.content)
    draft = create_revision(
        db,
        content=content,
        status="DRAFT",
        actor=actor,
        parent_revision_id=parent.id,
        change_summary=change_summary,
    )
    _copy_observation_approvals_to_draft(db, source=content, draft=draft, actor=actor)
    record_control_plane_audit(
        db,
        actor=actor,
        action="DRAFT_CREATED",
        target_type="control_plane_config_revision",
        target_id=draft.id,
        revision_id=draft.id,
        reason=change_summary,
        after_json=_revision_summary(draft),
    )
    return draft


def _copy_observation_approvals_to_draft(
    db: Session,
    *,
    source: ControlPlaneConfigContent,
    draft: ControlPlaneConfigRevision,
    actor: ControlPlaneUser,
) -> None:
    if not source.tool_observation_approvals:
        return

    copied = []
    for source_approval in source.tool_observation_approvals:
        observation = db.get(ToolProtocolObservation, source_approval.tool_observation_id)
        if observation is None:
            raise ControlPlaneConfigError("approval_observation_missing")
        if (
            observation.server_ref != source_approval.server_ref
            or observation.upstream_protocol_profile_id
            != source_approval.upstream_protocol_profile_id
            or observation.tool_fingerprint != source_approval.tool_fingerprint
        ):
            raise ControlPlaneConfigError("approval_observation_mismatch")

        try:
            current_bundle = evidence_bundle_for_observation(db, observation)
        except ValueError as exc:
            raise ControlPlaneConfigError("approval_evidence_unavailable") from exc
        if not _evidence_snapshot_approvable(current_bundle):
            raise ControlPlaneConfigError("inherited_approval_current_analysis_not_approvable")
        current_hash = sha256_canonical_json(current_bundle)

        source_review = db.scalar(
            select(ToolObservationReviewApproval).where(
                ToolObservationReviewApproval.observation_id == observation.id,
                ToolObservationReviewApproval.tool_fingerprint
                == source_approval.tool_fingerprint,
                ToolObservationReviewApproval.contract_hash
                == source_approval.contract_hash,
                ToolObservationReviewApproval.evidence_bundle_hash
                == source_approval.evidence_bundle_hash,
                ToolObservationReviewApproval.revision_id
                == source_approval.revision_id,
                ToolObservationReviewApproval.active.is_(True),
            )
        )
        source_bundle = source_review.evidence_bundle if source_review is not None else None
        source_snapshot_current = (
            isinstance(source_bundle, dict)
            and sha256_canonical_json(source_bundle)
            == source_approval.evidence_bundle_hash
            and _evidence_snapshot_matches_observation(source_bundle, observation)
            and current_hash == source_approval.evidence_bundle_hash
        )

        if source_snapshot_current:
            evidence_bundle = source_bundle
            evidence_hash = source_approval.evidence_bundle_hash
            admin_id = source_approval.admin_id
            approved_at = datetime.fromisoformat(source_approval.approved_at.rstrip("Z"))
        else:
            evidence_bundle = current_bundle
            evidence_hash = current_hash
            admin_id = actor.id
            approved_at = datetime.utcnow()

        copied_approval = source_approval.model_copy(
            update={
                "revision_id": draft.id,
                "evidence_bundle_hash": evidence_hash,
                "admin_id": admin_id,
                "approved_at": approved_at.isoformat(timespec="microseconds") + "Z",
            }
        )
        copied.append(copied_approval)
        db.add(
            ToolObservationReviewApproval(
                observation_id=copied_approval.tool_observation_id,
                tool_fingerprint=copied_approval.tool_fingerprint,
                contract_hash=copied_approval.contract_hash,
                evidence_bundle_hash=copied_approval.evidence_bundle_hash,
                evidence_bundle=evidence_bundle,
                admin_id=copied_approval.admin_id,
                revision_id=draft.id,
                active=True,
                approved_at=approved_at,
            )
        )

    next_content = source.model_copy(
        update={"tool_observation_approvals": tuple(copied)}
    )
    draft.content = content_model_to_json(next_content)
    draft.content_hash = config_content_hash(draft.content)
    db.flush()


def create_latest_draft(
    db: Session,
    *,
    actor: ControlPlaneUser,
    change_summary: str,
) -> ControlPlaneConfigRevision:
    draft = create_revision(
        db,
        content=empty_latest_configuration(),
        status="DRAFT",
        actor=actor,
        change_summary=change_summary,
    )
    record_control_plane_audit(
        db,
        actor=actor,
        action="LATEST_CONFIG_DRAFT_CREATED",
        target_type="control_plane_config_revision",
        target_id=draft.id,
        revision_id=draft.id,
        reason=change_summary,
        after_json=_revision_summary(draft),
    )
    return draft


def delete_inactive_revision(
    db: Session,
    *,
    revision_id: str,
    actor: ControlPlaneUser,
    change_summary: str,
) -> None:
    revision = db.get(ControlPlaneConfigRevision, revision_id)
    if revision is None:
        raise ControlPlaneConfigError("revision_not_found")
    if revision.status != "DRAFT":
        raise ControlPlaneConfigError("only_drafts_can_be_deleted")
    has_descendants = db.scalar(
        select(ControlPlaneConfigRevision.id)
        .where(ControlPlaneConfigRevision.parent_revision_id == revision.id)
        .limit(1)
    )
    if has_descendants is not None:
        raise ControlPlaneConfigError("revision_has_descendants")
    summary = _revision_summary(revision)
    db.execute(
        update(ToolObservationReviewApproval)
        .where(
            ToolObservationReviewApproval.revision_id == revision_id,
            ToolObservationReviewApproval.active.is_(True),
        )
        .values(active=False)
    )
    db.delete(revision)
    db.flush()
    record_control_plane_audit(
        db,
        actor=actor,
        action="CONFIG_REVISION_DELETED",
        target_type="control_plane_config_revision",
        target_id=revision_id,
        reason=change_summary,
        before_json=summary,
    )


def patch_draft_revision(
    db: Session,
    *,
    draft_id: str,
    content: ControlPlaneConfigContent,
    actor: ControlPlaneUser,
    change_summary: str,
) -> ControlPlaneConfigRevision:
    revision = db.get(ControlPlaneConfigRevision, draft_id)
    if revision is None:
        raise ControlPlaneConfigError("revision_not_found")
    if revision.status != "DRAFT":
        raise ControlPlaneConfigError("revision_immutable")
    before = _revision_summary(revision)
    validate_config_content(content_model_to_json(content))
    content_json = content_model_to_json(content)
    revision.schema_version = content.schema_version
    revision.content = content_json
    revision.content_hash = config_content_hash(content_json)
    revision.change_summary = change_summary
    revision.updated_at = datetime.utcnow()
    db.flush()
    record_control_plane_audit(
        db,
        actor=actor,
        action="CONFIG_UPDATED",
        target_type="control_plane_config_revision",
        target_id=revision.id,
        revision_id=revision.id,
        before_json=before,
        after_json=_revision_summary(revision),
        reason=change_summary,
    )
    return revision


def validate_revision(
    db: Session,
    *,
    revision_id: str,
    actor: ControlPlaneUser,
    change_summary: str,
) -> dict[str, Any]:
    revision = db.get(ControlPlaneConfigRevision, revision_id)
    if revision is None:
        raise ControlPlaneConfigError("revision_not_found")
    content = validate_config_content(revision.content)
    _validate_v2_database_artifacts(db, revision, content)
    expected_hash = config_content_hash(content_model_to_json(content))
    if expected_hash != revision.content_hash:
        raise ControlPlaneConfigError("revision_hash_mismatch")
    record_control_plane_audit(
        db,
        actor=actor,
        action="CONFIG_VALIDATED",
        target_type="control_plane_config_revision",
        target_id=revision.id,
        revision_id=revision.id,
        reason=change_summary,
        after_json={"content_hash": revision.content_hash},
    )
    return {"valid": True, "content_hash": revision.content_hash}


def publish_revision(
    db: Session,
    *,
    draft_id: str,
    actor: ControlPlaneUser,
    change_summary: str,
) -> ControlPlaneConfigRevision:
    state = lock_control_plane_state_for_update(db)
    draft = db.get(ControlPlaneConfigRevision, draft_id)
    if draft is None:
        raise ControlPlaneConfigError("revision_not_found")
    if draft.status != "DRAFT":
        raise ControlPlaneConfigError("only_draft_can_publish")
    validate_revision(db, revision_id=draft.id, actor=actor, change_summary=change_summary)
    now = datetime.utcnow()
    previous = _active_revision_from_locked_state(db, state)
    previous_content = (
        validate_config_content(previous.content) if previous is not None else None
    )
    draft_content = validate_config_content(draft.content)
    previous_hash = previous.content_hash if previous is not None else "0" * 64
    payload = revision_signature_payload(
        revision_id=draft.id,
        revision_number=draft.revision_number,
        schema_version=draft.schema_version,
        content_hash=draft.content_hash,
        previous_revision_hash=previous_hash,
    )
    signature, key_id = sign_revision_payload(payload)
    draft.previous_revision_hash = previous_hash
    draft.signature = signature
    draft.signature_key_id = key_id
    draft.signature_algorithm = REVISION_SIGNATURE_ALGORITHM
    draft.signature_version = REVISION_SIGNATURE_VERSION
    if previous is not None:
        previous.status = "ARCHIVED"
        previous.updated_at = now
    _archive_other_published_revisions(db, target_revision_id=draft.id, now=now)
    draft.status = "PUBLISHED"
    draft.published_by = actor.id
    draft.published_at = now
    draft.updated_at = now
    state.active_revision_id = draft.id
    state.updated_at = now
    _revoke_sessions_for_changed_identity_bindings(
        db,
        previous_content=previous_content,
        next_content=draft_content,
        now=now,
    )
    db.flush()
    _assert_single_published_revision(db, active_revision_id=draft.id)
    record_control_plane_audit(
        db,
        actor=actor,
        action="CONFIG_PUBLISHED",
        target_type="control_plane_config_revision",
        target_id=draft.id,
        revision_id=draft.id,
        before_json=_revision_summary(previous) if previous else None,
        after_json=_revision_summary(draft),
        reason=change_summary,
    )
    return draft


def rollback_to_revision(
    db: Session,
    *,
    revision_id: str,
    actor: ControlPlaneUser,
    change_summary: str,
) -> ControlPlaneConfigRevision:
    state = lock_control_plane_state_for_update(db)
    target = db.get(ControlPlaneConfigRevision, revision_id)
    if target is None:
        raise ControlPlaneConfigError("revision_not_found")
    current = _active_revision_from_locked_state(db, state)
    content = validate_config_content(target.content)
    draft = create_revision(
        db,
        content=content,
        status="DRAFT",
        actor=actor,
        parent_revision_id=target.id,
        change_summary=f"Rollback draft: {change_summary}",
    )
    _copy_observation_approvals_to_draft(
        db,
        source=content,
        draft=draft,
        actor=actor,
    )
    published = publish_revision(
        db,
        draft_id=draft.id,
        actor=actor,
        change_summary=change_summary,
    )
    record_control_plane_audit(
        db,
        actor=actor,
        action="CONFIG_ROLLED_BACK",
        target_type="control_plane_config_revision",
        target_id=target.id,
        revision_id=published.id,
        reason=change_summary,
        after_json={"published_revision_id": published.id, "rolled_back_to": target.id},
    )
    return published


def active_revision(db: Session) -> ControlPlaneConfigRevision | None:
    state = db.get(ControlPlaneState, 1)
    if state is None or state.active_revision_id is None:
        return None
    revision = db.get(ControlPlaneConfigRevision, state.active_revision_id)
    if revision is None or revision.status != "PUBLISHED":
        return None
    return revision


def _next_revision_number(db: Session) -> int:
    global _LAST_ALLOCATED_REVISION_NUMBER

    with _REVISION_NUMBER_LOCK:
        database_max = int(
            db.scalar(select(func.max(ControlPlaneConfigRevision.revision_number))) or 0
        )
        state = db.get(ControlPlaneState, 1)
        persisted_high_water = int(state.last_revision_number or 0) if state is not None else 0
        next_number = max(
            database_max,
            persisted_high_water,
            _LAST_ALLOCATED_REVISION_NUMBER,
        ) + 1
        if state is not None:
            state.last_revision_number = next_number
            db.flush()
        _LAST_ALLOCATED_REVISION_NUMBER = next_number
        return next_number


def _active_revision_from_locked_state(
    db: Session,
    state: ControlPlaneState,
) -> ControlPlaneConfigRevision | None:
    if state.active_revision_id is None:
        return None
    revision = db.get(ControlPlaneConfigRevision, state.active_revision_id)
    if revision is None or revision.status != "PUBLISHED":
        return None
    return revision


def _archive_other_published_revisions(
    db: Session,
    *,
    target_revision_id: str,
    now: datetime,
) -> None:
    revisions = db.scalars(
        select(ControlPlaneConfigRevision)
        .where(
            ControlPlaneConfigRevision.status == "PUBLISHED",
            ControlPlaneConfigRevision.id != target_revision_id,
        )
        .with_for_update()
    ).all()
    for revision in revisions:
        revision.status = "ARCHIVED"
        revision.updated_at = now


def _assert_single_published_revision(db: Session, *, active_revision_id: str) -> None:
    published_ids = list(
        db.scalars(
            select(ControlPlaneConfigRevision.id).where(
                ControlPlaneConfigRevision.status == "PUBLISHED"
            )
        ).all()
    )
    if published_ids != [active_revision_id]:
        raise ControlPlaneConfigError("published_revision_invariant_violation")
    state = db.get(ControlPlaneState, 1)
    if state is None or state.active_revision_id != active_revision_id:
        raise ControlPlaneConfigError("active_revision_invariant_violation")


def _revision_summary(revision: ControlPlaneConfigRevision | None) -> dict[str, Any] | None:
    if revision is None:
        return None
    return {
        "id": revision.id,
        "revision_number": revision.revision_number,
        "status": revision.status,
        "schema_version": revision.schema_version,
        "content_hash": revision.content_hash,
    }


def _revoke_sessions_for_changed_identity_bindings(
    db: Session,
    *,
    previous_content: ControlPlaneConfigContent | None,
    next_content: ControlPlaneConfigContent,
    now: datetime,
) -> None:
    if previous_content is None:
        return
    previous = {
        (binding.issuer, binding.subject): binding.agent_id
        for binding in previous_content.identity_bindings.bindings
    }
    current = {
        (binding.issuer, binding.subject): binding.agent_id
        for binding in next_content.identity_bindings.bindings
    }
    affected = [key for key, agent_id in previous.items() if current.get(key) != agent_id]
    for issuer, subject in affected:
        db.execute(
            update(TrustedAgentSession)
            .where(
                TrustedAgentSession.identity_issuer == issuer,
                TrustedAgentSession.identity_subject == subject,
                TrustedAgentSession.revoked_at.is_(None),
            )
            .values(
                revoked_at=now,
                revocation_reason="identity_binding_changed",
            )
        )


def _evidence_snapshot_matches_observation(
    evidence_bundle: dict[str, Any],
    observation: ToolProtocolObservation,
) -> bool:
    return (
        evidence_bundle.get("tool_observation_id") == observation.id
        and evidence_bundle.get("tool_fingerprint") == observation.tool_fingerprint
        and evidence_bundle.get("canonical_tool_definition")
        == observation.canonical_tool_definition
    )


def _evidence_snapshot_approvable(evidence_bundle: dict[str, Any]) -> bool:
    analysis = evidence_bundle.get("analysis")
    if not isinstance(analysis, dict):
        return False
    if analysis.get("analysis_status") in {
        "ANALYSIS_FAILED",
        "BLOCKED",
        "PENDING_ANALYSIS",
        "QUARANTINED",
        "STALE",
    }:
        return False
    if analysis.get("deterministic_critical_finding") == "true":
        return False
    return bool(
        analysis.get("semantic_scores")
        and analysis.get("consistency_result")
        and analysis.get("drift_result")
        and analysis.get("model_versions")
    )


def _canonical_utc_naive(value: datetime) -> datetime:
    if value.tzinfo is not None:
        return value.astimezone(timezone.utc).replace(tzinfo=None)
    return value


def _validate_build_security_database_artifacts(
    db: Session,
    content: ControlPlaneConfigContent,
) -> None:
    for evidence in content.build_security.evidence:
        scan = db.get(BuildScanRun, evidence.scan_id)
        if scan is None:
            raise ControlPlaneConfigError("build_evidence_scan_missing")
        if scan.status not in {"COMPLETED", "FAILED"} or scan.completed_at is None:
            raise ControlPlaneConfigError("build_evidence_scan_not_terminal")
        if scan.linked_server_id is None:
            raise ControlPlaneConfigError("build_evidence_scan_not_inventory_linked")
        server = db.get(MCPServer, scan.linked_server_id)
        if server is None:
            raise ControlPlaneConfigError("build_evidence_server_missing")
        if server.status == "archived":
            raise ControlPlaneConfigError("build_evidence_server_archived")

        expected_server_ref = server_ref_for_server(
            {
                "endpoint": server.endpoint,
                "transport": server.transport,
            }
        )
        if evidence.server_ref != expected_server_ref:
            raise ControlPlaneConfigError("build_evidence_server_ref_mismatch")
        if scan.source_fingerprint != evidence.source_fingerprint:
            raise ControlPlaneConfigError("build_evidence_source_fingerprint_mismatch")
        if scan.source_revision != evidence.source_revision:
            raise ControlPlaneConfigError("build_evidence_source_revision_mismatch")
        if _canonical_utc_naive(scan.completed_at) != _canonical_utc_naive(
            evidence.completed_at
        ):
            raise ControlPlaneConfigError("build_evidence_completed_at_mismatch")

        assessment = db.scalar(
            select(BuildAssessment).where(BuildAssessment.build_scan_id == scan.id)
        )
        if assessment is None:
            raise ControlPlaneConfigError("build_evidence_assessment_missing")
        if scan.status == "FAILED":
            if assessment.status != "ERROR" or assessment.required_scanners_complete:
                raise ControlPlaneConfigError("build_evidence_terminal_state_inconsistent")
        elif assessment.status == "ERROR" or not assessment.required_scanners_complete:
            raise ControlPlaneConfigError("build_evidence_terminal_state_inconsistent")
        if assessment.status != evidence.assessment_status:
            raise ControlPlaneConfigError("build_evidence_assessment_status_mismatch")
        if assessment.policy_version != evidence.assessment_policy_version:
            raise ControlPlaneConfigError("build_evidence_policy_version_mismatch")
        if (
            assessment.required_scanners_complete
            != evidence.required_scanners_complete
        ):
            raise ControlPlaneConfigError("build_evidence_scanner_completeness_mismatch")


def _validate_v2_database_artifacts(
    db: Session,
    revision: ControlPlaneConfigRevision,
    content: ControlPlaneConfigContent,
) -> None:
    _validate_build_security_database_artifacts(db, content)
    contracts = {
        (contract.server_ref, contract.tool_name): contract
        for contract in content.tool_security_contracts or ()
    }
    configured_resolutions = content.adapter_resolutions or ()
    capability_catalog_version = content.capability_catalog_version or "1"
    resource_type_registry_version = content.resource_type_registry_version or "1"
    security_packs = content.security_packs or ()
    capability_catalog = CapabilityCatalog(
        version=capability_catalog_version,
        security_packs=security_packs,
    )
    resource_type_registry = ResourceTypeRegistry(
        version=resource_type_registry_version,
        security_packs=security_packs,
    )
    adapter_registry = AdapterRegistry(
        capability_catalog_version=capability_catalog_version,
        resource_type_registry_version=resource_type_registry_version,
        security_packs=security_packs,
    )
    approved_contract_keys: set[tuple[str, str]] = set()
    for approval in content.tool_observation_approvals or ():
        if approval.revision_id != revision.id:
            raise ControlPlaneConfigError("approval_revision_mismatch")
        observation = db.get(ToolProtocolObservation, approval.tool_observation_id)
        if observation is None:
            raise ControlPlaneConfigError("approval_observation_missing")
        if (
            observation.server_ref != approval.server_ref
            or observation.upstream_protocol_profile_id
            != approval.upstream_protocol_profile_id
            or observation.tool_fingerprint != approval.tool_fingerprint
        ):
            raise ControlPlaneConfigError("approval_observation_mismatch")
        contract = contracts.get((approval.server_ref, observation.tool_name))
        if contract is None or contract.contract_hash != approval.contract_hash:
            raise ControlPlaneConfigError("approval_contract_hash_mismatch")
        input_schema = observation.canonical_tool_definition.get("input_schema")
        if not isinstance(input_schema, dict):
            raise ControlPlaneConfigError("approval_observation_schema_missing")
        try:
            derived = validate_contract_for_schema(
                contract,
                security_schema_projection(input_schema),
                capability_catalog=capability_catalog,
                resource_type_registry=resource_type_registry,
                adapter_resolver=adapter_registry,
            )
        except Exception as exc:
            raise ControlPlaneConfigError("approval_contract_schema_invalid") from exc
        expected = sorted(
            (
                value.effect_id,
                value.resource_type,
                value.adapter_id,
                value.adapter_api_version,
                value.implementation_version,
            )
            for value in configured_resolutions
            if value.effect_id in {effect.effect_id for effect in contract.effects}
        )
        actual = sorted(
            (
                value.effect_id,
                value.resource_type,
                value.adapter_id,
                value.adapter_api_version,
                value.implementation_version,
            )
            for value in derived
        )
        if expected != actual:
            raise ControlPlaneConfigError("approval_adapter_resolution_mismatch")
        approved_contract_keys.add((contract.server_ref, contract.tool_name))
        review = db.scalar(
            select(ToolObservationReviewApproval).where(
                ToolObservationReviewApproval.observation_id == observation.id,
                ToolObservationReviewApproval.tool_fingerprint
                == approval.tool_fingerprint,
                ToolObservationReviewApproval.contract_hash == approval.contract_hash,
                ToolObservationReviewApproval.evidence_bundle_hash
                == approval.evidence_bundle_hash,
                ToolObservationReviewApproval.admin_id == approval.admin_id,
                ToolObservationReviewApproval.revision_id == revision.id,
                ToolObservationReviewApproval.active.is_(True),
            )
        )
        if review is None:
            raise ControlPlaneConfigError("approval_review_record_missing")
        if not isinstance(review.evidence_bundle, dict):
            raise ControlPlaneConfigError("approval_evidence_snapshot_missing")
        if not _evidence_snapshot_matches_observation(review.evidence_bundle, observation):
            raise ControlPlaneConfigError("approval_evidence_observation_mismatch")
        evidence_hash = sha256_canonical_json(review.evidence_bundle)
        if evidence_hash != approval.evidence_bundle_hash:
            raise ControlPlaneConfigError("approval_evidence_hash_mismatch")
        if revision.status == "DRAFT":
            try:
                current_evidence_hash = sha256_canonical_json(
                    evidence_bundle_for_observation(db, observation)
                )
            except ValueError as exc:
                raise ControlPlaneConfigError("approval_evidence_unavailable") from exc
            if current_evidence_hash != approval.evidence_bundle_hash:
                raise ControlPlaneConfigError("approval_evidence_not_current")
    if set(contracts) != approved_contract_keys:
        raise ControlPlaneConfigError("published_contract_requires_profile_approval")
