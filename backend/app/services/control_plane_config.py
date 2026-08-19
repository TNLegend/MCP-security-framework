from __future__ import annotations

from datetime import datetime
import threading
from typing import Any

from sqlalchemy import event, func, select, text, update
from sqlalchemy.orm import Session

from app.models.control_plane import ControlPlaneConfigRevision, ControlPlaneState, ControlPlaneUser
from app.models.tool_analysis import ToolObservationReviewApproval, ToolProtocolObservation
from app.models.trusted_agent_session import TrustedAgentSession
from app.schemas.control_plane import ControlPlaneConfigContent
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
from proxy.tool_security_v2 import validate_contract_for_schema


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
        state = ControlPlaneState(id=1)
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
    if (
        status == "PUBLISHED"
        and content.schema_version == 1
        and _v2_cutover_active(db)
    ):
        raise ControlPlaneConfigError("schema_v1_publish_after_v2_cutover_refused")
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
    if status == "PUBLISHED":
        revision.published_by = actor.id if actor else None
        revision.published_at = datetime.utcnow()
    db.add(revision)
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
    if content.schema_version == 2:
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
    if draft.schema_version == 1 and _v2_cutover_active(db):
        raise ControlPlaneConfigError("schema_v1_publish_after_v2_cutover_refused")
    validate_revision(db, revision_id=draft.id, actor=actor, change_summary=change_summary)
    now = datetime.utcnow()
    previous = _active_revision_from_locked_state(db, state)
    previous_content = (
        validate_config_content(previous.content) if previous is not None else None
    )
    draft_content = validate_config_content(draft.content)
    if draft.schema_version == 2:
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
    if current is not None and current.schema_version == 2 and target.schema_version != 2:
        raise ControlPlaneConfigError("rollback_to_v1_requires_explicit_v2_migration")
    content = validate_config_content(target.content)
    draft = create_revision(
        db,
        content=content,
        status="DRAFT",
        actor=actor,
        parent_revision_id=target.id,
        change_summary=f"Rollback draft: {change_summary}",
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
        next_number = max(database_max, _LAST_ALLOCATED_REVISION_NUMBER) + 1
        _LAST_ALLOCATED_REVISION_NUMBER = next_number
        return next_number


def _v2_cutover_active(db: Session) -> bool:
    return bool(
        db.scalar(
            select(ControlPlaneConfigRevision.id)
            .where(
                ControlPlaneConfigRevision.schema_version == 2,
                ControlPlaneConfigRevision.status.in_({"PUBLISHED", "ARCHIVED"}),
            )
            .limit(1)
        )
    )


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


def _validate_v2_database_artifacts(
    db: Session,
    revision: ControlPlaneConfigRevision,
    content: ControlPlaneConfigContent,
) -> None:
    contracts = {
        (contract.server_ref, contract.tool_name): contract
        for contract in content.tool_security_contracts or ()
    }
    configured_resolutions = content.adapter_resolutions or ()
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
            derived = validate_contract_for_schema(contract, input_schema)
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
        try:
            evidence_hash = sha256_canonical_json(
                evidence_bundle_for_observation(db, observation)
            )
        except ValueError as exc:
            raise ControlPlaneConfigError("approval_evidence_unavailable") from exc
        if evidence_hash != approval.evidence_bundle_hash:
            raise ControlPlaneConfigError("approval_evidence_hash_mismatch")
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
    if set(contracts) != approved_contract_keys:
        raise ControlPlaneConfigError("published_contract_requires_profile_approval")
