from __future__ import annotations

from datetime import datetime
import threading
from typing import Any

from sqlalchemy import event, func, select, text
from sqlalchemy.orm import Session

from app.models.control_plane import ControlPlaneConfigRevision, ControlPlaneState, ControlPlaneUser
from app.schemas.control_plane import ControlPlaneConfigContent
from app.services.control_plane_audit import record_control_plane_audit
from app.services.published_configuration import (
    config_content_hash,
    content_model_to_json,
    validate_config_content,
)


class ControlPlaneConfigError(ValueError):
    pass


CONFIG_REVISION_LOCK_KEY = 807018002
_CONFIG_PROCESS_LOCK = threading.RLock()


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
    _acquire_config_revision_lock(db)
    target = db.get(ControlPlaneConfigRevision, revision_id)
    if target is None:
        raise ControlPlaneConfigError("revision_not_found")
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
    return int(db.scalar(select(func.max(ControlPlaneConfigRevision.revision_number))) or 0) + 1


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
