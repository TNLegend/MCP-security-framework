"""Persistent fencing. No model can activate or replace a generation."""

from app.services.tda_application.pipeline import (
    configured_pipeline,
    digest,
    PipelineIntegrityError,
)
from dataclasses import dataclass
from datetime import datetime
import os
from contextvars import ContextVar
from contextlib import contextmanager
from sqlalchemy import event, select
from app.models.analyzer_authority import AnalyzerAuthority
from app.models.control_plane import ControlPlaneUser


@dataclass(frozen=True)
class AuthorityToken:
    generation: int
    pipeline_identity: str


_control_activation = ContextVar("control_plane_activation", default=None)


def _token_from_verified_pipeline(p):
    # p must have been freshly verified by configured_pipeline() or
    # require_current_pipeline() in this same security decision.
    override = _control_activation.get()
    if override is not None:
        if override[1].pipeline_identity != p.identity:
            raise PipelineIntegrityError("activation_pipeline_changed")
        return override[1]
    try:
        g = int(os.environ["ANALYZER_AUTHORITY_GENERATION"])
    except (ValueError, KeyError) as exc:
        raise PipelineIntegrityError("worker_generation_required") from exc
    if g < 1:
        raise PipelineIntegrityError("invalid_worker_generation")
    return AuthorityToken(g, p.identity)


def worker_token():
    # This is local PostgreSQL generation fencing, not a cryptographic signer.
    return _token_from_verified_pipeline(configured_pipeline())


def initialize_local_analyzer_generation(db, pipeline):
    """Initialize/rotate a LOCAL code+model identity, without signing.

    Rotation is serialized in PostgreSQL. Previous analyses retain their old
    identity/generation and cannot be reused to admit a tool. This operation
    does not approve any tool, observation, contract or user.
    """
    from sqlalchemy import text
    from app.models.analyzer_authority import AnalyzerAuthority

    if db.bind is None or db.bind.dialect.name != "postgresql":
        raise PipelineIntegrityError("analyzer_authority_postgresql_required")
    if not getattr(pipeline, "m4_v2", False):
        raise PipelineIntegrityError("local_analyzer_m4_v2_required")
    db.execute(text("SELECT pg_advisory_xact_lock(678304172)"))
    row = db.get(AnalyzerAuthority, 1, populate_existing=True)
    closure = digest(pipeline._manifest["execution"]["source_sha256"])
    execution = digest(pipeline._manifest["execution"])
    revision = pipeline._manifest["execution"]["analyzer_revision"]
    if row is None or row.pipeline_identity != pipeline.identity:
        values = dict(
            generation=1 if row is None else row.generation + 1,
            pipeline_identity=pipeline.identity,
            closure_digest=closure,
            execution_digest=execution,
            analyzer_revision=revision,
            manifest_approval_ref="LOCAL_SHA256_INSTALL",
            activated_by="LOCAL_INSTALL",
            activated_at=datetime.utcnow(),
        )
        if row is None:
            row = AnalyzerAuthority(id=1, **values)
            db.add(row)
        else:
            for name, value in values.items():
                setattr(row, name, value)
        db.flush()
    # Even unchanged installations need a locally usable generation token.
    os.environ["ANALYZER_AUTHORITY_GENERATION"] = str(row.generation)
    return AuthorityToken(row.generation, row.pipeline_identity)



def verified_observation_token(analysis):
    """One current-content verification per observation dispatch decision.

    Local SHA-256 model/analyzer/E5 identity and analysis revision are
    checked by require_current_pipeline. PostgreSQL generation fencing,
    approval evidence and admin revocation remain in assert_current.
    """
    from app.services.tda_application.pipeline import require_current_pipeline

    verified = require_current_pipeline(analysis)
    return _token_from_verified_pipeline(verified)


def assert_current(db, token):
    from app.services.dispatch_admission import lock_emergency_dispatch_authority

    lock_emergency_dispatch_authority(db, require_postgresql=True)
    row = db.scalar(
        select(AnalyzerAuthority)
        .where(AnalyzerAuthority.id == 1)
        .execution_options(populate_existing=True)
    )
    if row is None or (row.generation, row.pipeline_identity) != (
        token.generation,
        token.pipeline_identity,
    ):
        raise PipelineIntegrityError("inactive_analyzer_authority")
    return row


def _check_commit(db):
    token = db.info.get("analyzer_authority_token")
    if token is not None:
        assert_current(db, token)


def _after_transaction(db, transaction):
    if transaction.parent is None:
        db.info.pop("analyzer_authority_token", None)
        db.info.pop("analyzer_inference_transaction", None)


def fence_session(db, token=None, *, purpose="CONTROL"):
    override = _control_activation.get()
    if override is not None and (override[0] != id(db) or purpose != "CONTROL"):
        raise PipelineIntegrityError("activation_cannot_retag_analyzer_work")
    if purpose != "CONTROL":
        db.info["analyzer_inference_transaction"] = True
    token = token or worker_token()
    previous = db.info.get("analyzer_authority_token")
    if previous is not None and previous != token:
        raise PipelineIntegrityError("transaction_authority_changed")
    if not db.info.get("analyzer_fence_listeners"):
        event.listen(db, "before_commit", _check_commit)
        event.listen(db, "after_transaction_end", _after_transaction)
        db.info["analyzer_fence_listeners"] = True
    db.info["analyzer_authority_token"] = token
    return token


@contextmanager
def control_plane_activation(
    db, *, admin_id, manifest_approval_ref, expected_previous=None
):
    """Explicit ADMIN coordinator only; never retags inference/staging work."""
    if (
        db.info.get("analyzer_inference_transaction")
        or _control_activation.get() is not None
    ):
        raise PipelineIntegrityError("activation_cannot_retag_analyzer_work")
    from app.services.control_plane_config import _acquire_config_revision_lock

    _acquire_config_revision_lock(db)
    source_token = (
        fence_session(db, expected_previous)
        if expected_previous is not None
        else fence_session(db)
    )
    assert_current(db, source_token)
    token = activate(db, admin_id=admin_id, manifest_approval_ref=manifest_approval_ref)
    db.info["analyzer_authority_token"] = token
    context = _control_activation.set((id(db), token))
    try:
        yield token
    finally:
        _control_activation.reset(context)


def activate(db, *, admin_id, manifest_approval_ref):
    from app.services.control_plane_config import _acquire_config_revision_lock
    from app.services.dispatch_admission import lock_emergency_dispatch_authority
    from app.services.control_plane_audit import record_control_plane_audit

    p = configured_pipeline()
    admin = db.get(ControlPlaneUser, admin_id)
    if admin is None or not admin.enabled or admin.role != "ADMIN":
        raise ValueError("activation_admin_invalid")
    if not manifest_approval_ref.strip():
        raise ValueError("manifest_approval_reference_required")
    _acquire_config_revision_lock(db)
    lock_emergency_dispatch_authority(db, require_postgresql=True)
    row = db.scalar(
        select(AnalyzerAuthority)
        .where(AnalyzerAuthority.id == 1)
        .execution_options(populate_existing=True)
    )
    before = row.generation if row else 0
    closure = digest(p._manifest["execution"]["source_sha256"])
    if (
        row
        and row.closure_digest != closure
        and (row.analyzer_revision == p._manifest["execution"]["analyzer_revision"])
    ):
        raise PipelineIntegrityError("source_change_requires_analyzer_revision_bump")
    values = dict(
        generation=before + 1,
        pipeline_identity=p.identity,
        closure_digest=closure,
        execution_digest=digest(p._manifest["execution"]),
        analyzer_revision=p._manifest["execution"]["analyzer_revision"],
        manifest_approval_ref=manifest_approval_ref,
        activated_by=admin.id,
        activated_at=datetime.utcnow(),
    )
    if row is None:
        row = AnalyzerAuthority(id=1, **values)
        db.add(row)
    else:
        for k, v in values.items():
            setattr(row, k, v)
    record_control_plane_audit(
        db,
        actor=admin,
        action="ANALYZER_AUTHORITY_ACTIVATED",
        target_type="analyzer_authority",
        target_id="1",
        revision_id=None,
        before_json={"generation": before},
        after_json={
            "generation": values["generation"],
            "pipeline_identity": p.identity,
            "manifest_approval_ref": manifest_approval_ref,
        },
        reason="Explicit activation; previous workers fenced, no approval migrated",
    )
    db.flush()
    return AuthorityToken(row.generation, row.pipeline_identity)


def bind_result_authority(db, analysis_id):
    """Bind to the job's captured token, never to a freshly substituted token."""
    from app.models.analysis_authority_binding import AnalysisAuthorityBinding

    token = db.info.get("analyzer_authority_token")
    if token is None:
        raise PipelineIntegrityError("analysis_authority_token_not_captured")
    assert_current(db, token)
    existing = db.get(AnalysisAuthorityBinding, analysis_id)
    if existing is not None:
        if (existing.generation, existing.pipeline_identity) != (
            token.generation,
            token.pipeline_identity,
        ):
            raise PipelineIntegrityError("analysis_authority_binding_immutable")
        return
    db.add(
        AnalysisAuthorityBinding(
            analysis_id=analysis_id,
            generation=token.generation,
            pipeline_identity=token.pipeline_identity,
        )
    )
