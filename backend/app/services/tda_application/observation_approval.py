from __future__ import annotations
from app.services.tda_application.authority import fence_session, assert_current
from app.services.tda.configuration import ANALYZER_REVISION
from app.services.tda_application.pipeline import require_current_pipeline
from app.services.tda.m5_context.identity import compute_analysis_context_hash
from datetime import datetime
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.models.control_plane import ControlPlaneConfigRevision, ControlPlaneUser
from app.models.tool_analysis import (
    ToolAnalysis,
    ToolAnalysisFinding,
    ToolHumanReview,
    ToolObservationReviewApproval,
    ToolProtocolObservation,
)
from app.services.control_plane_audit import record_control_plane_audit
from common.canonical_json import sha256_canonical_json
from proxy.tool_security_v2 import ToolObservationApproval, ToolSecurityContract

APPROVABLE_REVIEW_STATES = frozenset({"APPROVED", "REVIEW_REQUIRED", "ADMIN_ALLOWED"})


def evidence_bundle_for_observation(
    db: Session, observation: ToolProtocolObservation
) -> dict:
    if observation.analysis_id is None:
        raise ValueError("observation_analysis_missing")
    analysis = db.get(ToolAnalysis, observation.analysis_id, populate_existing=True)
    if analysis is None or analysis.completed_at is None:
        raise ValueError("observation_analysis_incomplete")
    findings = db.scalars(
        select(ToolAnalysisFinding)
        .execution_options(populate_existing=True)
        .where(ToolAnalysisFinding.analysis_id == analysis.id)
        .order_by(ToolAnalysisFinding.id)
    ).all()
    return {
        "tool_observation_id": observation.id,
        "tool_fingerprint": observation.tool_fingerprint,
        "canonical_tool_definition": observation.canonical_tool_definition,
        "analysis": {
            "analysis_status": analysis.analysis_status,
            "risk_score": analysis.risk_score,
            "risk_level": analysis.risk_level,
            "semantic_flagged": analysis.semantic_flagged,
            "deterministic_critical_finding": analysis.deterministic_critical_finding,
            "consistency_status": analysis.consistency_status,
            "drift_status": analysis.drift_status,
            "review_status": analysis.review_status,
            "semantic_scores": analysis.semantic_scores,
            "consistency_result": analysis.consistency_result,
            "drift_result": analysis.drift_result,
            "model_versions": analysis.model_versions,
            "analyzer_revision": analysis.analyzer_revision,
        },
        "findings": [
            {
                "code": finding.code,
                "category": finding.category,
                "source": finding.source,
                "severity": finding.severity,
                "confidence": finding.confidence,
                "evidence": finding.evidence,
                "recommendation": finding.recommendation,
            }
            for finding in findings
        ],
    }


def approve_tool_observation(
    db: Session,
    *,
    observation_id: int,
    contract: ToolSecurityContract,
    admin_id: str,
    revision_id: str,
) -> ToolObservationApproval:
    token = fence_session(db)
    from app.services.discovery_generation import lock_review_catalog_scope

    observation = db.get(ToolProtocolObservation, observation_id)
    if observation is None:
        raise ValueError("tool_observation_missing")
    lock_review_catalog_scope(db, tool_id=observation.tool_id)
    if db.get_bind().dialect.name == "postgresql":
        db.refresh(observation)
    from app.services.dispatch_admission import lock_emergency_dispatch_authority

    lock_emergency_dispatch_authority(db)
    assert_current(db, token)
    if observation is None:
        raise ValueError("tool_observation_missing")
    latest_review = db.scalar(
        select(ToolHumanReview)
        .where(
            ToolHumanReview.tool_id == observation.tool_id,
            ToolHumanReview.fingerprint == observation.tool_fingerprint,
        )
        .order_by(ToolHumanReview.id.desc())
        .limit(1)
    )
    if latest_review is not None and latest_review.action in {
        "block",
        "keep_review_required",
    }:
        raise ValueError("approval_human_review_hold_active")
    if not admin_id.strip() or not revision_id.strip():
        raise ValueError("approval_identity_or_revision_missing")
    admin = db.get(ControlPlaneUser, admin_id, populate_existing=True)
    if admin is None or not admin.enabled or admin.role != "ADMIN":
        raise ValueError("approval_admin_invalid")
    revision = db.get(ControlPlaneConfigRevision, revision_id)
    if revision is None or revision.status != "DRAFT":
        raise ValueError("approval_revision_not_draft")
    analysis = (
        db.get(ToolAnalysis, observation.analysis_id, populate_existing=True)
        if observation.analysis_id
        else None
    )
    if (
        analysis is None
        or analysis.tool_id != observation.tool_id
        or analysis.fingerprint != observation.tool_fingerprint
        or (analysis.completed_at is None)
        or (analysis.analysis_status not in APPROVABLE_REVIEW_STATES)
        or (analysis.review_status not in APPROVABLE_REVIEW_STATES)
        or (getattr(analysis, "analyzer_revision", None) != ANALYZER_REVISION)
    ):
        raise ValueError("tool_observation_not_approvable")
    require_current_pipeline(analysis)
    if analysis.deterministic_critical_finding == "true":
        raise ValueError("critical_finding_cannot_be_approved")
    if (
        not analysis.semantic_scores
        or not analysis.consistency_result
        or (not analysis.drift_result)
        or (not analysis.model_versions)
    ):
        raise ValueError("tool_observation_analysis_results_incomplete")
    if (
        contract.server_ref != observation.server_ref
        or contract.tool_name != observation.tool_name
    ):
        raise ValueError("approval_contract_observation_mismatch")
    if analysis.analysis_context_hash != compute_analysis_context_hash(
        {"contract_hash": contract.contract_hash}
    ):
        raise ValueError("approval_analysis_contract_context_mismatch")
    evidence_bundle = evidence_bundle_for_observation(db, observation)
    evidence_hash = sha256_canonical_json(evidence_bundle)
    now = datetime.utcnow()
    record = ToolObservationReviewApproval(
        observation_id=observation.id,
        tool_fingerprint=observation.tool_fingerprint,
        contract_hash=contract.contract_hash,
        evidence_bundle_hash=evidence_hash,
        evidence_bundle=evidence_bundle,
        admin_id=admin_id,
        revision_id=revision_id,
        active=True,
        approved_at=now,
    )
    db.add(record)
    db.flush()
    from app.models.approval_lineage import ToolApprovalLineage

    db.add(
        ToolApprovalLineage(
            approval_id=record.id,
            root_approval_id=record.id,
            original_admin_id=admin_id,
            original_approved_at=now,
            original_revision_id=revision_id,
            recorded_by=admin_id,
        )
    )
    record_control_plane_audit(
        db,
        actor=admin,
        action="TOOL_OBSERVATION_APPROVE",
        target_type="tool_protocol_observation",
        target_id=str(observation.id),
        revision_id=revision.id,
        after_json={
            "approval_id": record.id,
            "upstream_protocol_profile_id": observation.upstream_protocol_profile_id,
            "tool_fingerprint": observation.tool_fingerprint,
            "contract_hash": contract.contract_hash,
            "evidence_bundle_hash": evidence_hash,
        },
        reason="Profile-specific observation approval",
    )
    db.flush()
    return ToolObservationApproval(
        tool_observation_id=observation.id,
        server_ref=observation.server_ref,
        upstream_protocol_profile_id=observation.upstream_protocol_profile_id,
        tool_fingerprint=observation.tool_fingerprint,
        contract_hash=contract.contract_hash,
        evidence_bundle_hash=evidence_hash,
        admin_id=admin_id,
        approved_at=now.isoformat(timespec="microseconds") + "Z",
        revision_id=revision_id,
    )
