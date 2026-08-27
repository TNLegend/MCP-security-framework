from __future__ import annotations

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.control_plane import (
    ControlPlaneConfigRevision,
    ControlPlaneUser,
)
from app.models.tool_analysis import (
    ToolAnalysis,
    ToolAnalysisFinding,
    ToolObservationReviewApproval,
    ToolProtocolObservation,
)
from app.services.control_plane_audit import record_control_plane_audit
from common.canonical_json import sha256_canonical_json
from proxy.tool_security_v2 import ToolObservationApproval, ToolSecurityContract


NON_APPROVABLE_ANALYSIS_STATES = {
    "ANALYSIS_FAILED",
    "BLOCKED",
    "PENDING_ANALYSIS",
    "QUARANTINED",
    "STALE",
}


def evidence_bundle_for_observation(
    db: Session,
    observation: ToolProtocolObservation,
) -> dict:
    if observation.analysis_id is None:
        raise ValueError("observation_analysis_missing")
    analysis = db.get(ToolAnalysis, observation.analysis_id)
    if analysis is None or analysis.completed_at is None:
        raise ValueError("observation_analysis_incomplete")
    findings = db.scalars(
        select(ToolAnalysisFinding)
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
    observation = db.get(ToolProtocolObservation, observation_id)
    if observation is None:
        raise ValueError("tool_observation_missing")
    if not admin_id.strip() or not revision_id.strip():
        raise ValueError("approval_identity_or_revision_missing")
    admin = db.get(ControlPlaneUser, admin_id)
    if admin is None or not admin.enabled or admin.role != "ADMIN":
        raise ValueError("approval_admin_invalid")
    revision = db.get(ControlPlaneConfigRevision, revision_id)
    if revision is None or revision.status != "DRAFT":
        raise ValueError("approval_revision_not_draft")
    analysis = db.get(ToolAnalysis, observation.analysis_id) if observation.analysis_id else None
    if (
        analysis is None
        or analysis.completed_at is None
        or analysis.analysis_status in NON_APPROVABLE_ANALYSIS_STATES
    ):
        raise ValueError("tool_observation_not_approvable")
    if analysis.deterministic_critical_finding == "true":
        raise ValueError("critical_finding_cannot_be_approved")
    if (
        not analysis.semantic_scores
        or not analysis.consistency_result
        or not analysis.drift_result
        or not analysis.model_versions
    ):
        raise ValueError("tool_observation_analysis_results_incomplete")
    if contract.server_ref != observation.server_ref or contract.tool_name != observation.tool_name:
        raise ValueError("approval_contract_observation_mismatch")
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
    record_control_plane_audit(
        db,
        actor=admin,
        action="TOOL_OBSERVATION_APPROVE",
        target_type="tool_protocol_observation",
        target_id=str(observation.id),
        revision_id=revision.id,
        after_json={
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
