"""Explicit, fail-closed ADMIN approval of current observations in a draft.

Never silently inherit authority from a previous revision. An authenticated
ADMIN must review the *current* analysis, fingerprint and exact contract.
Reapproval verifies the installed analyzer and records new signed provenance.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime
from sqlalchemy import and_, or_, update

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.control_plane import ControlPlaneConfigRevision, ControlPlaneUser
from app.models.mcp_tool import MCPTool
from app.models.mcp_server import MCPServer
from app.models.tool_analysis import (
    ToolAnalysis,
    ToolApprovedBaseline,
    ToolHumanReview,
    ToolObservationReviewApproval,
)
from app.models.control_plane import EmergencyDeny
from app.services.emergency_deny import active_emergency_deny_clause
from app.schemas.control_plane import ControlPlaneConfigContent
from app.services.control_plane_config import (
    active_revision,
    patch_draft_revision,
)
from app.services.published_configuration import validate_config_content
from app.services.tda_application.authority import approved_analysis_provenance
from app.services.tda_application.observation_approval import (
    approve_tool_observation,
    evidence_bundle_for_observation,
)
from app.services.tda_application.queries import latest_protocol_observation
from common.canonical_json import sha256_canonical_json
from common.mcp_endpoint import server_ref_for_server


class ToolObservationRenewalError(ValueError):
    pass


def only_admin_allow_status_changed(prior: dict, current: dict) -> bool:
    """Allow only REVIEW_REQUIRED -> ADMIN_ALLOWED in administrative states.

    All tool-definition bytes, risks, context, analysis outputs and findings
    must remain *exactly* equal to the previously signed evidence snapshot.
    """
    if not isinstance(prior, dict) or not isinstance(current, dict):
        return False
    pa = prior.get("analysis")
    ca = current.get("analysis")
    if not isinstance(pa, dict) or not isinstance(ca, dict):
        return False
    for key in ("analysis_status", "review_status"):
        if pa.get(key) != "REVIEW_REQUIRED" or ca.get(key) != "ADMIN_ALLOWED":
            return False
    a, b = deepcopy(prior), deepcopy(current)
    for key in ("analysis_status", "review_status"):
        a["analysis"].pop(key, None)
        b["analysis"].pop(key, None)
    return a == b


def renew_admin_allowed_tool_observations(
    db: Session, *, tool: MCPTool, draft_revision_id: str,
    expected_content_hash: str, expected_fingerprint: str,
    change_summary: str, actor: ControlPlaneUser,
) -> dict:
    from app.services.discovery_generation import lock_review_catalog_scope

    if actor is None or actor.role != "ADMIN" or not actor.enabled:
        raise ToolObservationRenewalError("admin_authorization_required")
    # Match the established lock order: catalog -> config -> dispatch.
    lock_review_catalog_scope(db, tool_id=tool.id)
    db.refresh(tool)
    if tool.current_fingerprint != expected_fingerprint:
        raise ToolObservationRenewalError("tool_fingerprint_changed")

    server = db.get(MCPServer, tool.server_id)
    if server is None or server.status == "archived" or server.trust_status != "trusted":
        raise ToolObservationRenewalError("server_not_trusted")
    server_ref = server_ref_for_server(
        {"endpoint": server.endpoint, "transport": server.transport}
    )
    active_deny = db.scalar(select(EmergencyDeny.id).where(
        active_emergency_deny_clause(),
        or_(
            EmergencyDeny.target_type == "global",
            and_(EmergencyDeny.target_type == "server_ref",
                 EmergencyDeny.target_value == server_ref),
            and_(EmergencyDeny.target_type == "server_tool",
                 EmergencyDeny.target_value == server_ref,
                 EmergencyDeny.target_secondary_value == tool.name),
        ),
    ).limit(1))
    if active_deny is not None:
        raise ToolObservationRenewalError("emergency_deny_active")
    published = active_revision(db)
    draft = db.get(ControlPlaneConfigRevision, draft_revision_id)
    if published is None or draft is None or draft.status != "DRAFT":
        raise ToolObservationRenewalError("active_published_and_draft_required")
    if draft.parent_revision_id != published.id:
        raise ToolObservationRenewalError("draft_not_based_on_active_revision")
    if draft.content_hash != expected_content_hash:
        raise ToolObservationRenewalError("draft_content_changed_conflict")

    content = validate_config_content(draft.content)
    source = validate_config_content(published.content)
    lookup = (server_ref, tool.name)
    def find_contract(document: ControlPlaneConfigContent):
        return next(
            (v for v in document.tool_security_contracts
             if (v.server_ref, v.tool_name) == lookup),
            None,
        )
    contract = find_contract(content)
    original_contract = find_contract(source)
    if contract is None:
        raise ToolObservationRenewalError("reviewed_draft_contract_required")
    if original_contract is not None and contract.contract_hash != original_contract.contract_hash:
        raise ToolObservationRenewalError("contract_changed_requires_new_review")

    review = db.scalar(
        select(ToolHumanReview)
        .where(
            ToolHumanReview.tool_id == tool.id,
            ToolHumanReview.fingerprint == expected_fingerprint,
        )
        .order_by(ToolHumanReview.id.desc()).limit(1)
    )
    if review is None or review.action != "allow" or review.reviewer != actor.username:
        raise ToolObservationRenewalError("current_explicit_admin_allow_review_required")
    baseline = db.scalar(
        select(ToolApprovedBaseline).where(ToolApprovedBaseline.tool_id == tool.id)
    )
    if (
        baseline is None or baseline.analysis_id != review.analysis_id
        or baseline.fingerprint != expected_fingerprint
        or baseline.approval_source != "ADMIN" or baseline.reviewer != actor.username
    ):
        raise ToolObservationRenewalError("current_admin_review_baseline_required")

    # Validate every supported profile before writing any new approval.
    profiles = tuple(dict.fromkeys(server.supported_protocol_profiles or (
        server.preferred_upstream_profile,
    )))
    if not profiles or any(not profile for profile in profiles):
        raise ToolObservationRenewalError("no_supported_protocol_profiles")
    candidates = []
    for profile in profiles:
        observation = latest_protocol_observation(
            db, tool_id=tool.id, upstream_protocol_profile_id=profile
        )
        if (
            observation is None
            or observation.tool_fingerprint != expected_fingerprint
            or observation.server_ref != server_ref
            or observation.tool_name != tool.name
            or observation.analysis_state != "ADMIN_ALLOWED"
        ):
            raise ToolObservationRenewalError("current_observation_not_admin_allowed")
        analysis = db.get(ToolAnalysis, observation.analysis_id) if observation.analysis_id else None
        if (
            analysis is None or analysis.id != review.analysis_id
            or analysis.fingerprint != expected_fingerprint
            or analysis.analysis_status != "ADMIN_ALLOWED"
            or analysis.review_status != "ADMIN_ALLOWED"
        ):
            raise ToolObservationRenewalError("review_does_not_match_current_analysis")
        try:
            approved_analysis_provenance(db, observation, analysis)
        except ValueError as exc:
            raise ToolObservationRenewalError("analysis_provenance_not_verified") from exc
        # Previous published approval is context only, never authority for a
        # new report. A changed report is allowed only after a NEW completed
        # analysis, a NEW explicit ADMIN review and current pipeline verification.
        source_approval = next((
            a for a in source.tool_observation_approvals
            if a.server_ref == server_ref
            and a.upstream_protocol_profile_id == profile
            and a.tool_fingerprint == expected_fingerprint
            and a.contract_hash == contract.contract_hash
            and a.tool_observation_id == observation.id
        ), None)
        source_record = None
        if source_approval is not None:
            source_record = db.scalar(
                select(ToolObservationReviewApproval).where(
                    ToolObservationReviewApproval.revision_id == published.id,
                    ToolObservationReviewApproval.observation_id == observation.id,
                    ToolObservationReviewApproval.contract_hash == contract.contract_hash,
                    ToolObservationReviewApproval.evidence_bundle_hash
                    == source_approval.evidence_bundle_hash,
                )
            )
            if (
                source_record is None
                or source_record.admin_id != source_approval.admin_id
                or not isinstance(source_record.evidence_bundle, dict)
                or sha256_canonical_json(source_record.evidence_bundle)
                   != source_approval.evidence_bundle_hash
            ):
                raise ToolObservationRenewalError("source_approval_record_invalid")
        elif original_contract is not None:
            raise ToolObservationRenewalError("signed_source_profile_approval_missing")

        try:
            current_evidence = evidence_bundle_for_observation(db, observation)
        except ValueError as exc:
            raise ToolObservationRenewalError("current_evidence_unavailable") from exc
        exact_admin_promotion = (
            source_record is not None and source_record.active
            and only_admin_allow_status_changed(source_record.evidence_bundle, current_evidence)
        )
        fresh_explicit_review = (
            analysis.completed_at is not None
            and review.created_at is not None
            and review.created_at >= analysis.completed_at
            and baseline.analysis_id == analysis.id
            and baseline.analysis_context_hash == analysis.analysis_context_hash
            and (source_record is None or (
                analysis.completed_at > source_record.approved_at
                and review.created_at > source_record.approved_at
            ))
        )
        if not (exact_admin_promotion or fresh_explicit_review):
            raise ToolObservationRenewalError("security_evidence_changed_requires_new_review")
        candidates.append(observation)

    # Supersede only old approvals tied to this exact draft/tool. They remain
    # in the audit ledger but cannot be mistaken for the fresh decision.
    candidate_ids = [ob.id for ob in candidates]
    db.execute(update(ToolObservationReviewApproval).where(
        ToolObservationReviewApproval.revision_id == draft.id,
        ToolObservationReviewApproval.observation_id.in_(candidate_ids),
        ToolObservationReviewApproval.active.is_(True),
    ).values(active=False))
    approvals = []
    for observation in candidates:
        try:
            approvals.append(approve_tool_observation(
                db,
                observation_id=observation.id,
                contract=contract,
                admin_id=actor.id,
                revision_id=draft.id,
            ))
        except ValueError as exc:
            raise ToolObservationRenewalError(str(exc)) from exc

    # Explicit ADMIN approval replaces only this tool's stale draft entries.
    # Other tools' approved evidence stays untouched.
    kept = tuple(
        a for a in content.tool_observation_approvals
        if not (a.server_ref == server_ref and a.tool_fingerprint == expected_fingerprint
                and a.contract_hash == contract.contract_hash)
    )
    updated = content.model_copy(update={
        "tool_observation_approvals": kept + tuple(approvals)
    })
    patch_draft_revision(
        db, draft_id=draft.id, content=updated, actor=actor,
        change_summary=change_summary,
        expected_content_hash=expected_content_hash,
    )
    # A draft may still contain other unreviewed tools. Full publication
    # runs validate_revision and remains strictly fail-closed.
    return {
        "revision_id": draft.id,
        "tool_id": tool.id,
        "approved_profiles": len(approvals),
        "content_hash": draft.content_hash,
    }
