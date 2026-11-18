"""Linearized, durable emergency-deny admission for an upstream MCP dispatch.

A PostgreSQL transaction advisory lock is shared by all dispatch admissions and
the ADMIN deny writers. Its commit order determines which event takes effect
first; it is never held while talking to an external MCP.
"""
from __future__ import annotations

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.models.control_plane import ControlPlaneAuditEvent
from app.models.runtime_call import RuntimeCall
from app.models.mcp_tool import MCPTool
from app.models.tool_analysis import ToolHumanReview
from app.services.emergency_deny import (
    EmergencyDenyError,
    check_emergency_deny,
    emergency_check_payload,
)

EMERGENCY_DISPATCH_LOCK_KEY = 807018003


def lock_emergency_dispatch_authority(
    db: Session, *, require_postgresql: bool = False,
) -> None:
    # A process-local lock cannot serialize two API workers or hosts.
    # SQLite-only administrative fixtures may continue to mutate denies, but
    # admission MUST fail closed outside the PostgreSQL authority.
    if db.get_bind().dialect.name != "postgresql":
        if require_postgresql:
            raise EmergencyDenyError("dispatch_admission_requires_postgresql")
        return
    db.execute(
        text("SELECT pg_advisory_xact_lock(:key)"),
        {"key": EMERGENCY_DISPATCH_LOCK_KEY},
    )


def admit_mcp_dispatch(
    db: Session, *, operation_id: str, context: dict[str, str],
) -> dict[str, object]:
    context = emergency_check_payload(context)
    # Publication/activation take CONFIG before RUNTIME. Acquiring CONFIG
    # after RUNTIME would invert that order and can deadlock two API workers.
    # Hold both through the caller's commit; never through an upstream call.
    from app.services.control_plane_config import _acquire_config_revision_lock
    _acquire_config_revision_lock(db)
    lock_emergency_dispatch_authority(db, require_postgresql=True)

    # A duplicate admission is not an invitation to retry an uncertain side
    # effect. Even after a network failure the previous dispatch might have
    # executed. Record only one admission for one logical operation ID.
    prior = db.scalar(
        select(ControlPlaneAuditEvent.id)
        .where(
            ControlPlaneAuditEvent.action == "RUNTIME_DISPATCH_ADMITTED",
            ControlPlaneAuditEvent.target_type == "runtime_operation",
            ControlPlaneAuditEvent.target_id == operation_id,
        )
        .limit(1)
    )
    if prior is not None:
        return {"admitted": False, "reason": "dispatch_already_admitted"}

    # A terminal outcome, including a pre-dispatch block or auth failure,
    # irrevocably closes this logical operation. A delayed admission request
    # cannot reopen it. Outcome writes share this transaction authority lock.
    existing_outcome = db.scalar(
        select(RuntimeCall.id)
        .where(
            RuntimeCall.operation_id == operation_id,
            RuntimeCall.event_phase == "outcome",
        )
        .limit(1)
    )
    if existing_outcome is not None:
        return {"admitted": False, "reason": "dispatch_operation_already_finalized"}

    intent = db.scalar(
        select(RuntimeCall).execution_options(populate_existing=True).where(
            RuntimeCall.operation_id == operation_id,
            RuntimeCall.event_phase == "intent",
        )
    )
    if (
        intent is None
        or intent.execution_status != "authorized_pending_execution"
        or intent.status != "allowed"
        or intent.agent_id != context["agent_id"]
        or intent.session_id != context["framework_session_id"]
        or intent.tool_name != context["tool_name"]
    ):
        return {"admitted": False, "reason": "dispatch_intent_missing_or_invalid"}

    deny = check_emergency_deny(db, **context)
    if deny is not None:
        return {"admitted": False, "reason": "emergency_deny_active", "deny_id": deny}

    # Re-evaluate the latest human decision under the SAME transaction lock
    # that serializes administrative BLOCK/REVIEW_REQUIRED writes. An old
    # signed approval or stale Proxy inventory snapshot cannot undo a hold.
    if intent.server_id is None:
        return {"admitted": False, "reason": "dispatch_tool_identity_missing"}
    tool = db.scalar(
        select(MCPTool).execution_options(populate_existing=True).where(
            MCPTool.server_id == intent.server_id,
            MCPTool.name == context["tool_name"],
        )
    )
    if tool is None or not intent.upstream_protocol_profile_id:
        return {"admitted": False, "reason": "dispatch_tool_identity_missing"}
    from app.models.tool_analysis import ToolProtocolObservation
    from app.models.mcp_server import MCPServer
    from common.mcp_endpoint import server_ref_for_server
    server = db.get(MCPServer, intent.server_id, populate_existing=True)
    if server is None or server_ref_for_server({
        "endpoint": server.endpoint, "transport": server.transport,
    }) != context["server_ref"]:
        return {"admitted": False, "reason": "dispatch_tool_identity_missing"}
    observation = db.scalar(
        select(ToolProtocolObservation).execution_options(populate_existing=True)
        .where(
            ToolProtocolObservation.tool_id == tool.id,
            ToolProtocolObservation.upstream_protocol_profile_id ==
                intent.upstream_protocol_profile_id,
            ToolProtocolObservation.server_ref == context["server_ref"],
        )
        .order_by(
            ToolProtocolObservation.last_seen_at.desc(),
            ToolProtocolObservation.id.desc(),
        )
        .limit(1)
    )
    if observation is None:
        return {"admitted": False, "reason": "dispatch_tool_identity_missing"}
    # An earlier ALLOW is specific to one immutable observed definition.
    # A newly discovered profile fingerprint must not inherit that ALLOW.
    if (
        not intent.tool_fingerprint
        or observation.tool_fingerprint != intent.tool_fingerprint
    ):
        return {"admitted": False, "reason": "dispatch_observation_fingerprint_changed"}
    # Review holds are independently authoritative even if an approval
    # snapshot or an analysis status has already become stale. Preserve the
    # precise human-veto decision while also checking the current evidence.
    latest_review = db.scalar(
        select(ToolHumanReview).execution_options(populate_existing=True)
        .where(
            ToolHumanReview.tool_id == tool.id,
            ToolHumanReview.fingerprint == observation.tool_fingerprint,
        )
        .order_by(ToolHumanReview.id.desc())
        .limit(1)
    )
    if latest_review is not None and latest_review.action in {
        "block", "keep_review_required",
    }:
        return {"admitted": False, "reason": "human_review_hold_active"}

    # The previously authorized observation and linked analysis must still
    # be eligible at the final dispatch boundary. An older signed approval
    # does not upgrade an observation/analysis that became stale or blocked.
    from app.models.tool_analysis import ToolAnalysis
    analysis = (
        db.get(ToolAnalysis, observation.analysis_id, populate_existing=True)
        if observation.analysis_id is not None else None
    )
    approved = {"APPROVED", "ADMIN_ALLOWED"}
    if (
        observation.analysis_state not in approved
        or analysis is None
        or analysis.tool_id != tool.id
        or analysis.fingerprint != observation.tool_fingerprint
        or analysis.analysis_status not in approved
        or analysis.review_status not in approved
    ):
        return {"admitted": False, "reason": "dispatch_observation_not_approved"}

    from app.services.tda_application.authority import (
        verified_observation_token, assert_current, fence_session,
    )
    from app.services.published_configuration import PublishedConfigurationProvider
    try:
        # Recheck the current model/source identity (not owner-signed) and
        # analyzer generation at this locked dispatch boundary.
        # fence_session and assert_current keep DB-generation fencing intact.
        authority_token = fence_session(db, verified_observation_token(analysis))
        assert_current(db,authority_token)
        from app.services.tda_application.authority import (
            assert_analysis_generation_current,
        )
        assert_analysis_generation_current(db,analysis.id,authority_token)
        snapshot=PublishedConfigurationProvider(db).load_active_snapshot(fresh=True)
        # These are configuration revision coordinates, not a tool fingerprint
        # or the hash of one contract. An unchanged contract/approval in C2
        # cannot authorize a preparation/OPA decision made under C1.
        prepared_revision = (intent.control_plane_revision_id,
                             intent.control_plane_revision_number,
                             intent.control_plane_content_hash)
        active_revision = (snapshot.revision_id, snapshot.revision_number,
                           snapshot.content_hash)
        if prepared_revision != active_revision:
            db.add(ControlPlaneAuditEvent(
                action="RUNTIME_DISPATCH_REJECTED", target_type="runtime_operation",
                target_id=operation_id, event_metadata={
                    "reason":"dispatch_configuration_revision_changed",
                    "prepared_revision":list(prepared_revision),
                    "active_revision":list(active_revision)}))
            db.flush()
            return {"admitted":False,"reason":"dispatch_configuration_revision_changed"}
        contract=snapshot.get_tool_security_contract(server_ref=context['server_ref'],tool_name=context['tool_name'])
        approval=snapshot.get_tool_observation_approval(server_ref=context['server_ref'],
            upstream_protocol_profile_id=observation.upstream_protocol_profile_id,
            tool_fingerprint=observation.tool_fingerprint)
        if approval.contract_hash!=contract.contract_hash:
            return {'admitted':False,'reason':'dispatch_contract_approval_changed'}
        from app.models.tool_analysis import ToolObservationReviewApproval
        from app.services.tda_application.observation_approval import evidence_bundle_for_observation
        from common.canonical_json import sha256_canonical_json
        live=db.scalar(select(ToolObservationReviewApproval.id).where(
            ToolObservationReviewApproval.observation_id==observation.id,
            ToolObservationReviewApproval.revision_id==approval.revision_id,
            ToolObservationReviewApproval.evidence_bundle_hash==approval.evidence_bundle_hash,
            ToolObservationReviewApproval.active.is_(True)))
        if (approval.tool_observation_id!=observation.id or live is None
            or sha256_canonical_json(evidence_bundle_for_observation(db,observation))!=approval.evidence_bundle_hash):
            return {'admitted':False,'reason':'dispatch_approval_revoked_or_changed'}
    except Exception:
        return {'admitted':False,'reason':'dispatch_authority_or_contract_unavailable'}

    db.add(ControlPlaneAuditEvent(
        action="RUNTIME_DISPATCH_ADMITTED",
        target_type="runtime_operation",
        target_id=operation_id,
        event_metadata={
            "agent_id": context["agent_id"],
            "server_ref": context["server_ref"],
            "tool_name": context["tool_name"],
            "control_plane_revision_id": snapshot.revision_id,
            "control_plane_revision_number": snapshot.revision_number,
            "control_plane_content_hash": snapshot.content_hash,
            "contract_hash": contract.contract_hash,
            "analyzer_generation": authority_token.generation,
            "pipeline_identity": authority_token.pipeline_identity,
        },
    ))
    db.flush()
    # Caller MUST commit before reporting that dispatch can occur. The
    # advisory lock is released by that commit, never before.
    return {"admitted": True}
