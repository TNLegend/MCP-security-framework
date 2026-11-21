"""Explicit OD03 coordinator. Preparation and decisions never grant authority.

Activation is a single PostgreSQL transaction; callers must commit before
reporting success. No model inference or remote request occurs under locks.
"""

from app.services.tda.configuration import ANALYZER_REVISION
from app.services.tda_application.analysis_service import ToolAnalysisService
from app.services.tda_application.review_service import ToolReviewService
from app.services.tda.serialization import _json_safe
from app.services.tda.engine import analyze_tool_version
from app.services.tda.m5_context.identity import compute_analysis_context_hash
from app.services.tda.m5_context.identity import compute_tool_fingerprint
from app.services.tda_application.evidence import freeze_before_review
from app.services.tda_application.queries import latest_protocol_observation
from app.services.tda_application.pipeline import (
    configured_pipeline,
    PipelineIntegrityError,
    digest,
)
from app.services.tda_application.evidence import (
    KEY,
    LINEAGE,
    findings,
    freeze_before_review,
)
from app.services.tda_application.observation_approval import (
    evidence_bundle_for_observation,
    approve_tool_observation,
)
from app.services.tda_application.requalification import prepare
from app.services.tda_application.exposure_preview import preview
from app.services.tda_application.authority import (
    AuthorityToken,
    control_plane_activation,
)
from app.services.tda_application.authority import bind_result_authority
from app.models.mcp_tool import MCPTool
from app.models.tool_analysis import ToolAnalysis
from app.models.tool_analysis import ToolAnalysisFinding
from app.models.tool_analysis import ToolApprovedBaseline
from app.models.tool_analysis import ToolHumanReview
from app.models.tool_analysis import ToolObservedVersion
from app.models.tool_analysis import ToolProtocolObservation
from datetime import datetime
from copy import deepcopy
from sqlalchemy import select
from copy import deepcopy
from dataclasses import asdict, is_dataclass
from datetime import datetime
from sqlalchemy import select, and_, or_
from app.models.analyzer_authority import AnalyzerAuthority
from app.models.analyzer_migration import (
    AnalyzerMigration,
    AnalyzerMigrationDecision,
    AnalyzerMigrationActivation,
)
from app.models.control_plane import ControlPlaneUser, EmergencyDeny
from app.services.emergency_deny import active_emergency_deny_clause
from app.models.tool_analysis import (
    ToolAnalysis,
    ToolAnalysisFinding,
    ToolProtocolObservation,
    ToolObservedVersion,
    ToolObservationReviewApproval,
    ToolHumanReview,
    ToolApprovedBaseline,
)
from app.services.published_configuration import PublishedConfigurationProvider
from app.services.control_plane_audit import record_control_plane_audit
from app.services.revision_signing import sign_revision_payload, verify_revision_payload
from common.canonical_json import sha256_canonical_json


class MigrationError(ValueError):
    pass


def _admin(db, admin_id):
    row = db.get(ControlPlaneUser, admin_id, populate_existing=True)
    if row is None or not row.enabled or row.role != "ADMIN":
        raise MigrationError("migration_admin_required")
    return row


def _assert_packet(run):
    if sha256_canonical_json(run.payload) != run.packet_hash:
        raise MigrationError("migration_packet_changed")


def _report(db, analysis):
    value = {
        k: deepcopy(getattr(analysis, k))
        for k in (
            "analysis_status",
            "review_status",
            "risk_score",
            "risk_level",
            "consistency_status",
            "drift_status",
            "consistency_result",
            "drift_result",
            "model_versions",
            "analyzer_revision",
        )
    }
    value["semantic_scores"] = {
        k: v
        for k, v in (analysis.semantic_scores or {}).items()
        if k not in (KEY, LINEAGE)
    }
    value["semantic_flagged"] = analysis.semantic_flagged == "true"
    value["deterministic_critical_finding"] = (
        analysis.deterministic_critical_finding == "true"
    )
    value["findings"] = findings(db, analysis.id)
    return value


def _source(db, approval):
    obs = db.get(
        ToolProtocolObservation, approval.tool_observation_id, populate_existing=True
    )
    if obs is None or obs.analysis_id is None:
        raise MigrationError("migration_observation_missing")
    analysis = db.get(ToolAnalysis, obs.analysis_id, populate_existing=True)
    if (
        analysis is None
        or analysis.tool_id != obs.tool_id
        or analysis.fingerprint != obs.tool_fingerprint
        or (obs.tool_fingerprint != approval.tool_fingerprint)
        or (obs.server_ref != approval.server_ref)
        or (obs.upstream_protocol_profile_id != approval.upstream_protocol_profile_id)
    ):
        raise MigrationError("migration_source_identity_changed")
    version = db.get(ToolObservedVersion, analysis.version_id, populate_existing=True)
    review = db.scalar(
        select(ToolObservationReviewApproval).where(
            ToolObservationReviewApproval.observation_id == obs.id,
            ToolObservationReviewApproval.revision_id == approval.revision_id,
            ToolObservationReviewApproval.evidence_bundle_hash
            == approval.evidence_bundle_hash,
            ToolObservationReviewApproval.contract_hash == approval.contract_hash,
            ToolObservationReviewApproval.active.is_(True),
        )
    )
    if (
        not isinstance(obs.canonical_tool_definition, dict)
        or obs.canonical_tool_definition.get("tool_name") != obs.tool_name
        or compute_tool_fingerprint(obs.canonical_tool_definition)
        != obs.tool_fingerprint
    ):
        raise MigrationError("migration_source_definition_invalid")
    expected_context = compute_analysis_context_hash(
        {"contract_hash": approval.contract_hash}
    )
    if (
        version is None
        or analysis.analysis_context_hash != expected_context
        or compute_analysis_context_hash(version.profile_snapshot) != expected_context
    ):
        raise MigrationError("migration_source_profile_context_mismatch")
    bundle = evidence_bundle_for_observation(db, obs)
    if (
        review is None
        or review.admin_id != approval.admin_id
        or review.tool_fingerprint != obs.tool_fingerprint
        or (sha256_canonical_json(bundle) != approval.evidence_bundle_hash)
    ):
        raise MigrationError("migration_source_approval_changed")
    baseline = db.scalar(
        select(ToolApprovedBaseline).where(ToolApprovedBaseline.tool_id == obs.tool_id)
    )
    baseline_version = (
        db.get(ToolObservedVersion, baseline.version_id) if baseline else None
    )
    context = {
        "observation_id": obs.id,
        "protocol_profile_id": obs.upstream_protocol_profile_id,
        "tool_fingerprint": obs.tool_fingerprint,
        "contract_hash": approval.contract_hash,
        "tool_id": obs.tool_id,
        "analysis_id": analysis.id,
        "version_id": analysis.version_id,
        "source_approval_id": review.id,
        "source_bundle_hash": approval.evidence_bundle_hash,
        "definition": deepcopy(obs.canonical_tool_definition),
        "profile": deepcopy(version.profile_snapshot) if version else None,
        "baseline": deepcopy(baseline_version.snapshot) if baseline_version else None,
    }
    return (obs, analysis, context)


def prepare_migration(db, *, admin_id):
    """Reanalyse current ADMIN-approved observations using verified local models.

    The current observation pointers, approvals and pipeline authority stay
    unchanged. Stale preparation is allowed to exist but cannot activate.
    """
    if db.info.get("control_plane_config_process_lock_held") or db.info.get(
        "analyzer_authority_token"
    ):
        raise MigrationError("migration_preparation_requires_unlocked_session")
    admin = _admin(db, admin_id)
    pipeline = configured_pipeline()
    source = PublishedConfigurationProvider(db).load_active_snapshot(fresh=True)
    authority = db.get(AnalyzerAuthority, 1, populate_existing=True)
    if authority is None:
        raise MigrationError("migration_source_authority_missing")
    before = {
        "generation": authority.generation,
        "pipeline_identity": authority.pipeline_identity,
    }
    source_execution = authority.execution_digest
    target_execution = digest(pipeline._manifest["execution"])
    items = []
    service = ToolAnalysisService(pipeline=pipeline)
    for approval in source.content.tool_observation_approvals:
        obs, analysis, context = _source(db, approval)
        old = _report(db, analysis)
        definition = context["definition"]
        snapshot = {
            "name": obs.tool_name,
            "description": definition.get("description") or "",
            "input_schema": definition.get("input_schema") or {},
            "output_schema": definition.get("output_schema") or {},
            "annotations": definition.get("annotations") or {},
            "execution": definition.get("execution") or {},
        }
        # Historical V1 evidence is read for comparison only. Fresh
        # observations are inferred exclusively through locally pinned M4;
        # no prior approval is inherited as a runtime permission.
        from app.services.tda_application import m4_service as m4_service
        m4_report, proof = m4_service.infer_m4_description(
            snapshot["description"]
        )
        result = analyze_tool_version(
            tool_snapshot=snapshot,
            profile_snapshot=context["profile"],
            baseline_snapshot=context["baseline"],
            embedding_model=service.embedding_model,
            m4_report=m4_report, m4_identity=proof.identity,
            m4_pipeline_identity=pipeline.identity,
        )
        report = {k: _json_safe(result[k]) for k in old if k != "analyzer_revision"}
        report["findings"] = [
            asdict(f) if is_dataclass(f) else deepcopy(f) for f in result["findings"]
        ]
        report["analyzer_revision"] = ANALYZER_REVISION
        comparison = prepare(old, report, source_context=context)
        candidate_projection = preview(definition, obs.tool_name)
        previous_review = db.get(
            ToolObservationReviewApproval, context["source_approval_id"]
        )
        previous_definition = (previous_review.evidence_bundle or {}).get(
            "canonical_tool_definition"
        )
        previous_projection = (
            preview(previous_definition, obs.tool_name)
            if source_execution == target_execution
            and isinstance(previous_definition, dict)
            else None
        )
        group_context_verified = (
            source_execution == target_execution
            and previous_projection == candidate_projection
        )
        items.append(
            {
                "context": context,
                "source_approval": approval.model_dump(mode="json"),
                "old_report": old,
                "candidate_report": report,
                "source_projection_preview": previous_projection,
                "candidate_projection_preview": candidate_projection,
                "disposition": comparison.disposition
                if group_context_verified
                else "INDIVIDUAL_REVIEW_REQUIRED",
                "difference_paths": [d.pointer for d in comparison.differences],
            }
        )
    payload = {
        "schema": "tda-od03-migration-v1",
        "source_authority": before,
        "source_execution_digest": source_execution,
        "target_execution_digest": target_execution,
        "source_revision": {
            "id": source.revision_id,
            "number": source.revision_number,
            "hash": source.content_hash,
        },
        "target_pipeline": pipeline.identity,
        "target_analyzer_revision": ANALYZER_REVISION,
        "items": items,
    }
    run = AnalyzerMigration(
        prepared_by=admin.id,
        payload=payload,
        packet_hash=sha256_canonical_json(payload),
    )
    db.add(run)
    db.flush()
    record_control_plane_audit(
        db,
        actor=admin,
        action="ANALYZER_MIGRATION_PREPARED",
        target_type="analyzer_migration",
        target_id=run.id,
        after_json={
            "packet_hash": run.packet_hash,
            "target_pipeline": pipeline.identity,
            "observations": len(items),
        },
        reason="Non-authoritative reanalysis; no approval changed",
    )
    return run


def _load(db, migration_id):
    run = db.get(AnalyzerMigration, migration_id, populate_existing=True)
    if run is None:
        raise MigrationError("migration_not_found")
    _assert_packet(run)
    if run.state != "PREPARED":
        raise MigrationError("migration_not_prepared")
    return run


def decide_migration(
    db, *, migration_id, admin_id, packet_hash, decisions, grouped=False
):
    """Append signed nominative decisions. No inference, approval or publication."""
    from app.services.control_plane_config import _acquire_config_revision_lock

    _acquire_config_revision_lock(db)
    admin = _admin(db, admin_id)
    run = _load(db, migration_id)
    if packet_hash != run.packet_hash:
        raise MigrationError("migration_review_packet_mismatch")
    by_id = {item["context"]["observation_id"]: item for item in run.payload["items"]}
    ids = [d["observation_id"] for d in decisions]
    if not ids or len(ids) != len(set(ids)):
        raise MigrationError("migration_explicit_unique_observations_required")
    for decision in decisions:
        item = by_id.get(decision["observation_id"])
        if (
            item is None
            or decision.get("action") not in {"APPROVE", "EXCLUDE"}
            or (not decision.get("reason", "").strip())
        ):
            raise MigrationError("migration_decision_invalid")
        if decision.get("confirmed") is not True:
            raise MigrationError("migration_individual_confirmation_required")
        if grouped and item["disposition"] not in {
            "IDENTITY_ONLY_REQUIRES_EXPLICIT_REVIEW",
            "EXACT_REQUIRES_CURRENT_AUTHORITY_CHECK",
        }:
            raise MigrationError("migration_individual_review_required")
        act = {
            "context": "mcp/tda/migration-decision/v1",
            "migration_id": run.id,
            "packet_hash": run.packet_hash,
            "observation_id": decision["observation_id"],
            "admin_id": admin.id,
            "action": decision["action"],
            "reason": decision["reason"],
            "grouped": grouped,
            "target_pipeline": run.payload["target_pipeline"],
        }
        signature, key_id = sign_revision_payload(act)
        db.add(
            AnalyzerMigrationDecision(
                migration_id=run.id,
                observation_id=decision["observation_id"],
                admin_id=admin.id,
                act=act,
                signature=signature,
                signature_key_id=key_id,
            )
        )
        record_control_plane_audit(
            db,
            actor=admin,
            action="ANALYZER_MIGRATION_DECISION",
            target_type="analyzer_migration",
            target_id=run.id,
            after_json=act,
            reason=decision["reason"],
        )
    db.flush()


def _veto(db, obs):
    latest = latest_protocol_observation(
        db,
        tool_id=obs.tool_id,
        upstream_protocol_profile_id=obs.upstream_protocol_profile_id,
    )
    if latest is None or latest.id != obs.id:
        raise MigrationError("migration_observation_superseded")
    review = db.scalar(
        select(ToolHumanReview)
        .where(ToolHumanReview.tool_id == obs.tool_id)
        .order_by(ToolHumanReview.id.desc())
        .limit(1)
    )
    if review is not None and review.action in {"block", "keep_review_required"}:
        raise MigrationError("migration_human_hold_active")
    deny = db.scalar(
        select(EmergencyDeny.id)
        .where(
            active_emergency_deny_clause(),
            or_(
                EmergencyDeny.target_type == "global",
                and_(
                    EmergencyDeny.target_type == "server_ref",
                    EmergencyDeny.target_value == obs.server_ref,
                ),
                and_(
                    EmergencyDeny.target_type == "server_tool",
                    EmergencyDeny.target_value == obs.server_ref,
                    EmergencyDeny.target_secondary_value == obs.tool_name,
                ),
            ),
        )
        .limit(1)
    )
    if deny is not None:
        raise MigrationError("migration_emergency_deny_active")


def activate_migration(db, *, migration_id, admin_id, packet_hash):
    from app.services.control_plane_config import (
        _acquire_config_revision_lock,
        create_revision,
        patch_draft_revision,
        publish_revision,
    )
    from app.services.discovery_generation import lock_review_catalog_scope
    from app.services.dispatch_admission import lock_emergency_dispatch_authority
    from app.schemas.control_plane import ControlPlaneConfigContent
    from proxy.tool_security_v2 import ToolObservationApproval

    if db.info.get("analyzer_inference_transaction"):
        raise MigrationError("migration_cannot_activate_inference_transaction")
    if db.info.get("control_plane_config_process_lock_held"):
        raise MigrationError("migration_activation_requires_catalog_before_config")
    admin = _admin(db, admin_id)
    run = _load(db, migration_id)
    if packet_hash != run.packet_hash:
        raise MigrationError("migration_review_packet_mismatch")
    payload = run.payload
    pipeline = configured_pipeline()
    if pipeline.identity != payload["target_pipeline"]:
        raise MigrationError("migration_target_pipeline_changed")
    from app.models.mcp_tool import MCPTool
    from app.models.mcp_server import MCPServer
    from app.services.discovery_generation import (
        discovery_scope_key,
        _lock_generation_authority,
    )

    def scopes():
        result = {}
        for tool_id in {x["context"]["tool_id"] for x in payload["items"]}:
            row = db.execute(
                select(MCPServer.transport, MCPServer.endpoint)
                .select_from(MCPTool)
                .join(MCPServer, MCPServer.id == MCPTool.server_id)
                .where(MCPTool.id == tool_id)
            ).one_or_none()
            if row is None:
                raise MigrationError("migration_tool_missing")
            result[tool_id] = discovery_scope_key(
                transport=row.transport, endpoint=row.endpoint
            )
        return result

    captured_scopes = scopes()
    for scope in sorted(set(captured_scopes.values())):
        _lock_generation_authority(db, scope_key=scope)
    if scopes() != captured_scopes:
        raise MigrationError("migration_catalog_scope_changed")
    _acquire_config_revision_lock(db)
    admin = _admin(db, admin_id)
    locked_run = _load(db, migration_id)
    if locked_run.packet_hash != packet_hash or locked_run.payload != payload:
        raise MigrationError("migration_packet_changed_while_waiting")
    lock_emergency_dispatch_authority(db, require_postgresql=True)
    source = PublishedConfigurationProvider(db).load_active_snapshot(fresh=True)
    if payload["source_revision"] != {
        "id": source.revision_id,
        "number": source.revision_number,
        "hash": source.content_hash,
    }:
        raise MigrationError("migration_source_revision_changed")
    decisions = {
        d.observation_id: d
        for d in db.scalars(
            select(AnalyzerMigrationDecision).where(
                AnalyzerMigrationDecision.migration_id == run.id
            )
        )
    }
    expected = {x["context"]["observation_id"] for x in payload["items"]}
    if set(decisions) != expected:
        raise MigrationError("migration_explicit_decisions_incomplete")
    checked = []
    for item in payload["items"]:
        oid = item["context"]["observation_id"]
        decision = decisions[oid]
        _admin(db, decision.admin_id)
        verify_revision_payload(
            decision.act,
            signature=decision.signature,
            key_id=decision.signature_key_id,
            algorithm="Ed25519",
            version="1",
        )
        if (
            decision.act["packet_hash"] != run.packet_hash
            or decision.act["target_pipeline"] != pipeline.identity
            or decision.act["observation_id"] != oid
            or (decision.act["admin_id"] != decision.admin_id)
        ):
            raise MigrationError("migration_decision_binding_changed")
        obs, old, context = _source(
            db, ToolObservationApproval.model_validate(item["source_approval"])
        )
        if context != item["context"]:
            raise MigrationError("migration_source_context_changed")
        if decision.act["action"] == "APPROVE":
            _veto(db, obs)
            if (
                preview(obs.canonical_tool_definition, obs.tool_name)
                != item["candidate_projection_preview"]
            ):
                raise MigrationError("migration_projection_preview_changed")
            report = item["candidate_report"]
            if report["deterministic_critical_finding"] or report[
                "analysis_status"
            ] not in {"APPROVED", "ADMIN_ALLOWED", "REVIEW_REQUIRED"}:
                raise MigrationError("migration_candidate_not_approvable")
            if (
                report["model_versions"] != pipeline.model_versions
                or report["analyzer_revision"] != ANALYZER_REVISION
            ):
                raise MigrationError("migration_candidate_identity_changed")
        checked.append((item, decision, obs, old))
    previous = AuthorityToken(**payload["source_authority"])
    with control_plane_activation(
        db,
        admin_id=admin.id,
        manifest_approval_ref="od03:" + run.id + ":" + run.packet_hash,
        expected_previous=previous,
    ) as token:
        content = source.content.model_copy(update={"tool_observation_approvals": ()})
        draft = create_revision(
            db,
            content=content,
            status="DRAFT",
            actor=admin,
            parent_revision_id=source.revision_id,
            change_summary="Explicit OD03 migration " + run.id,
        )
        approvals = []
        for item, decision, obs, old in checked:
            if decision.act["action"] == "EXCLUDE":
                continue
            report = deepcopy(item["candidate_report"])
            new_findings = report.pop("findings")
            for flag in ("semantic_flagged", "deterministic_critical_finding"):
                report[flag] = str(report[flag]).lower()
            analysis = ToolAnalysis(
                tool_id=obs.tool_id,
                version_id=old.version_id,
                fingerprint=obs.tool_fingerprint,
                analysis_context_hash=compute_analysis_context_hash(
                    {"contract_hash": item["context"]["contract_hash"]}
                ),
                completed_at=datetime.utcnow(),
                **report,
            )
            db.add(analysis)
            db.flush()
            bind_result_authority(db, analysis.id)
            for finding in new_findings:
                db.add(ToolAnalysisFinding(analysis_id=analysis.id, **finding))
            db.flush()
            freeze_before_review(db, analysis)
            obs.analysis_id = analysis.id
            obs.analysis_state = analysis.analysis_status
            db.flush()
            reviewer = _admin(db, decision.admin_id)
            ToolReviewService().approve(
                db=db,
                tool_id=obs.tool_id,
                fingerprint=obs.tool_fingerprint,
                reviewer=reviewer.username,
                justification="Explicit OD03 decision "
                + decision.id
                + ": "
                + decision.act["reason"],
            )
            contract = source.get_tool_security_contract(
                server_ref=obs.server_ref, tool_name=obs.tool_name
            )
            approval = approve_tool_observation(
                db,
                observation_id=obs.id,
                contract=contract,
                admin_id=reviewer.id,
                revision_id=draft.id,
            )
            approvals.append(approval)
            record_control_plane_audit(
                db,
                actor=reviewer,
                action="APPROVAL_EXPLICITLY_RECONDUCTED",
                target_type="tool_protocol_observation",
                target_id=str(obs.id),
                revision_id=draft.id,
                before_json={
                    "source_approval_id": item["context"]["source_approval_id"],
                    "source_bundle_hash": item["context"]["source_bundle_hash"],
                },
                after_json={
                    "decision_id": decision.id,
                    "new_bundle_hash": approval.evidence_bundle_hash,
                    "generation": token.generation,
                    "pipeline_identity": token.pipeline_identity,
                },
                reason=decision.act["reason"],
            )
        content = content.model_copy(
            update={"tool_observation_approvals": tuple(approvals)}
        )
        patch_draft_revision(
            db,
            draft_id=draft.id,
            content=content,
            actor=admin,
            change_summary="Exact new OD03 approvals",
        )
        revision = publish_revision(
            db,
            draft_id=draft.id,
            actor=admin,
            change_summary="Activate explicitly requalified OD03 tools",
        )
        active = PublishedConfigurationProvider(db).load_active_snapshot(fresh=True)
        if active.revision_id != revision.id:
            raise MigrationError("migration_activation_snapshot_mismatch")
        run.state = "ACTIVATED"
        run.activated_generation = token.generation
        run.activated_revision_id = revision.id
        db.add(
            AnalyzerMigrationActivation(
                migration_id=run.id,
                admin_id=admin.id,
                generation=token.generation,
                revision_id=revision.id,
            )
        )
        db.flush()
        return {
            "migration_id": run.id,
            "revision_id": revision.id,
            "generation": token.generation,
            "pipeline_identity": token.pipeline_identity,
        }
