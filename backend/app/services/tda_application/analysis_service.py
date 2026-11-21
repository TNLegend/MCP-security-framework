from __future__ import annotations
from app.services.tda.configuration import ANALYZER_REVISION
from app.services.tda.configuration import APPROVAL_SOURCE_ADMIN
from app.services.tda.configuration import APPROVAL_SOURCE_FRAMEWORK
from app.services.tda.configuration import DRIFT_NONE
from app.services.tda.configuration import EMBEDDING_MODEL_NAME
from app.services.tda.types import EmbeddingModel
from app.services.tda.configuration import STATUS_ADMIN_ALLOWED
from app.services.tda.configuration import STATUS_ANALYSIS_FAILED
from app.services.tda.configuration import STATUS_APPROVED
from app.services.tda.configuration import STATUS_BLOCKED
from app.services.tda.configuration import STATUS_QUARANTINED
from app.services.tda_application.status_reasons import reason_for
from app.services.tda_application.m3_shadow_projection import (
    project_m3_report,
    unavailable as m3_unavailable,
)
from app.services.tda.configuration import STATUS_REVIEW_REQUIRED
from app.services.tda.configuration import STATUS_STALE
from app.services.tda.models.e5 import LocalEmbeddingModel
from app.services.tda_application.pipeline import (
    configured_pipeline,
)
from app.services.tda_application.evidence import KEY as EVIDENCE_KEY
from app.services.tda.findings import _finding
from app.services.tda.serialization import _json_safe
from app.services.tda.engine import analyze_tool_version
from app.services.tda_application.queries import approved_protocol_observation_exists
from app.services.tda_application.queries import baseline_for_tool
from app.services.tda.m5_context.identity import compute_analysis_context_hash
from app.services.tda.m5_context.identity import compute_tool_fingerprint
from app.services.tda_application.evidence import freeze_before_review
from app.services.tda_application.evidence import has_frozen_evidence
from app.services.tda_application.queries import latest_analysis_for_tool
from app.services.tda_application.queries import latest_protocol_observation
from app.services.tda.m5_context.identity import reusable_analysis_context_hash
from app.services.tda.m5_context.identity import tool_fingerprint_payload
from app.services.tda_application.queries import tool_snapshot_from_model
from app.services.tda_application.evidence import validate_frozen
from app.services.tda_application.authority import fence_session
from app.services.tda_application.authority import bind_result_authority
from app.services.tda_application.evidence import LINEAGE as REUSE_LINEAGE
from typing import Any
from proxy.protocol_profiles import LEGACY_PROFILE_ID
from app.models.mcp_tool import MCPTool
from sqlalchemy.orm import Session
from app.models.tool_analysis import ToolAnalysis
from app.models.tool_analysis import ToolApprovedBaseline
from app.models.tool_analysis import ToolObservedVersion
from app.models.tool_analysis import ToolProtocolObservation
from datetime import datetime


class ToolAnalysisService:
    """One locally fingerprinted GLiNER/DeBERTa M4. M6 owns E5 drift.

    V1 is NOT supported for new observations. Historical signed reports
    remain evidence in the database but are never implicitly approved.
    """
    def __init__(self, *, pipeline=None) -> None:
        import os
        if os.environ.get("ANALYZER_M4_V2_ENABLED","1") != "1":
            raise ValueError("M4_V2_ANALYZER_REQUIRED")
        pipeline = configured_pipeline() if pipeline is None else pipeline
        if not getattr(pipeline, "m4_v2", False):
            raise ValueError("M4_V2_ANALYZER_REQUIRED")
        from app.services.tda_application.pipeline import execution_configuration_v2
        pipeline.assert_execution(execution_configuration_v2())
        self.pipeline = pipeline
        self._m4_mode = True
        # M4 does not use the M6 E5 embeddings to infer semantics.
        self.semantic_model = None
        self.embedding_model = LocalEmbeddingModel(pipeline=pipeline)
        self._last_model_versions = None
        self._last_model_instances = None

    def _current_model_versions(self) -> dict[str, Any]:
        from copy import deepcopy
        return deepcopy(self.pipeline.model_versions)

    def observe_and_analyze(
        self,
        *,
        db: Session,
        tool: MCPTool,
        server_ref: str,
        profile_snapshot: dict[str, Any] | None,
        upstream_protocol_profile_id: str = LEGACY_PROFILE_ID,
        source_observation: ToolProtocolObservation | None = None,
        precomputed_analysis: dict[str, Any] | None = None,
    ) -> ToolAnalysis:
        from app.models.tool_analysis import ToolAnalysis
        from app.models.tool_analysis import ToolAnalysisFinding
        from app.models.tool_analysis import ToolHumanReview
        from app.models.tool_analysis import ToolObservedVersion
        from common.canonical_json import canonical_json_bytes
        from datetime import datetime
        from sqlalchemy import select
        from hashlib import sha256

        # Disallow runtime mode flips that could change the analyzer without
        # a new local generation and explicit migration.
        import os
        if self._m4_mode != (os.environ.get("ANALYZER_M4_V2_ENABLED","1") == "1"):
            raise ValueError("M4_ANALYZER_MODE_CHANGED_AFTER_SERVICE_STARTUP")
        # Capture the worker generation before inference; commit rechecks it.
        fence_session(db, purpose="ANALYSIS")
        now = datetime.utcnow()
        observed_before = latest_protocol_observation(
            db,
            tool_id=tool.id,
            upstream_protocol_profile_id=upstream_protocol_profile_id,
        )
        if source_observation is None:
            snapshot = tool_snapshot_from_model(tool)
        else:
            if (
                source_observation.tool_id != tool.id
                or source_observation.upstream_protocol_profile_id
                != upstream_protocol_profile_id
                or source_observation.analysis_state == STATUS_STALE
            ):
                raise ValueError("source_observation_profile_mismatch")
            current_profile_observation = latest_protocol_observation(
                db,
                tool_id=tool.id,
                upstream_protocol_profile_id=upstream_protocol_profile_id,
            )
            if (
                current_profile_observation is None
                or current_profile_observation.id != source_observation.id
            ):
                raise ValueError("source_observation_not_current")
            observed = source_observation.canonical_tool_definition
            if (
                not isinstance(observed, dict)
                or observed.get("tool_name") != tool.name
                or compute_tool_fingerprint(observed)
                != source_observation.tool_fingerprint
            ):
                raise ValueError("source_observation_definition_invalid")
            latest_profile_observation = latest_protocol_observation(
                db,
                tool_id=tool.id,
                upstream_protocol_profile_id=upstream_protocol_profile_id,
            )
            if (
                latest_profile_observation is None
                or latest_profile_observation.id != source_observation.id
            ):
                raise ValueError("source_observation_not_current")
            snapshot = {
                "name": tool.name,
                "description": observed.get("description") or "",
                "input_schema": observed.get("input_schema") or {},
                "output_schema": observed.get("output_schema") or {},
                "annotations": observed.get("annotations") or {},
                "execution": observed.get("execution") or {},
            }
        source_expected_analysis_id = (
            source_observation.analysis_id if source_observation is not None else None
        )
        fingerprint_payload = tool_fingerprint_payload(
            server_ref=server_ref,
            tool_name=tool.name,
            description=snapshot["description"],
            input_schema=snapshot["input_schema"],
            output_schema=snapshot["output_schema"],
            annotations=snapshot["annotations"],
            execution=snapshot["execution"],
            profile=profile_snapshot,
        )
        if (
            source_observation is not None
            and compute_tool_fingerprint(fingerprint_payload)
            != source_observation.tool_fingerprint
        ):
            raise ValueError("source_observation_fingerprint_changed")
        fingerprint = compute_tool_fingerprint(fingerprint_payload)
        analysis_context_hash = compute_analysis_context_hash(profile_snapshot)
        baseline = baseline_for_tool(db, tool.id)
        active_model_versions = self._current_model_versions()
        # TA-01: evaluate the SAME baseline conditions as before, in order,
        # and keep the first failing one as the enumerated restriction cause.
        baseline_mismatch_reason = baseline_mismatch_reason_for(
            baseline=baseline,
            fingerprint=fingerprint,
            analysis_context_hash=analysis_context_hash,
            active_model_versions=active_model_versions,
            approval_evidence_frozen=lambda: has_frozen_evidence(
                db.get(ToolAnalysis, baseline.analysis_id)),
            protocol_observation_approved=lambda: approved_protocol_observation_exists(
                db,
                tool_id=tool.id,
                upstream_protocol_profile_id=upstream_protocol_profile_id,
                fingerprint=fingerprint,
            ),
        )
        approved_match = baseline_mismatch_reason is None
        version = db.scalar(
            select(ToolObservedVersion).where(
                ToolObservedVersion.tool_id == tool.id,
                ToolObservedVersion.fingerprint == fingerprint,
            )
        )
        if version is None:
            version = ToolObservedVersion(
                tool_id=tool.id,
                server_ref=server_ref,
                tool_name=tool.name,
                fingerprint=fingerprint,
                status="new" if baseline is None else "changed",
                snapshot=snapshot,
                profile_snapshot=profile_snapshot,
                profile_revision=(profile_snapshot or {}).get("revision", "unknown"),
                first_seen_at=now,
                last_seen_at=now,
            )
            db.add(version)
            db.flush()
        else:
            version.status = "identical"
            version.last_seen_at = now
        latest_human_review = db.scalar(
            select(ToolHumanReview)
            .where(ToolHumanReview.tool_id == tool.id)
            .order_by(ToolHumanReview.id.desc())
        )
        pending_human_hold = (
            latest_human_review is not None
            and latest_human_review.action in {"block", "keep_review_required"}
        )
        if pending_human_hold and latest_human_review.fingerprint == fingerprint:
            last_reviewed_analysis = latest_analysis_for_tool(db, tool.id)
            if (
                last_reviewed_analysis is not None
                and last_reviewed_analysis.fingerprint == fingerprint
                and (
                    last_reviewed_analysis.analysis_status
                    in {STATUS_BLOCKED, STATUS_REVIEW_REQUIRED}
                )
            ):
                tool.current_fingerprint = fingerprint
                tool.approved_fingerprint = baseline.fingerprint if baseline else None
                tool.approved_fingerprint_match = False
                tool.analysis_status = last_reviewed_analysis.analysis_status
                tool.review_status = last_reviewed_analysis.review_status
                tool.policy_status = last_reviewed_analysis.analysis_status
                tool.status = last_reviewed_analysis.analysis_status
                tool.last_analyzed_at = now
                return last_reviewed_analysis
        tool.current_fingerprint = fingerprint
        tool.approved_fingerprint = baseline.fingerprint if baseline else None
        tool.approved_fingerprint_match = approved_match and (not pending_human_hold)
        approved_status = _approval_status_for_baseline(baseline) if baseline else None
        tool.analysis_status = approved_status if approved_match else STATUS_QUARANTINED
        tool.review_status = (
            approved_status if approved_match else STATUS_REVIEW_REQUIRED
        )
        tool.status = approved_status if approved_match else STATUS_QUARANTINED
        tool.status_reason = reason_for(tool.status, baseline_mismatch_reason)
        tool.last_analyzed_at = now
        if approved_match and (not pending_human_hold):
            analysis = self._record_approved_observation(
                db, tool, version, baseline, analysis_context_hash, now
            )
            self._record_protocol_observation(
                db,
                tool=tool,
                server_ref=server_ref,
                upstream_protocol_profile_id=upstream_protocol_profile_id,
                canonical_tool_definition=fingerprint_payload,
                fingerprint=fingerprint,
                analysis=analysis,
                now=now,
                expected_observation_id=source_observation.id
                if source_observation is not None
                else None,
                expected_observation_analysis_id=source_expected_analysis_id,
            )
            return analysis
        reusable_analysis = None
        if baseline is None:
            reusable_analysis = db.scalar(
                select(ToolAnalysis)
                .where(
                    ToolAnalysis.version_id == version.id,
                    ToolAnalysis.analysis_context_hash == analysis_context_hash,
                    ToolAnalysis.analyzer_revision == ANALYZER_REVISION,
                    ToolAnalysis.analysis_status != STATUS_ANALYSIS_FAILED,
                )
                .order_by(ToolAnalysis.id.desc())
            )
        if reusable_analysis is not None and (
            not has_frozen_evidence(reusable_analysis)
            or active_model_versions is None
            or reusable_analysis.model_versions != active_model_versions
        ):
            reusable_analysis = None
        if reusable_analysis is not None:
            validate_frozen(
                db, reusable_analysis, reusable_analysis.semantic_scores[EVIDENCE_KEY]
            )
            apply_analysis_to_tool(
                tool,
                reusable_analysis,
                baseline,
                protocol_approved_match=approved_protocol_observation_exists(
                    db,
                    tool_id=tool.id,
                    upstream_protocol_profile_id=upstream_protocol_profile_id,
                    fingerprint=fingerprint,
                ),
            )
            self._record_protocol_observation(
                db,
                tool=tool,
                server_ref=server_ref,
                upstream_protocol_profile_id=upstream_protocol_profile_id,
                canonical_tool_definition=fingerprint_payload,
                fingerprint=fingerprint,
                analysis=reusable_analysis,
                now=now,
                expected_observation_id=source_observation.id
                if source_observation is not None
                else None,
                expected_observation_analysis_id=source_expected_analysis_id,
            )
            return reusable_analysis
        baseline_snapshot = None
        if baseline is not None:
            baseline_version = db.get(ToolObservedVersion, baseline.version_id)
            baseline_snapshot = baseline_version.snapshot if baseline_version else None
        if precomputed_analysis is not None:
            # F11 staged catalog evidence must be from this same signed V2
            # analyzer and must carry source-bound M4, never historic V1.
            if (
                self.pipeline is not None
                and precomputed_analysis.get("model_versions")
                != self.pipeline.model_versions
            ):
                raise ValueError("discovery_staged_pipeline_changed")
            if (
                source_observation is not None
                or baseline is not None
                or observed_before is not None
                or (version.status != "new")
                or (precomputed_analysis.get("definition_fingerprint") != fingerprint)
                or (
                    precomputed_analysis.get("profile_digest")
                    != sha256(canonical_json_bytes(profile_snapshot)).hexdigest()
                )
                or (
                    precomputed_analysis.get("model_versions")
                    != precomputed_analysis.get("result", {}).get("model_versions")
                )
                or (latest_human_review is not None)
            ):
                raise ValueError("discovery_staged_analysis_provenance_changed")
            from app.services.discovery_analysis_staging import model_artifact_digest

            if (
                precomputed_analysis.get("model_artifact_digest")
                != model_artifact_digest()
            ):
                raise ValueError("discovery_stage_model_artifact_changed")
            result = precomputed_analysis["result"]
            bound = (result.get("semantic_scores") or {}).get("m4_structured_semantics")
            if (
                not isinstance(bound, dict)
                or bound.get("analyzer_pipeline_sha256") != self.pipeline.identity
                or bound.get("m4_model_identity_sha256")
                   != self.pipeline._manifest.get("m4_model_identity_sha256")
                or result.get("model_versions") != self.pipeline.model_versions
            ):
                raise ValueError("discovery_staged_m4_content_identity_required")
            if result.get("analysis_status") in {
                STATUS_APPROVED,
                STATUS_ADMIN_ALLOWED,
            } or result.get("review_status") in {STATUS_APPROVED, STATUS_ADMIN_ALLOWED}:
                raise ValueError("discovery_staged_analysis_cannot_grant_approval")
        else:
            try:
                from app.services.tda_application import m4_service as m4_service
                m4_report = None
                m4_identity = None
                if self._m4_mode:
                    # Local content identity is mandatory; the same bounded worker
                    # handles both this controlling route and ADMIN read-only M4.
                    m4_report, proof = m4_service.infer_m4_description(
                        snapshot["description"]
                    )
                    m4_identity = proof.identity
                result = analyze_tool_version(
                    tool_snapshot=snapshot,
                    profile_snapshot=profile_snapshot,
                    baseline_snapshot=baseline_snapshot,
                    embedding_model=self.embedding_model,
                    m4_report=m4_report,
                    m4_identity=m4_identity,
                    m4_pipeline_identity=(
                        self.pipeline.identity
                        if getattr(self.pipeline, "m4_v2", False) else None
                    ),
                )
            except Exception as exc:
                result = {
                    "analysis_status": STATUS_ANALYSIS_FAILED,
                    "risk_score": 100,
                    "risk_level": "critical",
                    "semantic_flagged": False,
                    "deterministic_critical_finding": False,
                    "consistency_status": "unknown",
                    "drift_status": DRIFT_NONE,
                    "review_status": STATUS_ANALYSIS_FAILED,
                    "semantic_scores": None,
                    "consistency_result": None,
                    "drift_result": {
                        "status": DRIFT_NONE,
                        "changes": [],
                        "similarity": None,
                    },
                    "model_versions": self.pipeline.model_versions,
                    "findings": [
                        _finding(
                            "analysis_failed",
                            "analyzer",
                            "description",
                            "critical",
                            100,
                            str(exc.__class__.__name__),
                            "Keep the tool blocked until analysis succeeds.",
                        )
                    ],
                }
        if result["analysis_status"] != STATUS_ANALYSIS_FAILED:
            self._last_model_versions = result["model_versions"]
            self._last_model_instances = (self.semantic_model, self.embedding_model)
        if profile_snapshot is None and result["analysis_status"] == STATUS_APPROVED:
            result["analysis_status"] = STATUS_QUARANTINED
            result["review_status"] = STATUS_REVIEW_REQUIRED
            result["status_reason"] = "APPROVED_PROFILE_MISSING"
        from app.services.dispatch_admission import lock_emergency_dispatch_authority

        # Serialize only the post-inference authority read and persistence.
        # Never hold the global dispatch authority lock during inference.
        lock_emergency_dispatch_authority(db)
        observed_after = latest_protocol_observation(
            db,
            tool_id=tool.id,
            upstream_protocol_profile_id=upstream_protocol_profile_id,
        )
        if (
            observed_after is not None
            and observed_after.tool_fingerprint != fingerprint
            and (
                observed_before is None
                or observed_after.id != observed_before.id
                or observed_after.tool_fingerprint != observed_before.tool_fingerprint
            )
        ):
            raise ValueError("analysis_observation_changed_during_inference")
        committed_review = db.scalar(
            select(ToolHumanReview)
            .where(ToolHumanReview.tool_id == tool.id)
            .order_by(ToolHumanReview.id.desc())
            .limit(1)
        )
        if committed_review is not None and committed_review.action in {
            "block",
            "keep_review_required",
        }:
            pending_human_hold = True
        model_upgrade_needs_admin_review = (
            baseline is not None
            and baseline.approval_source == APPROVAL_SOURCE_ADMIN
            and (baseline.fingerprint == fingerprint)
            and (baseline.analysis_context_hash == analysis_context_hash)
            and (
                baseline.analyzer_revision != ANALYZER_REVISION
                or baseline.model_versions != result["model_versions"]
                or (not has_frozen_evidence(db.get(ToolAnalysis, baseline.analysis_id)))
            )
        )
        if pending_human_hold and result["analysis_status"] == STATUS_APPROVED:
            result["analysis_status"] = STATUS_REVIEW_REQUIRED
            result["review_status"] = STATUS_REVIEW_REQUIRED
            result["findings"].append(
                _finding(
                    "prior_human_review_requires_new_approval",
                    "analyzer",
                    "review",
                    "medium",
                    100,
                    "An explicit human deny or review decision is still active.",
                    "Review the newly observed definition before approving it.",
                )
            )
        if (
            model_upgrade_needs_admin_review
            and result["analysis_status"] == STATUS_APPROVED
        ):
            result["analysis_status"] = STATUS_REVIEW_REQUIRED
            result["review_status"] = STATUS_REVIEW_REQUIRED
            result["findings"].append(
                _finding(
                    "approved_analyzer_revision_changed"
                    if baseline.analyzer_revision != ANALYZER_REVISION
                    else "approved_model_version_changed",
                    "analyzer",
                    "model_versions",
                    "medium",
                    100,
                    "Previously human-reviewed evidence requires requalification under the current Analyzer and model identity.",
                    "Review the reanalyzed tool before granting approval again.",
                )
            )
        analysis = ToolAnalysis(
            tool_id=tool.id,
            version_id=version.id,
            fingerprint=fingerprint,
            analysis_context_hash=analysis_context_hash,
            analysis_status=result["analysis_status"],
            status_reason=reason_for(result["analysis_status"], result.get("status_reason")),
            risk_score=result["risk_score"],
            risk_level=result["risk_level"],
            semantic_flagged=str(bool(result["semantic_flagged"])).lower(),
            deterministic_critical_finding=str(
                bool(result["deterministic_critical_finding"])
            ).lower(),
            consistency_status=result["consistency_status"],
            drift_status=result["drift_status"],
            review_status=result["review_status"],
            # TA-02: persist the advisory M3 SHADOW projection next to the
            # semantic evidence. It never alters any status computed above.
            semantic_scores=(
                {
                    **result["semantic_scores"],
                    "m3_shadow": (
                        project_m3_report(result["m3_report"])
                        if "m3_report" in result
                        else m3_unavailable(
                            "M3_REPORT_NOT_RETAINED_BY_DISCOVERY_STAGE"
                            if precomputed_analysis is not None
                            else "M3_REPORT_NOT_PRODUCED"
                        )
                    ),
                }
                if isinstance(result["semantic_scores"], dict)
                else result["semantic_scores"]
            ),
            consistency_result=_json_safe(result["consistency_result"]),
            drift_result=result["drift_result"],
            model_versions=result["model_versions"],
            analyzer_revision=ANALYZER_REVISION,
            created_at=now,
            completed_at=now,
        )
        db.add(analysis)
        db.flush()
        bind_result_authority(db, analysis.id)
        for finding in result["findings"]:
            db.add(
                ToolAnalysisFinding(
                    analysis_id=analysis.id,
                    code=finding.code,
                    category=finding.category,
                    source=finding.source,
                    severity=finding.severity,
                    confidence=finding.confidence,
                    evidence=finding.evidence,
                    recommendation=finding.recommendation,
                )
            )
        db.flush()
        freeze_before_review(db, analysis)
        if result["analysis_status"] == STATUS_APPROVED:
            baseline = _upsert_framework_baseline(
                db=db, tool_id=tool.id, version=version, analysis=analysis
            )
        apply_analysis_to_tool(
            tool,
            analysis,
            baseline,
            protocol_approved_match=result["analysis_status"] == STATUS_APPROVED
            or approved_protocol_observation_exists(
                db,
                tool_id=tool.id,
                upstream_protocol_profile_id=upstream_protocol_profile_id,
                fingerprint=fingerprint,
            ),
        )
        self._record_protocol_observation(
            db,
            tool=tool,
            server_ref=server_ref,
            upstream_protocol_profile_id=upstream_protocol_profile_id,
            canonical_tool_definition=fingerprint_payload,
            fingerprint=fingerprint,
            analysis=analysis,
            now=now,
            expected_observation_id=source_observation.id
            if source_observation is not None
            else None,
            expected_observation_analysis_id=source_expected_analysis_id,
        )
        return analysis

    def _record_protocol_observation(
        self,
        db: Session,
        *,
        tool: MCPTool,
        server_ref: str,
        upstream_protocol_profile_id: str,
        canonical_tool_definition: dict[str, Any],
        fingerprint: str,
        analysis: ToolAnalysis,
        now: datetime,
        expected_observation_id: int | None = None,
        expected_observation_analysis_id: int | None = None,
    ) -> ToolProtocolObservation:
        from app.models.mcp_tool import MCPTool
        from proxy.protocol_profiles import ProtocolProfileError
        from proxy.protocol_profiles import ProtocolProfileRegistry
        from app.models.tool_analysis import ToolProtocolObservation
        from sqlalchemy import select

        try:
            protocol_profile = ProtocolProfileRegistry().get(
                upstream_protocol_profile_id
            )
        except ProtocolProfileError as exc:
            raise ValueError("unsupported_mcp_protocol_profile") from exc
        if expected_observation_id is not None:
            db.scalar(select(MCPTool.id).where(MCPTool.id == tool.id).with_for_update())
            current = latest_protocol_observation(
                db,
                tool_id=tool.id,
                upstream_protocol_profile_id=upstream_protocol_profile_id,
            )
            if (
                current is None
                or current.id != expected_observation_id
                or current.tool_fingerprint != fingerprint
                or (current.analysis_state == STATUS_STALE)
            ):
                raise ValueError("source_observation_not_current")
        if expected_observation_id is not None:
            latest = db.scalar(
                select(ToolProtocolObservation)
                .where(
                    ToolProtocolObservation.tool_id == tool.id,
                    ToolProtocolObservation.upstream_protocol_profile_id
                    == upstream_protocol_profile_id,
                )
                .order_by(
                    ToolProtocolObservation.last_seen_at.desc(),
                    ToolProtocolObservation.id.desc(),
                )
                .limit(1)
                .with_for_update()
                .execution_options(populate_existing=True)
            )
            if latest is None or latest.id != expected_observation_id:
                raise ValueError("source_observation_not_current")
            if latest.analysis_id != expected_observation_analysis_id:
                raise ValueError("source_observation_changed_during_reanalysis")
        observation = db.scalar(
            select(ToolProtocolObservation).where(
                ToolProtocolObservation.tool_id == tool.id,
                ToolProtocolObservation.upstream_protocol_profile_id
                == upstream_protocol_profile_id,
                ToolProtocolObservation.tool_fingerprint == fingerprint,
            ).with_for_update()
        )
        if observation is None:
            if expected_observation_id is not None:
                raise ValueError("reanalysis_observation_not_found")
            observation = ToolProtocolObservation(
                tool_id=tool.id,
                server_ref=server_ref,
                upstream_protocol_profile_id=upstream_protocol_profile_id,
                protocol_era=protocol_profile.protocol_era.value,
                protocol_version=protocol_profile.protocol_version,
                transport_kind=protocol_profile.transport_kind.value,
                tool_name=tool.name,
                canonical_tool_definition=canonical_tool_definition,
                tool_fingerprint=fingerprint,
                analysis_state=analysis.analysis_status,
                analysis_id=analysis.id,
                observed_at=now,
                last_seen_at=now,
            )
            db.add(observation)
        else:
            if (
                expected_observation_id is not None
                and observation.id != expected_observation_id
            ):
                raise ValueError("reanalysis_observation_identity_mismatch")
            from app.models.tool_analysis import ToolObservationReviewApproval
            # A newly produced analysis is a CANDIDATE, not an ADMIN-approved
            # replacement for already published, profile-specific evidence.
            # This applies to ordinary rediscovery AND explicit reanalysis.
            # The exact observed tool fingerprint is unchanged; a different
            # definition still creates a separate observation and has no ALLOW.
            signed_origin = db.scalar(
                select(ToolObservationReviewApproval.id).where(
                    ToolObservationReviewApproval.observation_id == observation.id,
                    ToolObservationReviewApproval.tool_fingerprint == fingerprint,
                    ToolObservationReviewApproval.active.is_(True),
                ).limit(1)
            )
            if (
                signed_origin is not None
                and observation.analysis_id is not None
                and observation.analysis_id != analysis.id
            ):
                # Do not rebind the signed evidence bundle to a new analysis.
                # Retain the previous visible status and origin; no new
                # approval, signature or policy permission is created here.
                # The candidate remains in ToolAnalysis for ADMIN review.
                approved_analysis = db.get(
                    ToolAnalysis, observation.analysis_id, populate_existing=True
                )
                if approved_analysis is not None:
                    apply_analysis_to_tool(
                        tool, approved_analysis, baseline_for_tool(db, tool.id),
                        protocol_approved_match=True,
                    )
                if expected_observation_id is None:
                    observation.last_seen_at = now
                db.flush()
                return observation
            observation.protocol_era = protocol_profile.protocol_era.value
            observation.protocol_version = protocol_profile.protocol_version
            observation.transport_kind = protocol_profile.transport_kind.value
            observation.analysis_state = analysis.analysis_status
            observation.analysis_id = analysis.id
            if expected_observation_id is None:
                observation.last_seen_at = now
        db.flush()
        return observation

    def _record_approved_observation(
        self,
        db: Session,
        tool: MCPTool,
        version: ToolObservedVersion,
        baseline: ToolApprovedBaseline,
        analysis_context_hash: str,
        now: datetime,
    ) -> ToolAnalysis:
        from app.models.tool_analysis import ToolAnalysis
        from app.models.tool_analysis import ToolAnalysisFinding
        from app.models.tool_analysis import ToolHumanReview
        from copy import deepcopy
        from sqlalchemy import select
        from app.services.discovery_generation import lock_review_catalog_scope
        from app.services.dispatch_admission import lock_emergency_dispatch_authority

        lock_review_catalog_scope(db, tool_id=tool.id)
        lock_emergency_dispatch_authority(db)
        latest = db.scalar(
            select(ToolHumanReview)
            .where(ToolHumanReview.tool_id == tool.id)
            .order_by(ToolHumanReview.id.desc())
            .limit(1)
        )
        if latest is not None and latest.action in {"block", "keep_review_required"}:
            raise ValueError("approval_reuse_human_hold_active")
        db.refresh(baseline)
        if (
            baseline.fingerprint != version.fingerprint
            or baseline.analysis_context_hash != analysis_context_hash
            or baseline.analyzer_revision != ANALYZER_REVISION
        ):
            raise ValueError("approval_reuse_context_changed")
        source_analysis = db.get(ToolAnalysis, baseline.analysis_id)
        if source_analysis is None or source_analysis.completed_at is None:
            raise ValueError("approved_baseline_evidence_missing")
        db.refresh(source_analysis)
        record = (source_analysis.semantic_scores or {}).get(EVIDENCE_KEY)
        if record is None:
            raise ValueError("legacy_review_evidence_not_frozen")
        payload = validate_frozen(db, source_analysis, record)
        analysis = ToolAnalysis(
            tool_id=tool.id,
            version_id=version.id,
            fingerprint=version.fingerprint,
            analysis_context_hash=analysis_context_hash,
            analysis_status=_approval_status_for_baseline(baseline),
            risk_score=source_analysis.risk_score,
            risk_level=source_analysis.risk_level,
            semantic_flagged=source_analysis.semantic_flagged,
            deterministic_critical_finding=source_analysis.deterministic_critical_finding,
            consistency_status=source_analysis.consistency_status,
            drift_status=source_analysis.drift_status,
            review_status=_approval_status_for_baseline(baseline),
            semantic_scores={
                **deepcopy(source_analysis.semantic_scores or {}),
                REUSE_LINEAGE: {
                    "execution_kind": "REUSED_APPROVAL",
                    "source_analysis_id": source_analysis.id,
                    "original_evidence_analysis_id": payload["source_analysis_id"],
                    "source_evidence_sha256": record["sha256"],
                    "new_semantic_inference": False,
                },
            },
            consistency_result=deepcopy(source_analysis.consistency_result),
            drift_result=deepcopy(source_analysis.drift_result),
            model_versions=source_analysis.model_versions,
            analyzer_revision=baseline.analyzer_revision,
            created_at=now,
            completed_at=now,
        )
        db.add(analysis)
        db.flush()
        bind_result_authority(db, analysis.id)
        for finding in payload["findings"]:
            db.add(ToolAnalysisFinding(analysis_id=analysis.id, **deepcopy(finding)))
        db.flush()
        apply_analysis_to_tool(tool, analysis, baseline, protocol_approved_match=True)
        return analysis


def baseline_mismatch_reason_for(
    *,
    baseline: Any,
    fingerprint: str,
    analysis_context_hash: str | None,
    active_model_versions: Any,
    approval_evidence_frozen,
    protocol_observation_approved,
) -> str | None:
    """TA-01: the approved-baseline conditions, evaluated in their historical
    order. Returns the FIRST failing condition as an enumerated cause, or None
    when the baseline still matches. The two database checks are callables so
    they keep their original short-circuit behaviour."""
    if baseline is None:
        return "NO_APPROVED_BASELINE"
    if baseline.fingerprint != fingerprint:
        return "FINGERPRINT_CHANGED"
    if not (
        reusable_analysis_context_hash(baseline.analysis_context_hash)
        and baseline.analysis_context_hash == analysis_context_hash
    ):
        return "APPROVED_CONTEXT_CHANGED"
    if not (
        baseline.analyzer_revision == ANALYZER_REVISION
        and active_model_versions is not None
        and baseline.model_versions == active_model_versions
    ):
        return "ANALYSIS_OBSOLETE"
    if not approval_evidence_frozen():
        return "APPROVAL_EVIDENCE_MISSING"
    if not protocol_observation_approved():
        return "PROTOCOL_OBSERVATION_NOT_APPROVED"
    return None


def apply_analysis_to_tool(
    tool: MCPTool,
    analysis: ToolAnalysis,
    baseline: ToolApprovedBaseline | None,
    *,
    protocol_approved_match: bool | None = None,
) -> None:
    approved_context_match = (
        baseline is not None
        and baseline.fingerprint == analysis.fingerprint
        and reusable_analysis_context_hash(baseline.analysis_context_hash)
        and (baseline.analysis_context_hash == analysis.analysis_context_hash)
        and (baseline.analyzer_revision == ANALYZER_REVISION)
        and (analysis.analyzer_revision == ANALYZER_REVISION)
        and (baseline.model_versions == analysis.model_versions)
        and (analysis.analysis_status in {STATUS_APPROVED, STATUS_ADMIN_ALLOWED})
        and (analysis.review_status in {STATUS_APPROVED, STATUS_ADMIN_ALLOWED})
        and (protocol_approved_match is not False)
    )
    tool.current_fingerprint = analysis.fingerprint
    tool.approved_fingerprint = baseline.fingerprint if baseline else None
    tool.approved_fingerprint_match = approved_context_match
    tool.analysis_status = analysis.analysis_status
    tool.review_status = analysis.review_status
    tool.risk_score = analysis.risk_score
    tool.risk_level = analysis.risk_level
    tool.semantic_flagged = analysis.semantic_flagged == "true"
    tool.deterministic_critical_finding = (
        analysis.deterministic_critical_finding == "true"
    )
    tool.consistency_status = analysis.consistency_status
    tool.drift_status = analysis.drift_status
    tool.analyzer_revision = analysis.analyzer_revision
    tool.policy_status = analysis.analysis_status
    tool.status = analysis.analysis_status
    tool.status_reason = reason_for(tool.status, getattr(analysis, "status_reason", None))
    semantic_facts = (analysis.semantic_scores or {}).get("facts")
    if isinstance(semantic_facts, dict):
        tool.is_sensitive = semantic_facts.get("is_sensitive") is True
        sensitivity = semantic_facts.get("sensitivity")
        tool.sensitivity = sensitivity if isinstance(sensitivity, str) else "unknown"
    tool.last_analyzed_at = analysis.completed_at or analysis.created_at


def mark_tool_contract_pending_publication(tool: MCPTool) -> None:
    """Keep draft-backed analysis evidence from becoming a runtime admission state."""
    tool.analysis_status = STATUS_QUARANTINED
    tool.review_status = STATUS_REVIEW_REQUIRED
    tool.policy_status = STATUS_QUARANTINED
    tool.status = STATUS_QUARANTINED
    tool.status_reason = "CONTRACT_PENDING_PUBLICATION"
    tool.approved_fingerprint_match = False


def _upsert_framework_baseline(
    *, db: Session, tool_id: int, version: ToolObservedVersion, analysis: ToolAnalysis
) -> ToolApprovedBaseline:
    from app.models.tool_analysis import ToolApprovedBaseline
    from datetime import datetime

    freeze_before_review(db, analysis)
    baseline = baseline_for_tool(db, tool_id)
    values = {
        "version_id": version.id,
        "analysis_id": analysis.id,
        "fingerprint": analysis.fingerprint,
        "analysis_context_hash": analysis.analysis_context_hash,
        "approval_source": APPROVAL_SOURCE_FRAMEWORK,
        "reviewer": "framework",
        "justification": "Automatically approved after a clean completed analysis.",
        "analyzer_revision": analysis.analyzer_revision,
        "model_versions": analysis.model_versions,
    }
    if baseline is None:
        baseline = ToolApprovedBaseline(tool_id=tool_id, **values)
        db.add(baseline)
    else:
        for field, value in values.items():
            setattr(baseline, field, value)
        baseline.approved_at = datetime.utcnow()
    db.flush()
    return baseline


def _approval_status_for_baseline(baseline: ToolApprovedBaseline) -> str:
    if baseline.approval_source == APPROVAL_SOURCE_ADMIN:
        return STATUS_ADMIN_ALLOWED
    return STATUS_APPROVED
