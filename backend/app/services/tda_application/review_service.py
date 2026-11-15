from __future__ import annotations
from app.services.tda.configuration import ANALYZER_REVISION
from app.services.tda.configuration import APPROVAL_SOURCE_ADMIN
from app.services.tda.configuration import MIN_REVIEW_JUSTIFICATION_LENGTH
from app.services.tda.configuration import STATUS_ADMIN_ALLOWED
from app.services.tda.configuration import STATUS_APPROVED
from app.services.tda.configuration import STATUS_BLOCKED
from app.services.tda.configuration import STATUS_REVIEW_REQUIRED
from app.services.tda.configuration import STATUS_STALE
from app.services.tda_application.analysis_service import apply_analysis_to_tool
from app.services.tda_application.queries import baseline_for_tool
from app.services.tda_application.evidence import freeze_before_review
from app.services.tda_application.queries import latest_analysis_for_tool
from app.services.tda_application.authority import assert_current, fence_session
from app.services.tda.m5_context.identity import reusable_analysis_context_hash
from app.services.tda_application.pipeline import require_current_pipeline
from sqlalchemy.orm import Session
from app.models.tool_analysis import ToolAnalysis
from app.models.tool_analysis import ToolApprovedBaseline
from app.models.tool_analysis import ToolHumanReview
from app.models.tool_analysis import ToolObservedVersion


class ToolReviewService:
    def approve(
        self,
        *,
        db: Session,
        tool_id: int,
        fingerprint: str,
        reviewer: str,
        justification: str,
    ) -> ToolApprovedBaseline:
        from app.models.mcp_tool import MCPTool
        from app.models.tool_analysis import ToolApprovedBaseline
        from app.models.tool_analysis import ToolObservedVersion
        from app.models.tool_analysis import ToolProtocolObservation
        from datetime import datetime
        from sqlalchemy import select

        # Fence before reading evidence; catalog locks precede dispatch authority.
        token = fence_session(db)
        from app.services.discovery_generation import lock_review_catalog_scope
        from app.services.dispatch_admission import lock_emergency_dispatch_authority

        lock_review_catalog_scope(db, tool_id=tool_id)
        lock_emergency_dispatch_authority(db)
        assert_current(db, token)
        analysis = latest_analysis_for_tool(db, tool_id)
        if analysis is None or analysis.fingerprint != fingerprint:
            raise ValueError("fingerprint does not match the latest analysis.")
        _validate_review(reviewer, justification)
        version = db.get(ToolObservedVersion, analysis.version_id)
        if version is None:
            raise ValueError("observed version is missing.")
        _validate_approvable_analysis(db, tool_id, fingerprint, analysis, version)
        freeze_before_review(db, analysis)
        baseline = baseline_for_tool(db, tool_id)
        if baseline is None:
            baseline = ToolApprovedBaseline(
                tool_id=tool_id,
                version_id=version.id,
                analysis_id=analysis.id,
                fingerprint=fingerprint,
                analysis_context_hash=analysis.analysis_context_hash,
                approval_source=APPROVAL_SOURCE_ADMIN,
                reviewer=reviewer,
                justification=justification,
                analyzer_revision=analysis.analyzer_revision,
                model_versions=analysis.model_versions,
            )
            db.add(baseline)
        else:
            baseline.version_id = version.id
            baseline.analysis_id = analysis.id
            baseline.fingerprint = fingerprint
            baseline.analysis_context_hash = analysis.analysis_context_hash
            baseline.approval_source = APPROVAL_SOURCE_ADMIN
            baseline.reviewer = reviewer
            baseline.justification = justification
            baseline.analyzer_revision = analysis.analyzer_revision
            baseline.model_versions = analysis.model_versions
            baseline.approved_at = datetime.utcnow()
        analysis.analysis_status = STATUS_ADMIN_ALLOWED
        analysis.review_status = STATUS_ADMIN_ALLOWED
        self._record_review(
            db=db,
            action="allow",
            analysis=analysis,
            reviewer=reviewer,
            justification=justification,
        )
        tool = db.get(MCPTool, tool_id)
        if tool is not None:
            apply_analysis_to_tool(tool, analysis, baseline)
        observations = db.scalars(
            select(ToolProtocolObservation).where(
                ToolProtocolObservation.tool_id == tool_id,
                ToolProtocolObservation.analysis_id == analysis.id,
                ToolProtocolObservation.tool_fingerprint == analysis.fingerprint,
                ToolProtocolObservation.analysis_state != STATUS_STALE,
            )
        ).all()
        for observation in observations:
            observation.analysis_state = analysis.analysis_status
        db.flush()
        return baseline

    def block(
        self,
        *,
        db: Session,
        tool_id: int,
        fingerprint: str,
        reviewer: str,
        justification: str,
    ) -> ToolHumanReview:
        from app.models.mcp_tool import MCPTool
        from app.services.discovery_generation import lock_review_catalog_scope
        from app.services.dispatch_admission import lock_emergency_dispatch_authority

        lock_review_catalog_scope(db, tool_id=tool_id)
        lock_emergency_dispatch_authority(db)
        analysis = latest_analysis_for_tool(db, tool_id)
        if analysis is None or analysis.fingerprint != fingerprint:
            raise ValueError("fingerprint does not match the latest analysis.")
        _validate_review(reviewer, justification)
        analysis.analysis_status = STATUS_BLOCKED
        analysis.review_status = STATUS_BLOCKED
        review = self._record_review(
            db=db,
            action="block",
            analysis=analysis,
            reviewer=reviewer,
            justification=justification,
        )
        tool = db.get(MCPTool, tool_id)
        if tool is not None:
            apply_analysis_to_tool(
                tool,
                analysis,
                baseline_for_tool(db, tool_id),
                protocol_approved_match=False,
            )
            tool.approved_fingerprint_match = False
        return review

    def keep_review_required(
        self,
        *,
        db: Session,
        tool_id: int,
        fingerprint: str,
        reviewer: str,
        justification: str,
    ) -> ToolHumanReview:
        from app.models.mcp_tool import MCPTool
        from app.services.discovery_generation import lock_review_catalog_scope
        from app.services.dispatch_admission import lock_emergency_dispatch_authority

        lock_review_catalog_scope(db, tool_id=tool_id)
        lock_emergency_dispatch_authority(db)
        analysis = latest_analysis_for_tool(db, tool_id)
        if analysis is None or analysis.fingerprint != fingerprint:
            raise ValueError("fingerprint does not match the latest analysis.")
        _validate_review(reviewer, justification)
        analysis.analysis_status = STATUS_REVIEW_REQUIRED
        analysis.review_status = STATUS_REVIEW_REQUIRED
        review = self._record_review(
            db=db,
            action="keep_review_required",
            analysis=analysis,
            reviewer=reviewer,
            justification=justification,
        )
        tool = db.get(MCPTool, tool_id)
        if tool is not None:
            apply_analysis_to_tool(
                tool,
                analysis,
                baseline_for_tool(db, tool_id),
                protocol_approved_match=False,
            )
            tool.approved_fingerprint_match = False
        return review

    def _record_review(
        self,
        *,
        db: Session,
        action: str,
        analysis: ToolAnalysis,
        reviewer: str,
        justification: str,
    ) -> ToolHumanReview:
        from app.models.audit_event import AuditEvent
        from app.models.tool_analysis import ToolHumanReview
        from app.services.dispatch_admission import lock_emergency_dispatch_authority

        lock_emergency_dispatch_authority(db)
        review = ToolHumanReview(
            tool_id=analysis.tool_id,
            version_id=analysis.version_id,
            analysis_id=analysis.id,
            action=action,
            fingerprint=analysis.fingerprint,
            reviewer=reviewer,
            justification=justification,
        )
        db.add(review)
        db.add(
            AuditEvent(
                category="tool_analysis_review",
                summary=f"Tool analysis review action: {action}",
                related_event_id=str(analysis.tool_id),
                decision=action,
                evidence={
                    "tool_id": analysis.tool_id,
                    "analysis_id": analysis.id,
                    "fingerprint": analysis.fingerprint,
                    "reviewer": reviewer,
                },
            )
        )
        db.flush()
        return review


def _validate_review(reviewer: str, justification: str) -> None:
    if not reviewer.strip():
        raise ValueError("reviewer is required.")
    if len(justification.strip()) < MIN_REVIEW_JUSTIFICATION_LENGTH:
        raise ValueError("review justification is too short.")


def _validate_approvable_analysis(
    db: Session,
    tool_id: int,
    fingerprint: str,
    analysis: ToolAnalysis,
    version: ToolObservedVersion,
) -> None:
    from app.models.mcp_tool import MCPTool

    recognized_review_states = {
        STATUS_APPROVED,
        STATUS_ADMIN_ALLOWED,
        STATUS_REVIEW_REQUIRED,
    }
    if (
        analysis.analysis_status not in recognized_review_states
        or analysis.review_status not in recognized_review_states
    ):
        raise ValueError("analysis status cannot be approved.")
    if analysis.completed_at is None:
        raise ValueError("analysis is not complete.")
    if version.fingerprint != fingerprint:
        raise ValueError("observed version fingerprint does not match.")
    if analysis.analyzer_revision != ANALYZER_REVISION:
        raise ValueError("analysis was produced by an outdated analyzer revision.")
    if not reusable_analysis_context_hash(analysis.analysis_context_hash):
        raise ValueError("analysis context hash is missing or invalid.")
    tool = db.get(MCPTool, tool_id)
    if tool is None:
        raise ValueError("tool is missing.")
    if tool.current_fingerprint != fingerprint:
        raise ValueError("fingerprint does not match the current tool version.")
    if (
        not analysis.semantic_scores
        or not analysis.drift_result
        or (not analysis.model_versions)
    ):
        raise ValueError("analysis results are incomplete.")
    require_current_pipeline(analysis)
    if (
        analysis.analysis_status == STATUS_REVIEW_REQUIRED
        and analysis.review_status
        not in {STATUS_REVIEW_REQUIRED, STATUS_APPROVED, STATUS_ADMIN_ALLOWED}
    ):
        raise ValueError("review status is not approvable.")
