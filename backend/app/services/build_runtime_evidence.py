from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.build_security import BuildAssessment, BuildScanRun
from app.models.control_plane import ControlPlaneConfigRevision, ControlPlaneUser
from app.models.mcp_server import MCPServer
from app.schemas.control_plane import (
    BuildSecurityEvidenceReference,
    BuildSecurityGateMode,
)
from app.services.control_plane_config import (
    ControlPlaneConfigError,
    patch_draft_revision,
)
from app.services.published_configuration import validate_config_content
from common.mcp_endpoint import server_ref_for_server


class BuildEvidenceError(ValueError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def evidence_reference_from_scan(
    db: Session,
    *,
    scan_id: str,
) -> BuildSecurityEvidenceReference:
    scan = db.get(BuildScanRun, scan_id)
    if scan is None:
        raise BuildEvidenceError("build_scan_not_found")
    if scan.status not in {"COMPLETED", "FAILED"} or scan.completed_at is None:
        raise BuildEvidenceError("build_scan_not_terminal")
    if scan.linked_server_id is None:
        raise BuildEvidenceError("build_scan_not_inventory_linked")
    if not scan.source_fingerprint:
        raise BuildEvidenceError("build_scan_source_fingerprint_missing")

    server = db.get(MCPServer, scan.linked_server_id)
    if server is None:
        raise BuildEvidenceError("build_scan_server_missing")
    if server.status == "archived":
        raise BuildEvidenceError("build_scan_server_archived")

    assessment = db.scalar(
        select(BuildAssessment).where(BuildAssessment.build_scan_id == scan.id)
    )
    if assessment is None:
        raise BuildEvidenceError("build_scan_assessment_missing")
    if scan.status == "FAILED":
        if assessment.status != "ERROR" or assessment.required_scanners_complete:
            raise BuildEvidenceError("build_scan_terminal_state_inconsistent")
    elif assessment.status == "ERROR" or not assessment.required_scanners_complete:
        raise BuildEvidenceError("build_scan_terminal_state_inconsistent")

    return BuildSecurityEvidenceReference(
        server_ref=server_ref_for_server(
            {
                "endpoint": server.endpoint,
                "transport": server.transport,
            }
        ),
        scan_id=scan.id,
        source_fingerprint=scan.source_fingerprint,
        source_revision=scan.source_revision,
        assessment_status=assessment.status,
        assessment_policy_version=assessment.policy_version,
        required_scanners_complete=assessment.required_scanners_complete,
        completed_at=scan.completed_at,
    )


def attach_scan_evidence_to_draft(
    db: Session,
    *,
    scan_id: str,
    draft_revision_id: str,
    mode: BuildSecurityGateMode,
    max_evidence_age_hours: int,
    actor: ControlPlaneUser,
    change_summary: str,
) -> ControlPlaneConfigRevision:
    draft = db.get(ControlPlaneConfigRevision, draft_revision_id)
    if draft is None:
        raise BuildEvidenceError("revision_not_found")
    if draft.status != "DRAFT":
        raise BuildEvidenceError("build_evidence_requires_draft")

    reference = evidence_reference_from_scan(db, scan_id=scan_id)
    content = validate_config_content(draft.content)
    existing = [
        item
        for item in content.build_security.evidence
        if item.server_ref != reference.server_ref
    ]
    existing.append(reference)
    existing.sort(key=lambda item: item.server_ref)

    next_build_security = content.build_security.model_copy(
        update={
            "mode": mode,
            "max_evidence_age_hours": max_evidence_age_hours,
            "evidence": tuple(existing),
        }
    )
    next_content = content.model_copy(
        update={"build_security": next_build_security}
    )
    try:
        return patch_draft_revision(
            db,
            draft_id=draft.id,
            content=next_content,
            actor=actor,
            change_summary=change_summary,
        )
    except ControlPlaneConfigError as exc:
        raise BuildEvidenceError(str(exc)) from exc
