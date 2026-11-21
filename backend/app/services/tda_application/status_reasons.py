"""Enumerated, authoritative causes for a restricted (QUARANTINED) tool. TA-01.

Each code is produced by the exact condition that caused the restriction; no
free text and no remote data is stored. The GUI renders `label` and
`next_action` from this catalog through the API, never by guessing.
"""
from __future__ import annotations

QUARANTINE_REASONS: dict[str, dict[str, str]] = {
    "NO_APPROVED_BASELINE": {
        "label": "This tool has never been approved.",
        "next_action": "Review the tool analysis and record an explicit decision.",
    },
    "FINGERPRINT_CHANGED": {
        "label": "The tool definition changed since its approval.",
        "next_action": "Compare the change in the analysis, then review the new definition.",
    },
    "APPROVED_CONTEXT_CHANGED": {
        "label": "The approved security profile or contract context changed.",
        "next_action": "Re-run the analysis with the current profile and review it.",
    },
    "ANALYSIS_OBSOLETE": {
        "label": "The approval was produced by a previous analyzer or model version.",
        "next_action": "Re-run the analysis with the current analyzer and review the result.",
    },
    "APPROVAL_EVIDENCE_MISSING": {
        "label": "The frozen evidence of the approval is missing.",
        "next_action": "Re-run the analysis and record a new review; the old approval cannot be reused.",
    },
    "PROTOCOL_OBSERVATION_NOT_APPROVED": {
        "label": "This protocol profile observation of the tool is not approved.",
        "next_action": "Approve the observation for this upstream protocol profile in the contract workflow.",
    },
    "APPROVED_PROFILE_MISSING": {
        "label": "No approved security profile (contract) exists for this tool.",
        "next_action": "Create and approve the tool security contract, then publish it.",
    },
    "CONTRACT_PENDING_PUBLICATION": {
        "label": "The tool contract is a draft awaiting signed publication.",
        "next_action": "Validate and publish the signed security configuration revision.",
    },
    "DISCOVERY_STAGED_REQUIRES_REVIEW": {
        "label": "A newly discovered version is staged and needs an explicit review.",
        "next_action": "Open the staged analysis and record an explicit review decision.",
    },
    "NEWLY_DISCOVERED_NOT_ANALYZED": {
        "label": "The tool was discovered but not yet analyzed.",
        "next_action": "Run the tool analysis.",
    },
}


def reason_for(status: str | None, reason: str | None) -> str | None:
    """Keep a reason only for a restricted status, and only a known code."""
    if status != "QUARANTINED":
        return None
    return reason if reason in QUARANTINE_REASONS else None


def describe(reason: str | None) -> dict[str, str] | None:
    if reason not in QUARANTINE_REASONS:
        return None
    return {"code": reason, **QUARANTINE_REASONS[reason]}
