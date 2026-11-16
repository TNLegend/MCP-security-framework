"""M3-owned explicit instruction/authority findings, preserving V0 semantics.

These are the exact historical REVIEW candidates previously orchestrated by
M7.cross_checks. M7 consumes the results and retains corroboration ownership;
M3 does not import M4 and never authorizes a tool.
"""
from __future__ import annotations
from typing import Any

from app.services.tda.claim_context import metadata_texts, poisoning_signals
from app.services.tda.configuration import FINDING_DECISION_REVIEW
from app.services.tda.findings import _finding
from app.services.tda.m3_instructions.authority_relation import extract_priority_relations
from app.services.tda.m3_instructions.quoted_enactment import (
    instruction_concerns, _narrow_post_quote_enactment,
)
from app.services.tda.security_guards.propositions import extract_propositions
from app.services.tda.types import AnalysisFinding


def explicit_instruction_review(snapshot: dict) -> list[dict]:
    """Concealed agent actions and quote-then-enact, never permissions."""
    trusted = [
        c
        for c in instruction_concerns(extract_propositions(snapshot))
        if c["code"] in {"agent_conceals_action", "agent_enacts_quoted_instruction"}
    ]
    return trusted + _narrow_post_quote_enactment(snapshot)


def legacy_instruction_review_findings(
    snapshot: dict[str, Any]
) -> list[AnalysisFinding]:
    """Preserve exactly the historical V0 M3 contribution/order."""
    findings: list[AnalysisFinding] = []
    for relation in extract_priority_relations(snapshot)["relations"]:
        first = relation["evidence"][0]
        finding = _finding(
            "agent_instruction_priority_spoof",
            "prompt_injection",
            first["source_path"],
            "high",
            90,
            "Tool metadata claims its instructions outrank earlier instructions for the agent.",
            "Reject instructions promoting untrusted tool messages above prior trusted instructions.",
            decision=FINDING_DECISION_REVIEW,
        )
        finding.evidence["instruction_authority_relation"] = {
            "addressee": relation["addressee"],
            "promoted_source": relation["promoted_source"],
            "displaced_source": relation["displaced_source"],
            "operator": relation["operator"],
            "evidence": relation["evidence"],
            "creates_permissions": False,
        }
        findings.append(finding)
    for concern in explicit_instruction_review(snapshot):
        detail = concern["evidence"][0]
        instruction_finding = _finding(
            "agent_directed_unreviewed_action",
            "prompt_injection",
            detail["source_path"],
            "high",
            90,
            concern["claim"],
            "Review caller-directed concealed actions and enacted quotations independently of tool permissions.",
            decision=FINDING_DECISION_REVIEW,
        )
        instruction_finding.evidence.update(
            reason=concern["code"], spans=concern["evidence"]
        )
        findings.append(instruction_finding)
    poisoning = [
        (path, signal)
        for path, value in metadata_texts(snapshot)
        for signal in poisoning_signals(value)
    ]
    if poisoning:
        findings.append(
            _finding(
                "agent_directed_hidden_transfer",
                "prompt_injection",
                poisoning[0][0],
                "high",
                92,
                "Metadata directs the agent to collect and transfer content while concealing the action.",
                "Remove agent-directed hidden actions; require explicit reviewed tool behavior.",
                decision=FINDING_DECISION_REVIEW,
            )
        )
    return findings
