"""M3 shadow pipeline: provenance-preserving field inventory, no policy authority.

M2 owns derived views. In Lot 2 no M2 decoded view is consumed and no
transform/offset attestation is invented. M5 references are explicit inputs but
not interpreted until Lot 3. V0 remains the only owner of BLOCK/REVIEW.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.services.tda.m1_sources.capture import AnalysisContext
from app.services.tda.m3_instructions.contracts import (
    M3Report, InspectionRow, InstructionSignal, SourceProof, finding_id,
)
from app.services.tda.m3_instructions.surfaces import original_surfaces
from app.services.tda.m3_instructions.detectors import _text_findings
from app.services.tda.m3_instructions.quoted_enactment import _narrow_post_quote_enactment

MAX_RAW_VALUE_FIELDS = 256
MAX_FIELD_CHARS = 16_000
MAX_AGGREGATE_CHARS = 64_000

# These structural findings are M2 observations, not M3 directives.
M2_CATEGORIES = frozenset({"obfuscation", "hidden_text"})


@dataclass(frozen=True)
class M2Input:
    """Explicit M2 handoff. Existing V0 exposes no independently attested decoded views."""
    status: str = "NOT_EXPOSED_IN_V0"
    decoded_views: tuple[Any, ...] = ()
    transforms_verified: bool = False

    def __post_init__(self) -> None:
        if self.decoded_views and not self.transforms_verified:
            # Do not pretend to inspect decoded text without M2 attestation.
            raise ValueError("M3_M2_UNVERIFIED_DERIVED_INPUT")


@dataclass(frozen=True)
class M5Input:
    status: str = "NOT_RESOLVED_IN_V0"
    reference_resolutions: tuple[Any, ...] = ()


def run_m3(context: AnalysisContext, m2: M2Input, m5: M5Input) -> M3Report:
    """Run raw-value-only shadow scan; never update V0 findings or global coverage."""
    if not isinstance(context, AnalysisContext):
        raise ValueError("M3_CONTEXT_REQUIRED")
    if not isinstance(m2, M2Input) or not isinstance(m5, M5Input):
        raise ValueError("M3_EXPLICIT_M2_M5_INPUTS_REQUIRED")

    ledger: list[InspectionRow] = []
    signals: list[InstructionSignal] = []
    directives: list[InstructionSignal] = []
    limitations = [
        "SHADOW_NO_POLICY_AUTHORITY",
        "KEYS_INVENTORIED_NOT_SCANNED",
        "DECODED_VIEWS_NOT_CONSUMED_LOT2",
        "MODEL_NOT_REQUIRED_IN_SHADOW",
        "M5_REFERENCES_NOT_CONSUMED_LOT2",
        "LEGACY_MATCH_OFFSETS_UNAVAILABLE",
    ]
    scanned = 0
    chars_scanned = 0
    for surface in original_surfaces(context):
        if surface.kind == "KEY":
            for detector in ("M3_LEGACY_RAW_LEXICAL", "M3_QUOTE_THEN_ENACT"):
                ledger.append(InspectionRow(
                    pointer=surface.pointer, surface_kind="KEY",
                    view_id=surface.view_id, detector_id=detector,
                    mode="SHADOW", status="NOT_ANALYZED",
                    detail="KEY_RULES_SCHEDULED_FOR_LOT3",
                    value_sha256=surface.text_sha256))
            continue
        reason = ""
        if scanned >= MAX_RAW_VALUE_FIELDS:
            reason = "FIELD_COUNT_BUDGET"
        elif len(surface.text) > MAX_FIELD_CHARS:
            reason = "FIELD_CHAR_BUDGET"
        elif chars_scanned + len(surface.text) > MAX_AGGREGATE_CHARS:
            reason = "AGGREGATE_CHAR_BUDGET"
        if reason:
            for detector in ("M3_LEGACY_RAW_LEXICAL", "M3_QUOTE_THEN_ENACT"):
                ledger.append(InspectionRow(
                    pointer=surface.pointer, surface_kind="VALUE",
                    view_id=surface.view_id, detector_id=detector,
                    mode="SHADOW", status="NOT_ANALYZED",
                    detail=reason, value_sha256=surface.text_sha256))
            if "RAW_BUDGET_INCOMPLETE" not in limitations:
                limitations.append("RAW_BUDGET_INCOMPLETE")
            continue
        scanned += 1
        chars_scanned += len(surface.text)
        candidates = _text_findings(surface.pointer, surface.text)
        ledger.append(InspectionRow(
            pointer=surface.pointer, surface_kind="VALUE",
            view_id=surface.view_id, detector_id="M3_LEGACY_RAW_LEXICAL",
            mode="SHADOW", status="INSPECTED",
            detail="RAW_TEXT_ONLY_NO_EXACT_MATCH_OFFSETS",
            value_sha256=surface.text_sha256))
        ledger.append(InspectionRow(
            pointer=surface.pointer, surface_kind="VALUE",
            view_id=surface.view_id, detector_id="M3_QUOTE_THEN_ENACT",
            mode="SHADOW", status="INSPECTED",
            detail="RAW_SOURCE_OFFSETS_VERIFIED_ON_HIT",
            value_sha256=surface.text_sha256))
        # Reuse the *existing* narrow quote/enactment guard on one original
        # value at a time, so its offsets can be verified against M1.
        for concern in _narrow_post_quote_enactment({"description": surface.text}):
            enacted = next(
                (e for e in concern["evidence"]
                 if e.get("role") == "INSTRUCTION_TO_ENACT_QUOTE"), None
            )
            if enacted is None:
                continue
            proof = SourceProof(
                kind="VALUE", view_id=surface.view_id,
                source_digest=surface.source_digest, pointer=surface.pointer,
                start=enacted["start"], end=enacted["end"],
                excerpt=enacted["excerpt"],
            )
            proof.verify(context)
            directives.append(InstructionSignal(
                finding_id=finding_id(
                    concern["code"], surface.pointer, proof.start,
                    proof.end, surface.view_id,
                ),
                rule_id=concern["code"], pointer=surface.pointer,
                view_id=surface.view_id, support="LINGUISTICALLY_SUPPORTED",
                addressee="AGENT", activation_context="AFTER_QUOTED_TEXT",
                framing="INSTRUCTION", scope="SOURCE_METADATA",
                source_proof=proof,
                detail="SHADOW_QUOTE_ENACTMENT_CONTEXT_NOT_PROOF_OF_EXECUTION",
            ))
        for finding in candidates:
            if finding.category in M2_CATEGORIES:
                continue
            # Older lexical rule reports are not exact span proofs. We do NOT
            # promote them to ESTABLISHED_DIRECTIVE or mechanical evidence.
            signals.append(InstructionSignal(
                finding_id=finding_id(finding.code, surface.pointer, None, None,
                                      surface.view_id),
                rule_id=finding.code, pointer=surface.pointer,
                view_id=surface.view_id, support="UNRESOLVED",
                detail="SHADOW_LEXICAL_CANDIDATE_EXACT_OFFSETS_UNKNOWN",
            ))

    # Unique source-path/rule occurrence, without the legacy global dedupe
    # key (code, source, summary), which can hide distinct JSON locations.
    distinct = dict((s.finding_id, s) for s in signals)
    return M3Report(
        context_id=context.context_id,
        source_sha256=context.original.sha256,
        rows=tuple(ledger),
        directives=tuple({s.finding_id:s for s in directives}.values()),
        raw_signals=tuple(distinct.values()),
        limitations=tuple(limitations),
    )
