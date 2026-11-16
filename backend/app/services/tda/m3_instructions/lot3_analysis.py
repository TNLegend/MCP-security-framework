"""Lot 3 M3 exact-span and M2-derived observations, never BLOCK authority.

This is a source-bound adjunct to the already-validated Lot 2 shadow scan.
Legacy original rule decisions are preserved by the engine's V0 path. Every
derived match is interpreted as a linguistic candidate, not an established
agent instruction. A mechanically attested M2 conversion is only provenance.
"""
from __future__ import annotations

from dataclasses import replace
import re

from app.services.tda.m1_sources.capture import AnalysisContext
from app.services.tda.m2_structure.views import AttestedView
from app.services.tda.m3_instructions.contracts import (
    M3Report, InspectionRow, InstructionSignal, SourceProof, finding_id,
)
from app.services.tda.m3_instructions.span_rules import exact_directive_candidates
from app.services.tda.m3_instructions.response_manipulation import response_directive_candidates
from app.services.tda.m3_instructions.language_scope import language_scope
from app.services.tda.m3_instructions.surfaces import original_surfaces

def apply_lot3_shadow(context: AnalysisContext, baseline: M3Report,
                      *, derived_views: tuple[AttestedView,...],
                      m2_limitations: tuple[str,...]) -> M3Report:
    if baseline.context_id != context.context_id:
        raise ValueError("M3_LOT3_SOURCE_CONTEXT_MISMATCH")
    # In Lot 3 the new exact rule checks KEYS explicitly. Old value-only
    # detectors remain not applicable to KEYs, not coverage omissions.
    new_rows=[
        replace(r,status="NOT_APPLICABLE",
                detail="KEY_SCANNED_SEPARATELY_BY_EXACT_SOURCE_RULES")
        if r.surface_kind=="KEY" and r.status=="NOT_ANALYZED"
           and r.detector_id in ("M3_LEGACY_RAW_LEXICAL","M3_QUOTE_THEN_ENACT")
        else r for r in baseline.rows
    ]
    new_signals=[]
    new_directives=[]
    surfaces=original_surfaces(context)
    original_text_by_pointer={(s.pointer,s.kind):s.text for s in surfaces}
    # Independent expected-inspection plan. Construct from the M1 surface
    # inventory and *M2 attested view inventory* before any detector runs.
    expected=[]
    for s in surfaces:
        for detector_id in (
            "M3_LEGACY_RAW_LEXICAL","M3_QUOTE_THEN_ENACT",
            "M3_EXACT_SOURCE_DIRECTIVES","M3_RESPONSE_RELATIONS",
            "M3_LANGUAGE_SCOPE",
        ):
            expected.append((s.pointer,s.kind,s.view_id,detector_id))
    for v in derived_views:
        for detector_id in ("M3_DERIVED_DIRECTIVES","M3_DERIVED_RESPONSE_RELATIONS"):
            expected.append((v.pointer,v.source_kind,v.view_id,detector_id))
    limitations=[
        "M5_REFERENCES_NOT_RESOLVED" if x=="M5_REFERENCES_NOT_CONSUMED_LOT2" else x
        for x in baseline.limitations
        if x not in ("KEYS_INVENTORIED_NOT_SCANNED",
                     "DECODED_VIEWS_NOT_CONSUMED_LOT2")
    ]
    if derived_views:
        limitations.append("DERIVED_FINDINGS_ARE_NOT_AUTHORITY")
    if m2_limitations:
        limitations.extend(m2_limitations)
    # Language scope is independent of maliciousness and is declared for
    # *every* applicable raw VALUE, including languages written in Latin.
    # Latin-only text is never certified English by this lightweight check.
    for surface in surfaces:
        if surface.kind=="VALUE":
            scope=language_scope(surface.text)
            unsupported=scope!="ENGLISH_FIRST_NO_LANGUAGE_ID"
            if unsupported and "LANGUAGE_COVERAGE_UNVERIFIED_NOT_MALICIOUS" not in limitations:
                limitations.append("LANGUAGE_COVERAGE_UNVERIFIED_NOT_MALICIOUS")
            new_rows.append(InspectionRow(
                surface.pointer,surface.kind,surface.view_id,
                "M3_LANGUAGE_SCOPE","SHADOW",
                "NOT_ANALYZED" if unsupported else "INSPECTED",
                scope,surface.text_sha256))
        else:
            new_rows.append(InspectionRow(
                surface.pointer,surface.kind,surface.view_id,
                "M3_LANGUAGE_SCOPE","SHADOW","NOT_APPLICABLE",
                "SCHEMA_KEYS_ARE_NOT_LANGUAGE_IDENTIFICATION",
                surface.text_sha256))

    scanned_count=0
    chars=0
    for surface in surfaces:
        reason=""
        if scanned_count>=256:
            reason="M3_SPAN_FIELD_BUDGET"
        elif len(surface.text)>16_000:
            reason="M3_SPAN_CHAR_BUDGET"
        elif chars+len(surface.text)>64_000:
            reason="M3_SPAN_AGGREGATE_BUDGET"
        detector="M3_EXACT_SOURCE_DIRECTIVES"
        if reason:
            new_rows.append(InspectionRow(
                surface.pointer,surface.kind,surface.view_id,detector,
                "SHADOW","NOT_ANALYZED",reason,surface.text_sha256))
            if "M3_SPAN_COVERAGE_INCOMPLETE" not in limitations:
                limitations.append("M3_SPAN_COVERAGE_INCOMPLETE")
            continue
        scanned_count+=1
        chars+=len(surface.text)
        for hit in exact_directive_candidates(surface.text,key=surface.kind=="KEY"):
            proof=SourceProof(
                kind=surface.kind,view_id=surface.view_id,
                source_digest=surface.source_digest,
                pointer=surface.parent_pointer if surface.kind=="KEY" else surface.pointer,
                key=surface.key if surface.kind=="KEY" else None,
                start=hit.start,end=hit.end,excerpt=hit.excerpt,
            )
            proof.verify(context)
            new_signals.append(InstructionSignal(
                finding_id=finding_id(hit.rule_id,surface.pointer,
                                      hit.start,hit.end,surface.view_id),
                rule_id=hit.rule_id,pointer=surface.pointer,
                view_id=surface.view_id,support="LINGUISTICALLY_SUPPORTED",
                claimed_authority="UNRESOLVED",
                addressee=hit.addressee,
                activation_context="UNRESOLVED",
                framing=hit.framing,scope="RAW_ORIGINAL",
                source_proof=proof,
                detail="ORIGINAL_SOURCE_MATCH_WITH_CONTEXT_CHECK_NO_PERMISSION",
            ))
        new_rows.append(InspectionRow(
            surface.pointer,surface.kind,surface.view_id,detector,
            "SHADOW","INSPECTED","ORIGINAL_EXACT_MATCH_OFFSETS",
            surface.text_sha256))
        # Proposition-aware response redirection. Never interpret a schema
        # key as a user-facing action or grant authorization from its wording.
        if surface.kind=="VALUE":
            for candidate in response_directive_candidates(surface.text):
                hit=candidate.span
                proof=SourceProof(
                    kind="VALUE",view_id=surface.view_id,
                    source_digest=surface.source_digest,
                    pointer=surface.pointer,
                    start=hit.start,end=hit.end,excerpt=hit.excerpt)
                proof.verify(context)
                new_directives.append(InstructionSignal(
                    finding_id=finding_id(hit.rule_id,surface.pointer,
                                          hit.start,hit.end,surface.view_id),
                    rule_id=hit.rule_id,pointer=surface.pointer,
                    view_id=surface.view_id,
                    support="LINGUISTICALLY_SUPPORTED",
                    addressee=hit.addressee,
                    claimed_authority="UNRESOLVED",
                    activation_context="UNRESOLVED",
                    framing=hit.framing,scope="RAW_ORIGINAL",
                    source_proof=proof,
                    detail="SHADOW_SOURCE_BOUND_RELATIONAL_RESPONSE_DIRECTIVE",
                    proposition_id=candidate.proposition_id,
                    requested_action=candidate.action,
                    target=candidate.target,
                    uncertainty_reasons=candidate.uncertainty_reasons,
                ))
            new_rows.append(InspectionRow(
                surface.pointer,surface.kind,surface.view_id,
                "M3_RESPONSE_RELATIONS","SHADOW","INSPECTED",
                "PROPOSITION_ANCHORED_SOURCE_OFFSETS",
                surface.text_sha256))
        else:
            new_rows.append(InspectionRow(
                surface.pointer,surface.kind,surface.view_id,
                "M3_RESPONSE_RELATIONS","SHADOW","NOT_APPLICABLE",
                "RESPONSE_REWRITE_ON_SCHEMA_KEY_NOT_APPLICABLE",
                surface.text_sha256))

    for view in derived_views:
        if not isinstance(view,AttestedView) or not view.verify(context):
            raise ValueError("M3_DERIVED_VIEW_NOT_M2_ATTESTED")
        if len(view.derived_text)>16_000:
            for detector_id in ("M3_DERIVED_DIRECTIVES","M3_DERIVED_RESPONSE_RELATIONS"):
                new_rows.append(InspectionRow(
                    view.pointer,view.source_kind,view.view_id,
                    detector_id,"SHADOW","NOT_ANALYZED",
                    "DERIVED_CHAR_BUDGET",view.source_digest,True))
            limitations.append("M3_DERIVED_VIEW_BUDGET")
            continue
        matches=exact_directive_candidates(
            view.derived_text,key=view.source_kind=="KEY")
        # The raw source can explicitly quote/negate a dangerous decoded
        # example. M2 attesting a transform does not erase that framing.
        raw=original_text_by_pointer.get((view.pointer,view.source_kind),"")
        preceding=raw[max(0,view.start-200):view.start]
        after=raw[view.end:min(len(raw),view.end+120)]
        protective=bool(re.search(
            r"\b(?:never\s+(?:execute|obey|follow)|do\s+not\s+(?:execute|obey|follow)"
            r"|display\s+(?:it\s+)?only|do\s+not\s+run|security\s+example)\b",
            preceding+" "+after,re.I))
        enacted=bool(re.search(
            r"\b(?:then|now)\s+(?:execute|follow|obey|run)\b",
            preceding+" "+after,re.I))
        if protective and not enacted:
            matches=()
        for hit in matches:
            # The proof attests the ORIGINAL enclosing encoded/normalized
            # span. Derived offsets below are NOT ORIGINAL character offsets.
            original=SourceProof(
                kind=view.source_kind,
                pointer=view.parent_pointer if view.source_kind=="KEY" else view.pointer,
                key=view.key if view.source_kind=="KEY" else None,
                view_id=view.source_view_id,source_digest=view.source_digest,
                start=view.start,end=view.end,excerpt=view.original_excerpt,
                offset_precision="TOKEN",
            )
            original.verify(context)
            new_signals.append(InstructionSignal(
                finding_id=finding_id(hit.rule_id,view.pointer,
                                      view.start,view.end,view.view_id)
                           +":"+str(hit.start)+":"+str(hit.end),
                rule_id=hit.rule_id,pointer=view.pointer,
                view_id=view.view_id,support="LINGUISTICALLY_SUPPORTED",
                claimed_authority="UNRESOLVED",addressee=hit.addressee,
                activation_context="UNRESOLVED",
                framing=hit.framing,scope="DERIVED_M2_ATTESTED",
                source_proof=original,
                detail=("M2_"+view.transform+
                        "_SOURCE_TOKEN_ATTESTED_DERIVED_OFFSETS_ONLY_"
                        +str(hit.start)+"_"+str(hit.end)),
            ))
        new_rows.append(InspectionRow(
            view.pointer,view.source_kind,view.view_id,
            "M3_DERIVED_DIRECTIVES","SHADOW","INSPECTED",
            ("M2_ATTESTED_PROTECTIVE_SOURCE_NO_DIRECTIVE" if protective and not enacted else
             "M2_ATTESTED_TOKEN_ORIGIN_NOT_DERIVED_CHARACTER_OFFSETS"),
            view.source_digest,True))
        # Explicitly consume the same M2-attested derived scope for
        # response manipulation; proofs remain enclosing ORIGINAL TOKEN
        # spans, never fake exact offsets in decoded text.
        if view.source_kind=="VALUE":
            response_candidates=() if protective and not enacted else (
                response_directive_candidates(view.derived_text))
            for response in response_candidates:
                hit=response.span
                proof=SourceProof(
                    kind="VALUE",pointer=view.pointer,
                    view_id=view.source_view_id,source_digest=view.source_digest,
                    start=view.start,end=view.end,excerpt=view.original_excerpt,
                    offset_precision="TOKEN")
                proof.verify(context)
                new_directives.append(InstructionSignal(
                    finding_id=finding_id(hit.rule_id,view.pointer,
                                          view.start,view.end,view.view_id)
                               +":r"+str(hit.start)+":"+str(hit.end),
                    rule_id=hit.rule_id,pointer=view.pointer,
                    view_id=view.view_id,
                    support="LINGUISTICALLY_SUPPORTED",
                    addressee=hit.addressee,
                    framing=hit.framing,scope="DERIVED_M2_ATTESTED",
                    source_proof=proof,
                    detail="M2_ATTESTED_SOURCE_TOKEN_DERIVED_RESPONSE_RELATION",
                    proposition_id=response.proposition_id,
                    requested_action=response.action,target=response.target,
                    uncertainty_reasons=response.uncertainty_reasons,
                ))
            new_rows.append(InspectionRow(
                view.pointer,view.source_kind,view.view_id,
                "M3_DERIVED_RESPONSE_RELATIONS","SHADOW","INSPECTED",
                "SOURCE_TOKEN_VERIFIED_DERIVED_MATCH_OFFSETS_NOT_RAW",
                view.source_digest,True))
        else:
            new_rows.append(InspectionRow(
                view.pointer,view.source_kind,view.view_id,
                "M3_DERIVED_RESPONSE_RELATIONS","SHADOW","NOT_APPLICABLE",
                "SCHEMA_KEY_IS_NOT_OUTPUT_INSTRUCTION_TARGET",
                view.source_digest,True))
    # Preserve the Lot 2 signals and never claim raw lexical match offsets.
    unique={s.finding_id:s for s in (*baseline.raw_signals,*new_signals)}
    distinct_directives={s.finding_id:s for s in (*baseline.directives,*new_directives)}
    return replace(baseline,version="m3-report-prelot5-v1",rows=tuple(new_rows),
                   expected_inspections=tuple(expected),
                   directives=tuple(distinct_directives.values()),
                   raw_signals=tuple(unique.values()),
                   limitations=tuple(dict.fromkeys(limitations)))
