"""M3 internal shadow report contract (Lot 2).

A finding from legacy lexical rules is not automatically an established directive:
legacy AnalysisFinding carries no exact match offsets. This report cannot authorize
calls, lower existing BLOCK decisions, or claim decoded-source attestation.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
from typing import Literal

from app.services.tda.m1_sources.capture import AnalysisContext
from app.services.tda.m1_sources.contracts import Evidence

Mode = Literal["SHADOW", "ADVISORY", "REQUIRED"]
Support = Literal["MECHANICAL_VERIFIED", "LINGUISTICALLY_SUPPORTED", "MODEL_HYPOTHESIS", "UNRESOLVED"]
LedgerStatus = Literal["INSPECTED", "NOT_ANALYZED", "NOT_APPLICABLE", "ERROR"]


def _pointer_get(root: object, pointer: str) -> object:
    """Strict RFC6901 traversal; reject invalid indices and escape sequences."""
    import re
    if pointer == "":
        return root
    if not isinstance(pointer, str) or not pointer.startswith("/"):
        raise ValueError("M3_INVALID_POINTER")
    current = root
    for raw in pointer[1:].split("/"):
        if re.search(r"~(?![01])", raw):
            raise ValueError("M3_INVALID_POINTER_ESCAPE")
        key = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(current, list):
            if not re.fullmatch(r"0|[1-9][0-9]*", key):
                raise ValueError("M3_INVALID_LIST_INDEX")
            current = current[int(key)]
        elif isinstance(current, dict):
            current = current[key]
        else:
            raise ValueError("M3_POINTER_NOT_CONTAINER")
    return current


@dataclass(frozen=True)
class SourceProof:
    """Source-bound proof: TOKEN anchors original raw span, not derived match offsets."""
    kind: Literal["VALUE", "KEY"]
    view_id: str
    source_digest: str
    pointer: str
    start: int
    end: int
    excerpt: str
    key: str | None = None
    offset_precision: Literal["EXACT", "TOKEN"] = "EXACT"

    def verify(self, context: AnalysisContext) -> bool:
        if not isinstance(context, AnalysisContext):
            raise ValueError("M3_CONTEXT_REQUIRED")
        if (self.view_id != context.original.view_id
                or self.source_digest != context.original.sha256):
            raise ValueError("M3_SOURCE_MISMATCH")
        if (type(self.start) is not int or type(self.end) is not int
                or self.offset_precision not in ("EXACT", "TOKEN")):
            raise ValueError("M3_UNVERIFIED_OFFSETS")
        if self.kind == "VALUE":
            if self.key is not None:
                raise ValueError("M3_VALUE_KEY_UNEXPECTED")
            return Evidence(self.view_id, self.source_digest, self.pointer,
                            self.start, self.end, self.excerpt).verify(context.original)
        if self.kind != "KEY" or not isinstance(self.key, str):
            raise ValueError("M3_INVALID_KEY_PROOF")
        target = _pointer_get(json.loads(context.original.json_bytes), self.pointer)
        if not isinstance(target, dict) or self.key not in target:
            raise ValueError("M3_KEY_NOT_FOUND")
        if not 0 <= self.start <= self.end <= len(self.key):
            raise ValueError("M3_KEY_OFFSETS_INVALID")
        if self.key[self.start:self.end] != self.excerpt:
            raise ValueError("M3_KEY_EXCERPT_MISMATCH")
        return True


@dataclass(frozen=True)
class InspectionRow:
    pointer: str
    surface_kind: Literal["VALUE", "KEY"]
    view_id: str
    detector_id: str
    mode: Mode
    status: LedgerStatus
    detail: str = ""
    value_sha256: str = ""
    # A decoded view is never marked INSPECTED on an unverified transform.
    transform_attested_by_m2: bool = False

    def __post_init__(self):
        if self.mode not in ("SHADOW", "ADVISORY", "REQUIRED"):
            raise ValueError("M3_INVALID_MODE")
        if self.status not in ("INSPECTED", "NOT_ANALYZED", "NOT_APPLICABLE", "ERROR"):
            raise ValueError("M3_INVALID_STATUS")
        if not self.detector_id or not self.view_id:
            raise ValueError("M3_LEDGER_ID_REQUIRED")


@dataclass(frozen=True)
class InstructionSignal:
    finding_id: str
    rule_id: str
    pointer: str
    view_id: str
    support: Support
    claimed_authority: str = "UNRESOLVED"
    addressee: str = "UNRESOLVED"
    activation_context: str = "UNRESOLVED"
    framing: str = "UNRESOLVED"
    scope: str = "UNRESOLVED"
    source_proof: SourceProof | None = None
    detail: str = "LEGACY_RULE_WITHOUT_EXACT_MATCH_OFFSETS"

    def __post_init__(self):
        if self.support not in ("MECHANICAL_VERIFIED", "LINGUISTICALLY_SUPPORTED",
                                "MODEL_HYPOTHESIS", "UNRESOLVED"):
            raise ValueError("M3_INVALID_SUPPORT")
        if self.support == "MECHANICAL_VERIFIED" and self.source_proof is None:
            raise ValueError("M3_MECHANICAL_PROOF_REQUIRED")


@dataclass(frozen=True)
class M3Report:
    context_id: str
    source_sha256: str
    rows: tuple[InspectionRow, ...] = ()
    directives: tuple[InstructionSignal, ...] = ()
    raw_signals: tuple[InstructionSignal, ...] = ()
    limitations: tuple[str, ...] = ()
    mode: Literal["SHADOW"] = "SHADOW"
    authority: Literal["AT_MOST_REVIEW_ADVISORY"] = "AT_MOST_REVIEW_ADVISORY"
    version: Literal["m3-report-lot2-v1", "m3-report-lot3-v1"] = "m3-report-lot2-v1"
    # Not authoritative: shadow ledger does not change global coverage.
    coverage_complete: bool | None = None

    def __post_init__(self):
        if self.mode != "SHADOW" or self.authority != "AT_MOST_REVIEW_ADVISORY":
            raise ValueError("M3_REPORT_CANNOT_GRANT_AUTHORITY")
        if self.coverage_complete is not None:
            raise ValueError("M3_SHADOW_COVERAGE_MUST_REMAIN_UNASSESSED")

    def to_dict(self) -> dict:
        inspected=sum(r.status=="INSPECTED" for r in self.rows)
        omitted=sum(r.status=="NOT_ANALYZED" for r in self.rows)
        errors=sum(r.status=="ERROR" for r in self.rows)
        applicable=sum(r.status!="NOT_APPLICABLE" for r in self.rows)
        return {
            "schema": self.version, "mode": self.mode, "authority": self.authority,
            "context_id": self.context_id, "source_sha256": self.source_sha256,
            "directives": [asdict(s) for s in self.directives],
            "raw_signals": [asdict(s) for s in self.raw_signals],
            "ledger": [asdict(row) for row in self.rows],
            "coverage": {
                "complete": None, "status": "SHADOW_NOT_ASSESSED",
                "required_incomplete": False,
                "technical_complete_in_shadow": (omitted==0 and errors==0 and applicable>0),
                "inspected_rows": inspected, "omitted_rows": omitted,
                "error_rows": errors, "applicable_rows": applicable,
                "note": "Shadow inspection accounting only; not production approval or enforced REQUIRED coverage",
            },
            "limitations": list(self.limitations),
            "security_decision_changes": "NONE",
            "creates_permissions": False,
        }


def finding_id(rule_id: str, pointer: str, start: int | None,
               end: int | None, view_id: str) -> str:
    blob = json.dumps([rule_id, pointer, start, end, view_id],
                      ensure_ascii=False, separators=(",", ":")).encode("utf8")
    return sha256(blob).hexdigest()[:12]


def shadow_error(context: AnalysisContext, reason: str) -> M3Report:
    """Record non-authoritative failure; do not convert it into a clean result."""
    return M3Report(
        context_id=context.context_id, source_sha256=context.original.sha256,
        rows=(InspectionRow(pointer="", surface_kind="VALUE",
              view_id=context.original.view_id, detector_id="M3_SHADOW_PIPELINE",
              mode="SHADOW", status="ERROR", detail=reason),),
        limitations=("SHADOW_PIPELINE_ERROR", reason),
    )
