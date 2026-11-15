"""Bounded linguistic reference candidates for development experiments only.

No production caller, contract, policy, authorization or model is consulted.
The original extraction is retained verbatim. A nominal candidate is not actual
data provenance; possessive pronouns deliberately remain unresolved.
"""

from __future__ import annotations
from app.services.tda.security_guards.propositions import Budgets, extract_propositions
import re
from dataclasses import dataclass
from typing import Any

REVISION = "reference-shadow-explicit-nominal-v1"
_FRAME = re.compile("^(?P<frame>the tool|this tool|the agent must|you must)\\s+", re.I)
_COORDINATOR = re.compile("^(?:and|then|but)\\s+", re.I)
_READ = re.compile("^(?:reads?|retrieves?|fetch(?:es)?)\\s+", re.I)
_CONSUMER = re.compile("^(?:returns?|sends?|attaches?|includes?|appends?)\\s+", re.I)
_NEGATIVE = re.compile("\\b(?:not|never|cannot)\\b", re.I)
_NEGATIVE_PREFIX = re.compile("^(?:does not|do not|must not|never|not)\\s+", re.I)
_CONDITIONAL = re.compile(
    "\\b(?:if|unless|when|until|before|after|while|provided|without)\\b", re.I
)
_REF = re.compile(
    "\\b(?:that(?:\\s+same)?|this\\s+same)\\s+|\\b(?:its|their|it|son|sa|ses|su|sus)\\b",
    re.I,
)
_WORD = re.compile("[^\\W\\d_]+(?:[-’'][^\\W\\d_]+)*", re.UNICODE)
_STOP = frozenset(
    "to from of with which who whose that where if unless when until before after while provided without and but then the a an another it its their this those these".split()
)
_SENTENCE = re.compile("[.!?;\\n]")


@dataclass(frozen=True)
class ReferenceLimits:
    references: int = 128
    candidates: int = 64

    def __post_init__(self):
        if not (0 < self.references <= 512 and 0 < self.candidates <= 512):
            raise ValueError("reference_limits_must_be_positive_and_at_most_512")


def _resolve(snapshot, pointer):
    value = snapshot
    for part in pointer.lstrip("/").split("/") if pointer else ():
        key = part.replace("~1", "/").replace("~0", "~")
        value = value[int(key)] if isinstance(value, list) else value[key]
    return value


def _evidence(path, raw, start, end):
    return {
        "source_path": path,
        "start": start,
        "end": end,
        "excerpt": raw[start:end],
        "trust": "UNTRUSTED_METADATA",
    }


def _simple_name(text):
    if not re.fullmatch(f"{_WORD.pattern}(?:\\s+{_WORD.pattern}){{0,5}}", text):
        return None
    words = text.casefold().split()
    if any((word in _STOP for word in words)):
        return None
    return " ".join(words)


def _nominal_operand(text):
    match = re.fullmatch("(?:the|a|an|another)\\s+(.+)", text, re.I)
    return (match, _simple_name(match[1])) if match else (None, None)


def _references(path, raw, proposition):
    """Find reference spans, without claiming comprehensive reference recall."""
    for match in _REF.finditer(raw, proposition["start"], proposition["end"]):
        token = match.group().strip().casefold()
        if token in {"its", "their", "it", "son", "sa", "ses", "su", "sus"}:
            yield (_evidence(path, raw, match.start(), match.end()), None, token)
            continue
        cursor = match.end()
        words = []
        for word in _WORD.finditer(raw, cursor, proposition["end"]):
            if raw[cursor : word.start()].strip() or word.group().casefold() in _STOP:
                break
            words.append(word)
            cursor = word.end()
            if len(words) > 6:
                break
        end = words[-1].end() if words else match.end()
        name = _simple_name(raw[match.end() : end]) if words else None
        yield (_evidence(path, raw, match.start(), end), name, "EXPLICIT_NOMINAL")


def _consumer_supported(body, body_start, reference):
    predicate = _CONSUMER.match(body)
    if not predicate:
        return False
    before = body[predicate.end() : reference["start"] - body_start].strip()
    if before:
        if not before.casefold().endswith(" of"):
            return False
        _, name = _nominal_operand(before[:-3].strip())
        if name is None:
            return False
    after = body[reference["end"] - body_start :].strip().rstrip(".!?;").strip()
    return not after or bool(re.fullmatch("to\\s+[^,;.!?]+", after, re.I))


class ReferenceShadowEngine:
    revision = REVISION

    def __init__(
        self, budgets: Budgets | None = None, limits: ReferenceLimits | None = None
    ):
        self.budgets = budgets
        self.limits = limits or ReferenceLimits()

    def extract(self, snapshot: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(snapshot, dict):
            raise TypeError("tool_snapshot_must_be_an_object")
        extraction = extract_propositions(snapshot, self.budgets)
        references = []
        omissions = list(extraction["omissions"])
        grouped = {}
        for p in extraction["propositions"]:
            grouped.setdefault(p["source_path"], []).append(p)
        for path, props in grouped.items():
            raw = _resolve(snapshot, path)
            actor = "UNKNOWN"
            actor_evidence = None
            candidates = []
            barrier = None
            scope_start = 0
            previous_end = 0
            for p in props:
                gap = raw[previous_end : p["start"]]
                if _SENTENCE.search(gap):
                    actor = "UNKNOWN"
                    actor_evidence = None
                    candidates = []
                    barrier = None
                    scope_start = p["start"]
                previous_end = p["end"]
                text = p["excerpt"]
                offset = p["start"]
                coordinator = _COORDINATOR.match(text)
                if coordinator:
                    offset += coordinator.end()
                    text = text[coordinator.end() :]
                frame = _FRAME.match(text)
                if frame:
                    new_actor = (
                        "AGENT"
                        if re.search("agent|you", frame["frame"], re.I)
                        else "TOOL"
                    )
                    if actor != "UNKNOWN" and new_actor != actor:
                        barrier = "actor_scope_changed"
                    actor = new_actor
                    actor_evidence = _evidence(path, raw, offset, offset + frame.end())
                    offset += frame.end()
                    text = text[frame.end() :]
                scoped = raw[scope_start : p["end"]]
                conditional = bool(_CONDITIONAL.search(scoped))
                negative = bool(_NEGATIVE.search(text))
                if p["quotation"]:
                    barrier = "quoted_scope"
                elif conditional:
                    barrier = "conditional_scope"
                elif negative:
                    barrier = "nonpositive_scope"
                positive_body = _NEGATIVE_PREFIX.sub("", text)
                source = _READ.match(positive_body)
                if source and (not p["quotation"]):
                    operand = (
                        positive_body[source.end() :].strip().rstrip(".!?;").strip()
                    )
                    nominal, name = _nominal_operand(operand)
                    if name:
                        if len(candidates) >= self.limits.candidates:
                            omissions.append(
                                {
                                    "source_path": path,
                                    "reason": "reference_candidate_budget",
                                }
                            )
                        else:
                            local = text.find(
                                nominal[1],
                                len(text) - len(positive_body) + source.end(),
                            )
                            candidates.append(
                                {
                                    "object": name,
                                    "actor": actor,
                                    "evidence": _evidence(
                                        path,
                                        raw,
                                        offset + local,
                                        offset + local + len(nominal[1]),
                                    ),
                                    "actor_evidence": actor_evidence,
                                    "mode": "CONDITIONAL"
                                    if conditional
                                    else "NEGATIVE"
                                    if negative
                                    else "CLAIMED",
                                    "proposition_id": p["id"],
                                }
                            )
                    else:
                        barrier = barrier or "unaccounted_clause"
                local_refs = list(_references(path, raw, p))
                for ref, name, kind in local_refs:
                    if len(references) >= self.limits.references:
                        omissions.append(
                            {"source_path": path, "reason": "reference_record_budget"}
                        )
                        break
                    possible = [
                        c for c in candidates if c["evidence"]["end"] < ref["start"]
                    ]
                    matching = (
                        [c for c in possible if c["object"] == name] if name else []
                    )
                    if p["quotation"]:
                        reason = "quoted_scope"
                    elif kind in {"son", "sa", "ses", "su", "sus"}:
                        reason = "unsupported_reference_form"
                    elif kind in {"its", "their", "it"}:
                        reason = "pronoun_not_disambiguated"
                    elif omissions:
                        reason = "incomplete_input"
                    elif barrier:
                        reason = barrier
                    elif actor == "UNKNOWN":
                        reason = "actor_unresolved"
                    elif name is None:
                        reason = "unsupported_reference_form"
                    elif not _consumer_supported(
                        positive_body, offset + len(text) - len(positive_body), ref
                    ):
                        reason = "unsupported_clause_structure"
                    elif len(matching) > 1:
                        reason = "multiple_candidates"
                    elif not matching:
                        reason = "no_exact_candidate"
                    elif matching[0]["actor"] != actor:
                        reason = "actor_scope_changed"
                    else:
                        reason = "unique_exact_nominal_candidate"
                    linked = reason == "unique_exact_nominal_candidate"
                    references.append(
                        {
                            "reference": ref,
                            "reference_kind": kind,
                            "actor": actor,
                            "actor_evidence": actor_evidence,
                            "status": "LINKED_CANDIDATE" if linked else "UNRESOLVED",
                            "reason": reason,
                            "antecedent": matching[0] if linked else None,
                            "candidates": possible,
                            "alternative_subject": actor_evidence,
                            "context": _evidence(path, raw, scope_start, p["end"]),
                            "proposition_id": p["id"],
                            "actual_data_lineage_verified": False,
                        }
                    )
                if not source and (not p["quotation"]):
                    supported = local_refs and all(
                        (
                            _consumer_supported(
                                positive_body,
                                offset + len(text) - len(positive_body),
                                ref,
                            )
                            for ref, _, _ in local_refs
                        )
                    )
                    if not supported:
                        barrier = barrier or "unaccounted_clause"
        if omissions:
            for r in references:
                if r["status"] == "LINKED_CANDIDATE":
                    r.update(
                        status="UNRESOLVED", reason="incomplete_input", antecedent=None
                    )
        extraction["reference_shadow"] = {
            "revision": REVISION,
            "status": "INCOMPLETE" if omissions else "AVAILABLE",
            "shadow_only": True,
            "creates_permissions": False,
            "authorization_verified": False,
            "actual_data_lineage_verified": False,
            "references": references,
            "omissions": omissions,
            "coverage": {
                "complete_semantic_understanding": None,
                "scope": "bounded EN explicit nominal reference grammar; pronouns unresolved",
            },
            "limits": {
                "references": self.limits.references,
                "candidates": self.limits.candidates,
            },
            "limitations": [
                "untrusted metadata hypotheses",
                "no guaranteed referent existence",
                "no proof of actual data flow, authorized effect or resource binding",
                "no general coreference, number agreement, multilingual or discourse understanding",
                "no clearing of observed uncertainties; not connected to production decisions",
            ],
        }
        return extraction
