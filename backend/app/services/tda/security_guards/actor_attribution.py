"""Narrow explicit-actor projection for contract evidence, never authority.

Original metadata/facts remain observable. Only proved local agent-subject
clauses are masked in a derived consistency view. Discovery is not exhaustive.
"""

from __future__ import annotations
from app.services.tda.security_guards.propositions import (
    extract_propositions,
    _AGENT,
    _PRECALL,
    _TOOL,
    _QUOTE,
    _ACTION,
    _coarse_segments,
)
from app.services.tda.claim_context import _AGENT_FRAME
import copy, re

REVISION = "explicit-agent-contract-evidence-v1"


def _value(snapshot, pointer):
    node = snapshot
    for part in pointer[1:].split("/"):
        key = part.replace("~1", "/").replace("~0", "~")
        node = node[int(key)] if isinstance(node, list) else node[key]
    return node


def _set(snapshot, pointer, value):
    parent, key = pointer.rsplit("/", 1)
    node = _value(snapshot, parent) if parent else snapshot
    key = key.replace("~1", "/").replace("~0", "~")
    node[int(key) if isinstance(node, list) else key] = value


def explicit_agent_contract_view(snapshot):
    extraction = extract_propositions(snapshot)
    excluded = []
    uncertain = []
    for p in extraction["propositions"]:
        if p["actor"] != "AGENT" or p["speech_act"] not in {"INSTRUCTION", "ENACTMENT"}:
            continue
        if p["quotation"] or p["polarity"] != "POSITIVE" or p["action"] not in _ACTION:
            continue
        raw = _value(snapshot, p["source_path"])
        text = p["excerpt"]
        predicate = _ACTION[p["action"]].search(text)
        if predicate is None:
            continue
        sentence = max(
            (m.end() for m in re.finditer("[.;!?\\n]", raw[: p["start"]])), default=0
        )
        quotes = [(m.start(), m.end()) for m in _QUOTE.finditer(raw)]
        roles = []
        for pattern, actor in ((_AGENT, "AGENT"), (_PRECALL, "AGENT"), (_TOOL, "TOOL")):
            for m in pattern.finditer(raw, sentence, p["start"] + predicate.start()):
                if not any((a <= m.start() < b for a, b in quotes)):
                    roles.append((m.start(), m.end(), actor))
        if not roles:
            continue
        a, b, actor = max(roles)
        if actor != "AGENT":
            continue
        leader = raw[sentence:a]
        local_start = a >= p["start"] and bool(
            re.fullmatch(
                "\\s*(?:(?:and|then|et|puis|y)\\s+)?", raw[p["start"] : a], re.I
            )
        )
        inherited = a < p["start"] and bool(re.fullmatch("\\s*", leader))
        if not (local_start or inherited):
            continue
        prefix = text[b - p["start"] if local_start else 0 : predicate.start()]
        direct = bool(re.fullmatch("\\s*(?:(?:and|then|et|puis|y)\\s+)?", prefix, re.I))
        claim = {
            "source_path": p["source_path"],
            "start": p["start"],
            "end": p["end"],
            "excerpt": text,
            "action": p["action"],
            "actor": "AGENT",
            "condition": p["condition"],
            "polarity": p["polarity"],
            "quotation": p["quotation"],
            "actor_evidence": {
                "source_path": p["source_path"],
                "start": a,
                "end": b,
                "excerpt": raw[a:b],
            },
        }
        (excluded if direct else uncertain).append(claim)
    for field in extraction["fields"]:
        if field.get("kind") != "TEXT":
            continue
        path = field["source_path"]
        raw = _value(snapshot, path)
        retained = raw[: field["retained_chars"]]
        quoted = [(m.start(), m.end()) for m in _QUOTE.finditer(retained)]
        for start, end in _coarse_segments(retained):
            segment = retained[start:end]
            frame = _AGENT_FRAME.match(segment)
            if frame is None:
                continue
            suffix = segment[frame.end() :]
            separator = re.match("\\s*:\\s*", suffix)
            if separator is None:
                continue
            command_start = frame.end() + separator.end()
            command = segment[command_start:]
            action_match = next(
                (
                    (name, pattern.match(command))
                    for name, pattern in _ACTION.items()
                    if pattern.match(command)
                ),
                None,
            )
            if action_match is None:
                continue
            action, predicate = action_match
            if (
                any((q0 < end and q1 > start for q0, q1 in quoted))
                or _TOOL.search(command)
                or any(
                    (
                        c["source_path"] == path
                        and c["start"] < end
                        and (c["end"] > start)
                        for c in excluded
                    )
                )
            ):
                continue
            claim = {
                "source_path": path,
                "start": start,
                "end": end,
                "excerpt": segment,
                "action": action,
                "actor": "AGENT",
                "condition": None,
                "polarity": "POSITIVE",
                "quotation": False,
                "actor_evidence": {
                    "source_path": path,
                    "start": start,
                    "end": start + frame.end(),
                    "excerpt": segment[: frame.end()],
                },
                "evidence_origin": "explicit_local_agent_addressee_colon",
            }
            excluded.append(claim)
    view = copy.deepcopy(snapshot) if excluded else snapshot
    by_field = {}
    for p in excluded:
        by_field.setdefault(p["source_path"], []).append(p)
    for path, claims in by_field.items():
        chars = list(_value(snapshot, path))
        for p in claims:
            for i in range(p["start"], p["end"]):
                if not chars[i].isspace():
                    chars[i] = " "
        _set(view, path, "".join(chars))
    return (
        view,
        {
            "revision": REVISION,
            "scope": "explicit local agent subject/frame only; not exhaustive actor understanding",
            "excluded_claims": excluded,
            "uncertain_claims": uncertain,
            "omissions": extraction["omissions"],
            "creates_permissions": False,
            "original_metadata_preserved": True,
        },
    )
