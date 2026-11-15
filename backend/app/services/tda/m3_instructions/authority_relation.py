"""Conservative, directional agent instruction-authority relation evidence.

Only emits a REVIEW candidate for explicitly evidenced promotion of an
untrusted tool over prior instructions. No BLOCK or execution permissions.
Unknown/incomplete relations remain unclaimed. Original offsets preserved.
"""

from __future__ import annotations
from app.services.tda.m1_sources.capture import SourcePath
import re
import unicodedata
from typing import Any

REVISION = "p1-directional-review-v1"
_CLAUSE = re.compile("[^.!?;\\n]+")
_AGENT = re.compile(
    "\\b(?:agent|assistant|model|llm|ai|you|your|vous|votre|asistente|agente|modelo)\\b",
    re.I,
)
_TOOL = re.compile(
    "\\b(?:tool|server|service|connector|outil|serveur|herramienta|servidor|servicio)\\b",
    re.I,
)
_TOOL_MESSAGE = re.compile(
    "\\b(?:tool|server|service|connector|outil|serveur|herramienta|servidor|servicio)\\b",
    re.I,
)
_PRIOR = re.compile(
    "\\b(?:earlier|previous|prior|previously|original|beforehand|already|existing|system|developer|user|precedent\\w*|anterieur\\w*|auparavant|initial\\w*|utilisateur|recues?|anteriores?|previas?|usuario|sistema)\\b",
    re.I,
)
_INSTRUCTION = re.compile(
    "\\b(?:instructions?|directives?|guidance|directions?|requests?|messages?|prompts?|consignes?|indicaciones?|instrucciones?|ordenes?|directrices?)\\b",
    re.I,
)
_QUOTED = re.compile('["“«\\x27][^"”»\\x27]{1,250}["”»\\x27]')
_DOCUMENTARY = re.compile(
    "\\b(?:quotation|literal phrase|literal text|quoted|the report|the documentation|security report|documents? (?:that|how|the)|search for|find the literal|shows? an? example|example of|d[ée]crit|ejemplo|documentaci[oó]n)\\b",
    re.I,
)
_LOCAL_NEG = re.compile(
    "\\b(?:do not|does not|must not|should not|never|don.t|cannot|ne\\s+\\w+(?:\\s+\\w+){0,4}\\s+(?:pas|jamais)|no debe|no deben)\\b",
    re.I,
)
_OPS = [
    (
        "take_priority",
        "(?P<P>.+?)\\b(?:take|takes|have|has)\\s+(?:the\\s+)?(?:priority|precedence)\\s+over\\s+(?P<D>.+)",
    ),
    (
        "give_priority",
        "\\bgive\\s+(?P<P>.+?)\\s+(?:priority|precedence)\\s+over\\s+(?P<D>.+)",
    ),
    (
        "active_override",
        "(?P<P>.+?)\\b(?:override|overrides|supersede|supersedes|outrank|outranks|outweigh|outweighs)\\s+(?P<D>.+)",
    ),
    (
        "passive_override",
        "(?P<D>.+?)\\b(?:is|are|will be|must be)\\s+(?:overridden|superseded|outranked|outweighed)\\s+by\\s+(?P<P>.+)",
    ),
    (
        "rank_above",
        "\\b(?:rank|put|place|prioriti[sz]e|prefer)\\s+(?P<P>.+?)\\s+(?:above|over|ahead\\s+of|before)\\s+(?P<D>.+)",
    ),
    (
        "follow_before",
        "\\b(?:follow|obey|treat|apply)\\s+(?P<P>.+?)\\s+(?:ahead\\s+of|before|rather\\s+than|instead\\s+of|in\\s+preference\\s+to|over)\\s+(?P<D>.+)",
    ),
    (
        "more_authoritative",
        "(?P<P>.+?)\\b(?:is|are|be|as)\\s+(?:more\\s+authoritative|higher[- ]priority|more\\s+important|superior)\\s+(?:than|to)\\s+(?P<D>.+)",
    ),
    (
        "treat_more_authoritative",
        "\\btreat\\s+(?P<P>.+?)\\s+as\\s+(?:more\\s+authoritative|higher[- ]priority|superior)(?:\\s+instructions?)?\\s+(?:than|to)\\s+(?P<D>.+)",
    ),
    (
        "passive_follow",
        "(?P<P>.+?)\\b(?:are|must be|should be)\\s+(?:to\\s+be\\s+)?(?:followed|obeyed)\\s+(?:instead\\s+of|rather\\s+than|before)\\s+(?P<D>.+)",
    ),
    (
        "higher_authority",
        "(?P<P>.+?)\\b(?:has|have)\\s+(?:higher|greater)\\s+authority\\s+than\\s+(?P<D>.+)",
    ),
    (
        "fr_primer",
        "(?P<P>.+?)\\b(?:priment?|a\\s+priorit[eé]|ont\\s+priorit[eé])\\s+(?:sur|avant)\\s+(?P<D>.+)",
    ),
    (
        "fr_priviliger",
        "\\b(?:privil[eé]gi\\w*|suivr\\w*|donn\\w*\\s+priorit[eé]\\s+(?:a|aux?|à|au))\\s+(?P<P>.+?)\\s+(?:plut[oô]t\\s+que|sur|avant)\\s+(?P<D>.+)",
    ),
    (
        "es_priorizar",
        "\\b(?:prioriza\\w*|seguir|obedecer|sigue|debe\\s+seguir)\\s+(?P<P>.+?)\\s+(?:sobre|antes\\s+que|en\\s+lugar\\s+de)\\s+(?P<D>.+)",
    ),
]
_OPS = [(name, re.compile(pattern, re.I)) for name, pattern in _OPS]


def _source_label(span: str) -> str:
    folded = "".join(
        (
            ch
            for ch in unicodedata.normalize("NFKD", span.casefold())
            if not unicodedata.combining(ch)
        )
    )
    has_tool = bool(_TOOL.search(folded))
    has_prior = bool(_PRIOR.search(folded))
    if has_tool and (not has_prior):
        return "TOOL_ORIGIN"
    if has_prior and (not has_tool) and _INSTRUCTION.search(folded):
        return "PRIOR_INSTRUCTIONS"
    return "UNKNOWN"


def _exact(path: str, text: str, start: int, end: int, role: str) -> dict[str, Any]:
    return {
        "source_path": path,
        "start": start,
        "end": end,
        "excerpt": text[start:end],
        "role": role,
    }


def _context_is_protected(clause: str, match: re.Match) -> bool:
    prefix = clause[max(0, match.start() - 80) : match.end()]
    if (
        _DOCUMENTARY.search(prefix)
        and (
            _QUOTED.search(clause)
            or re.search(
                "\\b(?:report|documentation|example|quotation)\\b", clause, re.I
            )
        )
        and (
            not re.search(
                "\\b(?:then|and|afterwards)\\s+(?:follow|obey|enact|apply)\\b",
                clause,
                re.I,
            )
        )
    ):
        return True
    operator_prefix = clause[max(0, match.start() - 30) : match.end()]
    if _LOCAL_NEG.search(operator_prefix):
        return True
    return False


def extract_priority_relations(
    snapshot: dict[str, Any], max_fields: int = 256, max_chars: int = 16000
) -> dict[str, Any]:
    rows = []
    omissions = []
    stack = [(SourcePath(None, ""), snapshot)]
    fields = 0
    nodes = 0
    while stack:
        path, val = stack.pop()
        nodes += 1
        if nodes > 16384:
            omissions.append({"reason": "node_budget_exceeded"})
            break
        if isinstance(val, dict):
            for k, v in reversed(tuple(val.items())):
                stack.append((SourcePath(path, str(k)), v))
            continue
        if isinstance(val, list):
            for i in reversed(range(len(val))):
                stack.append((SourcePath(path, str(i)), val[i]))
            continue
        if not isinstance(val, str):
            continue
        fields += 1
        if fields > max_fields:
            omissions.append({"reason": "field_budget_exceeded"})
            break
        if len(val) > max_chars:
            omissions.append({"source_path": path.pointer, "reason": "text_truncated"})
        txt = val[:max_chars]
        for clause in _CLAUSE.finditer(txt):
            raw = clause.group()
            if not _AGENT.search(raw):
                continue
            check = "".join(
                (
                    ch
                    for ch in unicodedata.normalize("NFKD", raw.casefold())
                    if not unicodedata.combining(ch)
                )
            )
            if not _TOOL_MESSAGE.search(check) or not _PRIOR.search(check):
                continue
            for opname, pattern in _OPS:
                matched = False
                for m in pattern.finditer(raw):
                    pp = m.group("P")
                    dd = m.group("D")
                    if (
                        _source_label(pp) != "TOOL_ORIGIN"
                        or _source_label(dd) != "PRIOR_INSTRUCTIONS"
                    ):
                        continue
                    if _context_is_protected(raw, m):
                        continue
                    p0, p1 = m.span("P")
                    d0, d1 = m.span("D")
                    offset = clause.start()
                    ptr = path.pointer
                    spans = [
                        _exact(ptr, val, offset + p0, offset + p1, "PROMOTED_SOURCE"),
                        _exact(ptr, val, offset + d0, offset + d1, "DISPLACED_SOURCE"),
                        _exact(
                            ptr,
                            val,
                            offset + m.start(),
                            offset + m.end(),
                            "RELATION_CLAUSE",
                        ),
                    ]
                    rows.append(
                        {
                            "code": "instruction_authority_relation",
                            "addressee": "AGENT",
                            "promoted_source": "TOOL_ORIGIN",
                            "displaced_source": "PRIOR_INSTRUCTIONS",
                            "operator": opname,
                            "evidence": spans,
                            "creates_permissions": False,
                            "status": "REVIEW_ONLY",
                        }
                    )
                    matched = True
                    break
                if matched:
                    break
    return {
        "revision": REVISION,
        "review_only": True,
        "relations": rows,
        "omissions": omissions,
        "coverage_complete": not omissions,
        "creates_permissions": False,
    }
