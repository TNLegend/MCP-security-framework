"""Bounded, evidence-linked proposition candidates from raw untrusted metadata.

This is a deterministic research extractor, not a language-understanding proof.
No contracts or permissions enter extraction. Actor is distinct from addressee.
"""

from __future__ import annotations
from dataclasses import asdict, dataclass
from hashlib import sha256
import re
from itertools import islice
from typing import Any, Protocol

REVISION = "propositions-deterministic-v1.1"


@dataclass(frozen=True)
class Budgets:
    nodes: int = 16384
    depth: int = 48
    total_chars: int = 64000
    field_chars: int = 16000
    propositions: int = 512


class PropositionEngine(Protocol):
    revision: str

    def extract(self, snapshot: dict[str, Any]) -> dict[str, Any]: ...


@dataclass(frozen=True)
class Proposition:
    id: str
    source_path: str
    start: int
    end: int
    excerpt: str
    actor: str
    addressee: str
    speech_act: str
    action: str
    object: str
    destination: str
    condition: str | None
    polarity: str
    quotation: bool
    concealment: str
    reference: str
    interpretation: str
    uncertainty: tuple[str, ...]
    evidence_quality: str
    evidence: tuple[dict, ...]
    operational: bool
    concealment_directive: str = "UNKNOWN"


_QUOTE = re.compile('"[^"\\n]*"|“[^”\\n]*”|«[^»\\n]*»|`[^`\\n]*`')
_LINK = re.compile('https?://[^\\s"<>]+', re.I)
_PRECALL = re.compile(
    "\\b(?:before\\s+(?:using|calling|every\\s+call)|avant\\s+d[’'](?:utiliser|appeler)|antes\\s+de\\s+(?:usar|llamar))\\b",
    re.I,
)
_AGENT = re.compile(
    "\\b(?:you\\s+(?:must|should|need)|the\\s+(?:AI\\s+)?agent\\s+(?:must|should)|l.agent\\s+doit|el\\s+agente\\s+debe)\\b",
    re.I,
)
_TOOL = re.compile(
    "\\b(?:this\\s+tool|the\\s+tool|the\\s+service|cet\\s+outil|l.outil|la\\s+herramienta)\\s+(?!is\\s+requested|metadata)",
    re.I,
)
_ENACT = re.compile(
    "\\b(?:follow|obey|apply|perform|execute|suiv\\w*|appliqu\\w*|sigue|aplica)\\s+(?:those|these|the\\s+(?:quoted|above)|ces|estas|esas)\\s+(?:instructions?|directions?|steps?|consignes?|instrucciones?)\\b",
    re.I,
)
_DOC = re.compile(
    "\\b(?:search|find|scan|match|quote|explain|discuss|documentation|recherch\\w*|chercher|cit\\w*|busca\\w*|documentaci[oó]n)\\b",
    re.I,
)
_NEG = re.compile(
    "\\b(?:do\\s+not|does\\s+not|never|don.t|must\\s+not|ne\\b.{0,24}\\b(?:pas|jamais)|no\\s+(?:revel\\w*|env[ií]\\w*|transmit\\w*)|sin\\s+|without\\s+)\\b",
    re.I,
)
_SECRET = re.compile(
    "\\b(?:credentials?|passwords?|tokens?|secrets?|api\\s+keys?|identifiants?|jetons?|mots?\\s+de\\s+passe|credenciales|contraseñas)\\b",
    re.I,
)
_CONCEAL = re.compile(
    "\\b(?:do\\s+not|don.t|never)\\s+(?:tell|mention|reveal|disclose|inform)|\\b(?:hide|conceal|omit)\\b|\\b(?:without\\s+(?:telling|notifying)|keep\\b.{0,35}\\bhidden|quietly|secretly|en\\s+cachette|ne\\s+(?:le\\s+)?dites\\s+pas|no\\s+(?:inform\\w*|dig\\w*))\\b",
    re.I,
)
_HIDE_PREDICATE = re.compile("\\b(?:hide|conceal|omit)\\b", re.I)
_FORBID_PREDICATE = re.compile(
    "\\b(?:never|do\\s+not|don.t|must\\s+not|should\\s+not)\\s+(?:(?:ever|deliberately|intentionally)\\s+)?$",
    re.I,
)
_GUIDE = re.compile(
    "\\b(?:supply|provide|specify|set|pass|use|fournir|indiqu\\w*|proporcion\\w*)\\b",
    re.I,
)
_CROSS = re.compile(
    "\\b(?:another|other|different|second|un\\s+autre|otro|otra)\\s+(?:MCP\\s+)?(?:tool|service|outil|herramienta)|\\b(?:call|invoke|appeler|llamar)\\s+[`\\w.-]+",
    re.I,
)
_CONDITION = re.compile("\\b(?:if|unless|when|si|cuando)\\b[^,.;]*", re.I)
_ACTION = {
    "read": re.compile(
        "\\b(?:read\\w*|retrieve\\w*|fetch\\w*|lire|lisez|lit|lee|leer|lectura)\\b",
        re.I,
    ),
    "search": re.compile("\\b(?:search\\w*|find\\w*|recherch\\w*|busca\\w*)\\b", re.I),
    "send": re.compile(
        "\\b(?:send\\w*|sent|transmi\\w*|forward\\w*|upload\\w*|envoy\\w*|envi\\w*)\\b",
        re.I,
    ),
    "delete": re.compile(
        "\\b(?:delet\\w*|remov\\w*|destroy\\w*|supprim\\w*|effac\\w*|borr\\w*|elimin\\w*)\\b",
        re.I,
    ),
    "execute": re.compile("\\b(?:execut\\w*|run\\w*|lanc\\w*|ejecut\\w*)\\b", re.I),
    "return": re.compile(
        "\\b(?:return\\w*|retourn\\w*|renvoi\\w*|devuelv\\w*)\\b", re.I
    ),
    "compose": re.compile(
        "\\b(?:attach\\w*|includ\\w*|append\\w*|put|joign\\w*|ajout\\w*|adjunt\\w*)\\b",
        re.I,
    ),
}
_SOURCE = re.compile(
    "\\b(?:file|report|document|record|note|fichier|rapport|informe|archivo|documento)s?\\b|(?:~[/\\\\]|[A-Za-z]:[/\\\\])[^\\s,;]+",
    re.I,
)
_OUTPUT = re.compile(
    "\\b(?:response|result|output|retour|r[eé]ponse|salida|contenido)\\b.{0,55}\\b(?:caller|user|recipient|utilisateur|usuario)|\\b(?:return\\w*|devuelv\\w*)\\b",
    re.I,
)
_OUTBOUND = re.compile(
    "\\b(?:outgoing|outbound|request|payload|requ[eê]te|charge\\s+utile|carga|solicitud)\\b",
    re.I,
)


def _pointer(path: str, key: Any) -> str:
    return path + "/" + str(key).replace("~", "~0").replace("/", "~1")


def _coarse_segments(raw: str):
    """Non-whitespace text is retained; quotation/URL punctuation stays intact."""
    protected = [(m.start(), m.end()) for p in (_QUOTE, _LINK) for m in p.finditer(raw)]
    boundary = re.compile(
        "[;!?\\n]|\\.(?=\\s|$)|,|\\b(?:and|but|then|et|mais|puis|y|pero)\\b", re.I
    )
    start = 0
    for hit in boundary.finditer(raw):
        if any((a <= hit.start() < b for a, b in protected)):
            continue
        stop = hit.start()
        a = start
        while a < stop and raw[a].isspace():
            a += 1
        while stop > a and raw[stop - 1].isspace():
            stop -= 1
        if stop > a:
            yield (a, stop)
        start = hit.start() if hit.group()[0].isalpha() else hit.end()
    a = start
    b = len(raw)
    while a < b and raw[a].isspace():
        a += 1
    while b > a and raw[b - 1].isspace():
        b -= 1
    if a < b:
        yield (a, b)


def _segments(raw: str):
    for a, b in _coarse_segments(raw):
        cursor = a
        for q in _QUOTE.finditer(raw, a, b):
            if raw[cursor : q.start()].strip():
                left = cursor
                while raw[left].isspace():
                    left += 1
                right = q.start()
                while right > left and raw[right - 1].isspace():
                    right -= 1
                yield (left, right)
            yield (q.start(), q.end())
            cursor = q.end()
        if raw[cursor:b].strip():
            while raw[cursor].isspace():
                cursor += 1
            yield (cursor, b)


def _documentary(raw: str, start: int, end: int) -> bool:
    return any(
        (
            q.start() <= start
            and end <= q.end()
            and _DOC.search(raw[max(0, q.start() - 180) : q.start()])
            for q in _QUOTE.finditer(raw)
        )
    )


def _claim(
    path: str, raw: str, start: int, end: int, index: int, arguments: tuple[str, ...]
) -> Proposition:
    text = raw[start:end]
    before = raw[:start]
    prefix = raw[max(0, start - 500) : start]
    quoted = any((q.start() <= start and end <= q.end() for q in _QUOTE.finditer(raw)))
    documentary = bool(
        _QUOTE.search(text) and _DOC.search(text[: _QUOTE.search(text).start()])
    ) or _documentary(raw, start, end)
    active_text = (
        _QUOTE.sub(lambda m: " " * (m.end() - m.start()), text) if documentary else text
    )
    enact = bool(_ENACT.search(active_text))
    local_tool = _TOOL.search(active_text)
    actor = "TOOL" if local_tool else "UNKNOWN"
    addressee = "UNKNOWN"
    speech = "UNKNOWN"
    precall = bool(_PRECALL.search(raw[:end]))
    quote_ranges = [(q.start(), q.end()) for q in _QUOTE.finditer(raw)]
    outside = lambda m: not any((a <= m.start() < b for a, b in quote_ranges))
    role_marks = [
        (m.start(), "AGENT")
        for pattern in (_AGENT, _PRECALL)
        for m in pattern.finditer(raw[:end])
        if outside(m)
    ]
    role_marks.extend(
        ((m.start(), "TOOL") for m in _TOOL.finditer(raw[:end]) if outside(m))
    )
    inherited = max(role_marks, default=(-1, "UNKNOWN"))[1]
    agent = bool(
        _AGENT.search(active_text)
        or (inherited == "AGENT" and (not local_tool))
        or enact
    )
    if agent:
        actor = "AGENT"
        addressee = "AGENT"
        speech = "ENACTMENT" if enact else "INSTRUCTION"
    elif inherited == "TOOL":
        actor = "TOOL"
    names = [
        (action, m)
        for action, pattern in _ACTION.items()
        if (m := pattern.search(active_text))
    ]
    names.sort(key=lambda x: x[1].start())
    action = names[0][0] if names else "UNKNOWN"
    if actor == "TOOL":
        speech = "TOOL_DESCRIPTION"
    predicate_prefix = active_text[: names[0][1].start()] if names else active_text
    negative = bool(_NEG.search(predicate_prefix))
    conceal = "NONE"
    if _CONCEAL.search(active_text):
        conceal = (
            "SECRET"
            if _SECRET.search(active_text)
            and negative
            and (
                not re.search(
                    "\\b(?:action|step|operation|did|doing|doing so)\\b",
                    active_text,
                    re.I,
                )
            )
            else "ACTION"
        )
    if (
        negative
        and _SECRET.search(active_text)
        and re.search(
            "\\b(?:reveal|disclose|révél\\w*|revel\\w*)\\b", active_text, re.I
        )
    ):
        conceal = "SECRET"
    concealment_directive = "NONE" if conceal == "NONE" else "UNKNOWN"
    if conceal == "ACTION":
        hidden = list(_HIDE_PREDICATE.finditer(active_text))
        if hidden and all(
            (_FORBID_PREDICATE.search(active_text[: m.start()]) for m in hidden)
        ):
            concealment_directive = "FORBIDDEN"
        else:
            concealment_directive = "REQUIRED"
    if conceal == "SECRET":
        speech = "PROTECTIVE_GUIDANCE"
        actor = "TOOL" if actor == "UNKNOWN" and _TOOL.search(before) else actor
    source = _SOURCE.search(active_text)
    obj = source.group() if source else "UNKNOWN"
    destination = "UNKNOWN"
    if _OUTPUT.search(active_text):
        destination = "CALLER_OUTPUT"
    elif _CROSS.search(active_text):
        destination = "OTHER_TOOL"
    elif _OUTBOUND.search(active_text):
        destination = "UNRESOLVED_OUTBOUND"
    elif any(
        (
            re.search(
                "\\b(?:to|vers|a)\\s+" + re.escape(name) + "(?!\\w)", active_text, re.I
            )
            for name in arguments
        )
    ):
        destination = "ARGUMENT"
    link = _LINK.search(active_text)
    if link:
        destination = "EXPLICIT_URI"
    parameters = re.findall(
        "\\b([\\w-]+)\\s+(?:argument|parameter)\\b", active_text, re.I
    )
    if parameters and action == "compose":
        destination = "INPUT_PARAMETER"
    named_argument = any(
        (
            re.search("(?<!\\w)" + re.escape(name) + "(?!\\w)", active_text, re.I)
            for name in arguments
        )
    )
    guide = bool(
        _GUIDE.search(active_text)
        and (
            parameters
            or named_argument
            or re.search(
                "\\b(?:argument|parameter|champ|param[eè]tre)\\b", active_text, re.I
            )
        )
    )
    if (
        guide
        and conceal != "ACTION"
        and (action not in {"read", "send", "delete", "execute"})
    ):
        actor = "AGENT"
        addressee = "AGENT"
        speech = "USAGE_GUIDANCE"
    if documentary and (not enact):
        speech = "DOCUMENTARY"
        quoted = True
        if _documentary(raw, start, end):
            actor = "UNKNOWN"
            action = "UNKNOWN"
    conditional = list(_CONDITION.finditer(_QUOTE.sub("", raw[:end])))
    condition = (
        conditional[-1].group()
        if conditional and conditional[-1].start() >= max(0, start - 180)
        else None
    )
    reference = (
        "UNRESOLVED"
        if re.search(
            "\\b(?:its|their|those|these|it|son|sa|ses|su|sus)\\b", active_text, re.I
        )
        else "NONE"
    )
    if enact:
        reference = "QUOTED_INSTRUCTION" if _QUOTE.search(before) else "UNRESOLVED"
    uncertainty = []
    operational = (
        bool(action != "UNKNOWN" or agent or conceal == "ACTION")
        and speech != "DOCUMENTARY"
    )
    if operational and actor == "UNKNOWN":
        uncertainty.append("actor_unresolved")
    if operational and action == "UNKNOWN":
        uncertainty.append("predicate_unresolved")
    if action in {"send", "compose"} and destination in {
        "UNKNOWN",
        "UNRESOLVED_OUTBOUND",
    }:
        uncertainty.append("destination_unresolved")
    if reference == "UNRESOLVED":
        uncertainty.append("reference_unresolved")
    if action not in {"UNKNOWN", "return"} and obj == "UNKNOWN":
        uncertainty.append("object_unresolved")
    interpretation = "SUPPORTED" if not uncertainty else "PARTIAL"
    if (
        action == "UNKNOWN"
        and (not guide)
        and (not documentary)
        and (not (negative and conceal == "SECRET"))
    ):
        interpretation = "UNACCOUNTED"
        uncertainty.append("uninterpreted_text")
    return Proposition(
        f"p{index}",
        path,
        start,
        end,
        text,
        actor,
        addressee,
        speech,
        action,
        obj,
        destination,
        condition,
        "NEGATIVE" if negative else "POSITIVE",
        quoted,
        conceal,
        reference,
        interpretation,
        tuple(dict.fromkeys(uncertainty)),
        "EXPLICIT_UNTRUSTED_METADATA",
        (
            {
                "source_path": path,
                "start": start,
                "end": end,
                "excerpt": text,
                "relation": "CONTEXTUAL_HYPOTHESIS",
            },
        ),
        operational,
        concealment_directive,
    )


class DeterministicPropositionEngine:
    revision = REVISION

    def __init__(self, budgets: Budgets | None = None):
        self.budgets = budgets or Budgets()

    def extract(self, snapshot: dict[str, Any]) -> dict[str, Any]:
        return extract_propositions(snapshot, self.budgets)


def extract_propositions(
    snapshot: dict[str, Any], budgets: Budgets | None = None
) -> dict[str, Any]:
    b = budgets or Budgets()
    stack = [("", snapshot, 0, frozenset())]
    fields = []
    omissions = []
    claims = []
    visited = chars = 0
    argument_names = set()
    todo = [snapshot.get("input_schema")]
    seen = set()
    while todo and len(seen) < b.nodes:
        node = todo.pop()
        if not isinstance(node, (dict, list)) or id(node) in seen:
            continue
        seen.add(id(node))
        if isinstance(node, dict):
            props = node.get("properties")
            if isinstance(props, dict):
                argument_names.update((str(k) for k in islice(props, b.nodes)))
            todo.extend(islice(node.values(), max(0, b.nodes - len(todo) - len(seen))))
        else:
            todo.extend(islice(node, max(0, b.nodes - len(todo) - len(seen))))
    arguments = tuple(sorted(argument_names))
    while stack and visited < b.nodes:
        path, value, depth, ancestors = stack.pop()
        visited += 1
        if depth > b.depth:
            omissions.append({"source_path": path, "reason": "depth_budget"})
            continue
        if isinstance(value, (dict, list)):
            if id(value) in ancestors:
                omissions.append({"source_path": path, "reason": "cyclic_metadata"})
                continue
            ids = ancestors | {id(value)}
            items = value.items() if isinstance(value, dict) else enumerate(value)
            available = max(0, b.nodes - visited - len(stack))
            if len(value) > available:
                omissions.append(
                    {
                        "source_path": path,
                        "reason": "node_budget",
                        "omitted_children": len(value) - available,
                    }
                )
            for key, child in reversed(list(islice(items, available))):
                stack.append((_pointer(path, key), child, depth + 1, ids))
            continue
        if not isinstance(value, str):
            fields.append(
                {
                    "source_path": path,
                    "kind": "SCALAR_HINT",
                    "trusted": False,
                    "proposition_ids": [],
                }
            )
            continue
        retained = min(len(value), b.field_chars, max(0, b.total_chars - chars))
        chars += retained
        if retained < len(value):
            omissions.append(
                {
                    "source_path": path,
                    "reason": "character_budget",
                    "omitted_chars": len(value) - retained,
                }
            )
        ids = []
        intervals = []
        for a, z in _segments(value[:retained]):
            if len(claims) >= b.propositions:
                omissions.append(
                    {"source_path": path, "reason": "proposition_budget", "start": a}
                )
                break
            p = _claim(path, value, a, z, len(claims), arguments)
            claims.append(asdict(p))
            ids.append(p.id)
            intervals.append([a, z])
        fields.append(
            {
                "source_path": path,
                "kind": "TEXT",
                "raw_sha256": sha256(value.encode()).hexdigest(),
                "original_chars": len(value),
                "retained_chars": retained,
                "proposition_ids": ids,
                "represented_intervals": intervals,
                "discovery_claim": "bounded segmentation; lexical coverage is not semantic completeness",
            }
        )
    if stack:
        omissions.append(
            {"source_path": "", "reason": "node_budget", "pending_nodes": len(stack)}
        )
    complete = not omissions
    return {
        "schema": "tool-propositions-v1",
        "engine": REVISION,
        "shadow_only": True,
        "creates_permissions": False,
        "fields": fields,
        "propositions": claims,
        "omissions": omissions,
        "budgets": asdict(b),
        "coverage": {
            "metadata_fields": {"complete": complete, "visited_nodes": visited},
            "proposition_discovery": {
                "complete": None,
                "status": "NOT_VERIFIED",
                "represented": len(claims),
            },
            "interpretation": {
                "supported": sum((p["interpretation"] == "SUPPORTED" for p in claims)),
                "partial": sum((p["interpretation"] == "PARTIAL" for p in claims)),
                "unaccounted": sum(
                    (p["interpretation"] == "UNACCOUNTED" for p in claims)
                ),
            },
            "contract_verification": {
                "status": "NOT_RUN",
                "reason": "contracts do not enter extraction",
            },
        },
        "limitations": [
            "rule-based contextual hypotheses",
            "discovery recall not proven",
            "EN/FR/ES subset only",
            "not proof of remote behavior",
        ],
    }
