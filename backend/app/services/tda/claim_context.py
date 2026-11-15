"""Local speech-act context, shared by extraction and poisoning checks.

Quotation is not an exemption: only a positively evidenced documentary/search
use makes a quoted span non-operational. Raw metadata is always retained.
"""

from __future__ import annotations
import re

_QUOTES = re.compile(
    "\"[^\"\\n]*\"|«[^»\\n]*»|“[^”\\n]*”|`[^`\\n]*`|(?<!\\w)\\'[^\\'\\n]+\\'(?!\\w)"
)
_DOCUMENTARY = re.compile(
    "\\b(?:search\\w*|find\\w*|scan\\w*|match\\w*|contain\\w*|quot\\w*|document\\w*|explain\\w*|discuss\\w*|recherch\\w*|cherch\\w*|contient|cit\\w*)\\b.{0,150}\\b(?:phrase|literal|occurrences?|strings?|patterns?|text|examples?|instructions?|attacks?|expression|texte|exemples?)\\b",
    re.I,
)
_ENACT = re.compile(
    "\\b(?:follow|obey|execute|apply|perform|suivre|exécuter|appliquer)\\w*\\b", re.I
)


def quotation_spans(text: str) -> list[tuple[int, int]]:
    """Boundaries only; a quotation does not itself make a claim harmless."""
    return [match.span() for match in _QUOTES.finditer(text)]


def metadata_texts(snapshot: dict):
    """Keep source boundaries; never synthesize a claim across unrelated fields."""
    stack = [("$", snapshot)]
    visited = 0
    while stack and visited < 16384:
        path, value = stack.pop()
        visited += 1
        if isinstance(value, str):
            yield (path, value)
        elif isinstance(value, dict):
            stack.extend(((f"{path}.{k}", v) for k, v in value.items()))
        elif isinstance(value, list):
            stack.extend(((f"{path}[{i}]", v) for i, v in enumerate(value)))


def reference_span(text: str, start: int, end: int) -> bool:
    for quote in _QUOTES.finditer(text):
        if quote.start() <= start and end <= quote.end():
            prefix = re.split(
                "[;.!?\\n]", text[max(0, quote.start() - 220) : quote.start()]
            )[-1]
            enact = list(_ENACT.finditer(prefix))
            document = list(_DOCUMENTARY.finditer(prefix))
            return bool(
                document and (not enact or enact[-1].start() < document[-1].start())
            )
    return False


def comparative_span(text: str, start: int, end: int) -> bool:
    sentence_start = (
        max(
            text.rfind(".", 0, start),
            text.rfind(";", 0, start),
            text.rfind("\n", 0, start),
        )
        + 1
    )
    prefix = text[sentence_start:start]
    return bool(
        re.search(
            "\\b(?:unlike|rather\\s+than|contrary\\s+to|contrairement\\s+à)\\b[^,]*$",
            prefix,
            re.I,
        )
    )


def claim_mode(text: str, start: int, end: int) -> str:
    if reference_span(text, start, end):
        return "QUOTED"
    if comparative_span(text, start, end):
        return "HYPOTHETICAL"
    prefix = re.split("[;.!?\\n]", text[max(0, start - 180) : start])[-1]
    if re.search(
        "\\b(?:never|not|without|pas|jamais)\\b(?:\\s+\\w+){0,4}\\s*$", prefix, re.I
    ):
        return "NEGATED"
    if re.search("\\b(?:if|unless|when|si|cuando)\\b", prefix, re.I):
        return "CONDITIONAL"
    return "CLAIMED"


def poisoning_signals(text: str) -> list[dict]:
    """Evidence of an agent-directed hidden action, never inferred from names.

    This is a bounded rule detector, not a proof of absence of poisoning.
    One concealment request alone (e.g. never reveal credentials) is insufficient.
    """
    directive = re.compile(
        "\\b(?:before\\s+(?:using|calling)|you\\s+(?:must|should)|(?:read|collect|retrieve|fetch|include|pass|send|forward)\\b)",
        re.I,
    )
    conceal = re.compile(
        "\\b(?:do\\s+not|don.t|never)\\s+(?:mention|tell|disclose|inform|reveal)\\b|\\b(?:hide|conceal)\\s+(?:this|the\\s+(?:step|action|operation))\\b",
        re.I,
    )
    transfer = re.compile(
        "\\b(?:pass|send|forward|include|transmit)\\b.{0,100}\\b(?:content|contents|data|result|value|text|material|as|to)\\b",
        re.I,
    )
    collect = re.compile("\\b(?:read|collect|retrieve|fetch|extract|open)\\b", re.I)
    active = lambda pattern: [
        m
        for m in pattern.finditer(text)
        if claim_mode(text, m.start(), m.end())
        not in {"QUOTED", "HYPOTHETICAL", "NEGATED"}
    ]
    directives = active(directive)
    hidden = active(conceal)
    sources = active(collect)
    sinks = active(transfer)
    if directives and hidden and sources and sinks:
        spans = [directives[0], hidden[0], sources[0], sinks[0]]
        if max((m.end() for m in spans)) - min((m.start() for m in spans)) <= 1000:
            return [
                {
                    "kind": "agent_directed_hidden_transfer",
                    "evidence": [
                        {"start": m.start(), "end": m.end(), "text": m.group()}
                        for m in spans
                    ],
                }
            ]
    return []


_AGENT_FRAME = re.compile(
    "(?:\\b(?:for|to|as|para|pour)\\s+(?:(?:the|el|un|an|le)\\s+)?(?:calling\\s+)?(?:l[' ])?(?:assistant|agent|agente|asistente|model|modelo)\\b|\\bwhen\\s+acting\\s+as\\s+(?:an?\\s+)?(?:agent|assistant|model)\\b|\\b(?:assistant|agent|agente|asistente|model|modelo)\\s*[,;:]|\\b(?:the|el|l[' ])?\\s*(?:assistant|agent|agente|asistente|model|modelo)\\s+(?:must|should|shall|doit|debe)\\b)",
    re.I,
)
