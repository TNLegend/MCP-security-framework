"""Bounded evidence for agent-directed lower-trust instruction precedence.

This detection only requests review. It never creates a tool permission,
signed observation, contract, role, or Runtime capability. Not an exhaustive
multilingual prompt-injection recognizer.
"""

from __future__ import annotations

from app.services.tda.claim_context import _AGENT_FRAME
from app.services.tda.claim_context import metadata_texts
import re
import unicodedata
from typing import Any

REVISION = "agent-priority-evidence-v1"
_SENTENCE = re.compile("[^.!?;\\n]+")
_AGENT = re.compile("\\b(?:assistant|agent|agente|asistente|model|modelo|llm)\\b", re.I)
_TOOL_ORIGIN = re.compile(
    "\\b(?:tool|service|server|connector|outil|serveur|servicio|servidor|herramienta)\\b",
    re.I,
)
_TOOL_CONTENT = re.compile(
    "\\b(?:instructions?|guidance|directions?|directives?|consignes?|replies|responses?|messages?|outputs?|indicaciones?|ordenes?|respuestas?|mensajes?)\\b",
    re.I,
)
_PRECEDENCE = re.compile(
    "\\b(?:take(?:s)?\\s+priority|higher\\s+priority|precedence|above|ahead\\s+of|overrides?|supersedes?|outranks?|rather\\s+than|instead\\s+of|in\\s+preference\\s+to|more\\s+authoritative\\s+than|superior|before|avant|prefer|prioritize|rank|priorite|privilegi(?:e|er|ez)|priment?|plutot\\s+que|prioriza(?:r|s|n)?|sobre|antes\\s+que|precedencia|en\\s+lugar\\s+de)\\b",
    re.I,
)
_PRIOR = re.compile(
    "\\b(?:earlier|previous(?:ly)?|prior|already|beforehand|existing|original|system|developer|user|precedent(?:es)?|auparavant|recues?|initiales?|anteriores?|previas?|originales?|usuario|utilisateur|sistema|politique|policy)\\b",
    re.I,
)
_PRIOR_DIRECTION = re.compile(
    "(?:\\b(?:earlier|previous(?:ly)?|prior|already|beforehand|existing|original|precedent(?:es)?|auparavant|recues?|initiales?|anteriores?|previas?)\\b.{0,65}\\b(?:instructions?|directions?|directives?|guidance|consignes?|indicaciones?|ordenes?)\\b|\\b(?:instructions?|directions?|directives?|guidance|consignes?|indicaciones?|ordenes?)\\b.{0,65}\\b(?:earlier|previous(?:ly)?|prior|already|beforehand|existing|original|precedent(?:es)?|auparavant|recues?|initiales?|anteriores?|previas?)\\b)",
    re.I,
)
_PRESENTATIONAL = re.compile(
    "\\b(?:show|display|render|sort|list|table|dashboard|index|transcript|visuali[sz]e|quoted\\s+data|muestra|mostrar|tabla|pantalla|affiche|afficher|tableau|classe|classer)\\b",
    re.I,
)
_ENACT = re.compile(
    "\\b(?:obey|follow|treat|enact|apply|regard|obedec(?:e|er)|seguir|sigue|suivre|agir|privil[eé]gi|prioriza)\\w*\\b",
    re.I,
)
_PROTECTION = re.compile(
    "\\b(?:do\\s+not|does\\s+not|must\\s+not|should\\s+not|never|cannot|dont|is\\s+not|are\\s+not|ne\\s+\\w+(?:\\s+\\w+){0,4}\\s+(?:pas|jamais)|no\\s+(?:debe|deberia|priorice|siga|sigas|obedezca))\\b",
    re.I,
)
_DOCUMENTARY = re.compile(
    "\\b(?:search|find|quote|document(?:ation|s)?|literal\\s+phrase|literal\\s+text|quotation|report\\s+documents|reports?\\s+on|detect|review|describe|recherch(?:er|e)|cite|documenter|mostrar|buscar|citar|documentar)\\b",
    re.I,
)
_DOC_SOURCE = re.compile("\\b(?:report|document|logs?|test)\\b", re.I)


def _fold(source: str) -> str:
    return (
        "".join(
            (
                c
                for c in unicodedata.normalize("NFKD", source.casefold())
                if not unicodedata.combining(c)
            )
        )
        .replace("’", "'")
        .replace("‘", "'")
    )


def agent_priority_claims(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    """Evidence spans are original whole sentences, not normalized offsets."""
    found = []
    for path, text in metadata_texts(snapshot):
        for match in _SENTENCE.finditer(text):
            original = match.group()
            normalized = _fold(original)
            if not all(
                (
                    p.search(normalized)
                    for p in (
                        _AGENT,
                        _TOOL_ORIGIN,
                        _TOOL_CONTENT,
                        _PRECEDENCE,
                        _PRIOR_DIRECTION,
                        _AGENT_FRAME,
                    )
                )
            ):
                continue
            if (
                _DOCUMENTARY.search(normalized)
                and (
                    re.search("[\"'][^\"']+[\"']", original)
                    or _DOC_SOURCE.search(normalized)
                    or re.search("\\b(?:quotation|literal\\s+phrase)\\b", normalized)
                )
                and (
                    not re.search(
                        "\\b(?:then|and|afterwards)\\s+(?:follow|obey|enact|apply)\\b",
                        normalized,
                    )
                )
            ):
                continue
            locally_protected = False
            for denial in _PROTECTION.finditer(normalized):
                segment = normalized[denial.start() :]
                segment = segment.split(",", 1)[0]
                if _PRECEDENCE.search(segment):
                    locally_protected = True
                    break
            if locally_protected:
                continue
            if _PRESENTATIONAL.search(normalized) and (not _ENACT.search(normalized)):
                continue
            start, end = match.span()
            found.append(
                {
                    "code": "agent_instruction_priority_spoof",
                    "source_path": path,
                    "start": start,
                    "end": end,
                    "excerpt": text[start:end],
                    "reason": "agent_directed_promotion_of_tool_origin_over_prior_directions",
                    "revision": REVISION,
                    "classification": "REVIEW_ONLY_NOT_AUTHORITY",
                    "creates_permissions": False,
                }
            )
    return found
