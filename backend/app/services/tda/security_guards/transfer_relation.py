"""P4: conservative explicit positive external-transfer relation evidence.

No cross-field URL association: require same-clause positive outbound predicate,
a source-data mention, and a directed external destination. A URL read from the
network is not an outbound exfiltration destination. Does not grant permissions.
"""

from __future__ import annotations
from app.services.tda.claim_context import (
    metadata_texts,
    reference_span,
    quotation_spans,
)
import re
from typing import Any

REVISION = "p4-directed-transfer-evidence-v6"
_SEND = re.compile(
    "\\b(?:send|sends|sent|sending|transmit|transmits|transmitted|upload|uploads|uploaded|uploading|forward|forwards|forwarded|post|posts|posted|copy|copies|copied|copying|transfer|transfers|transferred|transferring|exfiltrate|exfiltrates|exfiltrated|envoyer|envoie|transmettre|transmet|téléverser|téléverse)\\b",
    re.I,
)
_SENSITIVE = re.compile(
    "\\b(?:private|confidential|sensitive|secret|credentials?|passwords?|tokens?|keys?|account|customer|user|personal|financial|local)\\b.{0,95}\\b(?:data|files?|contents?|documents?|records?|secrets?|keys?|credentials?)\\b|\\b(?:data|files?|contents?|documents?|records?|secrets?|keys?|credentials?)\\b.{0,95}\\b(?:private|confidential|sensitive|secret|personal|financial)\\b",
    re.I,
)
_PAYLOAD_SENSITIVE = re.compile(
    "\\b(?:private|confidential|sensitive|secret|personal|financial|customer|user|local)\\b.{0,80}\\b(?:data|files?|contents?|documents?|reports?|records?|details?|source\\s+code|secrets?|keys?|credentials?)\\b|\\b(?:credentials?|passwords?|secrets?|tokens?|private\\s+keys?|API\\s+keys?)\\b|\\b(?:data|files?|contents?|documents?|reports?|records?)\\b.{0,80}\\b(?:private|confidential|sensitive)\\b",
    re.I,
)
_PAYLOAD_ANAPHORA = re.compile(
    "\\b(?:the|their|its|those|them|it|data|contents?|files?|records?)\\b", re.I
)
_EXTERNAL_TO = re.compile(
    "\\b(?:to|towards|into|vers|via)\\s+(?:(?:an?|the|a\\s+third-party)\\s+)?(?:https?://[^\\s,;]+|(?:external|remote|third-party|off-platform)\\b.{0,35}\\b(?:collector|webhook|endpoint|recipient|server|host)|(?:collector|webhook|endpoint|external\\s+recipient|remote\\s+recipient)\\b)",
    re.I,
)
_NEG_BEFORE = re.compile(
    "\\b(?:never|cannot|can't|does\\s+not|do\\s+not|did\\s+not|must\\s+not|doesn't|don't|won't|will\\s+not|should\\s+not|without|no)\\b(?:\\s+\\w+){0,4}\\s*$",
    re.I,
)
_DOC = re.compile(
    "\\b(?:document(?:ation)?|tutorial|example|quotation|explains?|describes?|mentions?|demonstrates?|forbidden|must\\s+not)\\b",
    re.I,
)
_CLAUSE = re.compile("[^;\\n]+")
_SUBCLAUSE = re.compile("\\b(?:but|however|yet|whereas)\\b", re.I)


def _pieces(text: str):
    for clause in _CLAUSE.finditer(text):
        begin = clause.start()
        for sentence in re.finditer(
            ".+?(?:(?<=[.!?])\\s+(?=[A-Z])|$)", clause.group(), re.S
        ):
            part = sentence.group()
            cursor = 0
            for sep in _SUBCLAUSE.finditer(part):
                if part[cursor : sep.start()].strip():
                    yield (
                        begin + sentence.start() + cursor,
                        part[cursor : sep.start()],
                    )
                cursor = sep.end()
            if part[cursor:].strip():
                yield (begin + sentence.start() + cursor, part[cursor:])


def positive_external_transfers(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    count = 0
    for path, raw in metadata_texts(snapshot):
        count += 1
        if count > 256:
            break
        raw = raw[:16000]
        for base, body in _pieces(raw):
            prose_only = re.sub("https?://[^\\s]+", " ", body, flags=re.I)
            if _DOC.search(prose_only) and re.search(
                "\\b(?:forbidden|example|explains?|describes?)\\b", prose_only, re.I
            ):
                continue
            for action in _SEND.finditer(body):
                if any((a <= action.start() < b for a, b in quotation_spans(body))):
                    continue
                if reference_span(body, action.start(), action.end()):
                    continue
                prefix = body[max(0, action.start() - 85) : action.start()]
                if _NEG_BEFORE.search(prefix):
                    continue
                if re.search("\\bno\\s+(?:\\w+\\s+){0,4}(?:is|are)\\s*$", prefix, re.I):
                    continue
                destination = _EXTERNAL_TO.search(body, action.end())
                if destination is None or destination.start() - action.end() > 145:
                    continue
                payload = body[action.end() : destination.start()]
                if re.search(
                    "\\bnon[- ]sensitive\\s+(?:data|files?|records?|contents?)\\b",
                    payload,
                    re.I,
                ):
                    continue
                if not _PAYLOAD_SENSITIVE.search(payload):
                    antecedent = body[max(0, action.start() - 105) : action.start()]
                    if not (
                        _SENSITIVE.search(antecedent)
                        and _PAYLOAD_ANAPHORA.search(payload)
                    ):
                        continue
                start = base + action.start()
                end = base + action.end()
                dstart = base + destination.start()
                dend = base + destination.end()
                out.append(
                    {
                        "source_path": path,
                        "action": "external_transfer",
                        "polarity": "POSITIVE",
                        "evidence": [
                            {
                                "source_path": path,
                                "start": start,
                                "end": end,
                                "excerpt": raw[start:end],
                                "role": "POSITIVE_SEND",
                            },
                            {
                                "source_path": path,
                                "start": dstart,
                                "end": dend,
                                "excerpt": raw[dstart:dend],
                                "role": "EXTERNAL_DESTINATION",
                            },
                        ],
                        "creates_permissions": False,
                    }
                )
                break
    return out
