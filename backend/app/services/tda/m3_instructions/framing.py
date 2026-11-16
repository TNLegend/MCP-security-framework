"""M3-local scope and framing; NEVER change shared V0 claim_context.

A protective clause modifies the interpretation of evidence; it does not
erase source spans. A documentary word in another sentence is not a governor.
Uncertain language/recipient cannot be promoted into a confirmed directive.
"""
from __future__ import annotations
import re
from app.services.tda.claim_context import claim_mode

ENACT_QUOTE=re.compile(
    r"\b(?:then|and|now|after\s+that)\s+(?:follow|obey|execute|perform|apply|"
    r"comply\s+with|act\s+on)\b"
    r"|\b(?:do\s+exactly\s+what\s+it\s+says|"
    r"follow\s+that\s+instruction|"
    r"comply\s+with\s+it|act\s+on\s+it)\b",re.I)
PSEUDO_NEGATION=re.compile(
    r"\b(?:do\s+not\s+hesitate\s+to|never\s+fail\s+to|"
    r"do\s+not\s+forget\s+to|don't\s+forget\s+to)\s*$",re.I)
COMPARATIVE=re.compile(
    r"\b(?:rather\s+than|instead\s+of)\s+(?:asking|telling|consulting|"
    r"informing)\s+(?:the\s+)?(?:user|assistant|agent)"
    r"(?:\s+to)?\s*$",re.I)
DOC_GOVERNOR=re.compile(
    r"\b(?:detects?|flags?|prevents?|quotes?|documents?|describes?|"
    r"explains?|search(?:es)?\s+for|matches?|recognizes?)\s+"
    r"(?:attempts?\s+to\s+|an?\s+(?:example|attack|attempt)\s+(?:to\s+|of\s+)?"
    r"|a\s+quoted\s+(?:phrase|instruction)\s+|"
    r"(?:the\s+)?(?:literal|quoted)\s+(?:phrase|text)\s+)?$",re.I)

def local_clause_prefix(text: str, start: int) -> str:
    boundary=max(text.rfind(ch,0,start) for ch in ".;!?\n")
    return text[boundary+1:start]

def source_frame(text: str, start: int, end: int) -> str:
    """Return INSTRUCTION, NEGATED_CONTEXT, DOCUMENTARY, or HYPOTHETICAL.

    This is only a linguistic interpretation; even INSTRUCTION does not imply
    trust, policy authority, or a production BLOCK.
    """
    prefix=local_clause_prefix(text,start)
    mode=claim_mode(text,start,end)
    follow=text[end:min(len(text),end+200)]
    enact=bool(ENACT_QUOTE.search(follow))
    if PSEUDO_NEGATION.search(prefix) or COMPARATIVE.search(prefix):
        return "INSTRUCTION"
    if mode=="QUOTED":
        return "INSTRUCTION" if enact else "DOCUMENTARY"
    if mode=="NEGATED":
        return "NEGATED_CONTEXT"
    if mode=="HYPOTHETICAL":
        return "HYPOTHETICAL"
    if DOC_GOVERNOR.search(prefix) and not enact:
        return "DOCUMENTARY"
    return "INSTRUCTION"

def derived_source_frame(raw: str, start: int, end: int) -> str:
    """Assess *only* the clause governing the encoded M2 token.

    A separate previous sentence like 'Security example.' is not an
    exemption. Token provenance is separate from directive maliciousness.
    """
    prefix=local_clause_prefix(raw,start)
    following=raw[end:min(len(raw),end+160)]
    enacted=bool(ENACT_QUOTE.search(following))
    if re.search(
        r"\b(?:never|do\s+not|don't)\s+(?:execute|obey|follow|run)\b"
        r"|\b(?:display\s+(?:it\s+)?only\s+as\s+an?\s+example|"
        r"security\s+example\s*:)\s*$",prefix,re.I) and not enacted:
        return "DOCUMENTARY"
    return "INSTRUCTION"
