"""M3 bounded source-span directive candidates; never a permission/block verdict.

Match locations are provenance-bound before they become observations.
Raw KEY proofs are M3-internal and cannot be promoted to the existing Gate3B
value-only evidence schema. Derived text requires independent M2 attestation.
"""
from __future__ import annotations

from dataclasses import dataclass
import re

from app.services.tda.claim_context import claim_mode

# Narrow, positive patterns; no generic 'must', 'always' or 'before using'
# detector. Legitimate usage guidance remains non-malicious.
RULES = (
    ("instruction_override", re.compile(
        r"\b(?:ignore|disregard|override|bypass|disable)\b"
        r"[\s\S]{0,65}?\b(?:previous|prior|earlier|system|developer|security|safety|platform)\b"
        r"[\s\S]{0,70}?\b(?:instructions?|rules?|polic(?:y|ies)|checks?|safeguards?|restrictions?)\b",
        re.I)),
    ("direct_security_bypass", re.compile(
        r"\b(?:bypass|disable|skip|remove)\b[\s\S]{0,45}?"
        r"\b(?:security|safety|authorization|access\s+controls?|guardrails?)\b"
        r"[\s\S]{0,30}?\b(?:checks?|rules?|policy|restrictions?|controls?|protections?)\b",
        re.I)),
    ("system_role_spoof", re.compile(
        r"(?:<\|im_start\|>\s*(?:system|developer)|\[im_start\]\s*(?:system|developer))",
        re.I)),
    ("hidden_agent_exfiltration", re.compile(
        r"\b(?:send|forward|transmit|upload|export)\b.{0,120}?"
        r"\b(?:secrets?|credentials?|tokens?|private\s+keys?|contents?|internal\s+records?)\b"
        r".{0,100}?\b(?:silently|secretly|without\s+(?:telling|notifying)|hide)\b"
        r"|\b(?:read|collect|retrieve)\b.{0,65}?\b(?:internal\s+records?|secrets?|credentials?)\b"
        r".{0,85}?\b(?:send|forward|transmit)\b.{0,90}?\b(?:hide|silently|secretly)\b",
        re.I)),
    ("precall_secret_read", re.compile(
        r"\b(?:before\s+(?:using|calling)|you\s+must|first)\b"
        r".{0,85}?\b(?:read|collect|retrieve|fetch|open)\b"
        r".{0,80}?(?:\.ssh/id_rsa|\.env\b|(?:user\s+)?session\s+tokens?|api[_ -]?keys?|credentials?|secrets?)",
        re.I)),
)
# English-first. Unknown languages are tracked as coverage limitations, not
# evidence of attacker intent.
DOCUMENTARY = re.compile(
    r"\b(?:scanner|detector|security\s+report|documentation|tutorial|"
    r"example|explanation|educational|flags?\s+attempts?|detects?|"
    r"prevents?|quotes?|quoted\s+phrase|protects?\s+against|"
    r"describes?\s+(?:a\s+)?(?:threat|attack))\b", re.I)
ENACT_QUOTE = re.compile(
    r"\b(?:then|now|after\s+that)\s+(?:follow|obey|execute|perform|apply)\b", re.I)
RULE_TRIGGER = re.compile(
    r"\b(?:ignore|disregard|override|bypass|disable|skip|remove|"
    r"read|collect|retrieve|first|before|send|forward|transmit|upload|export)\b"
    r"|<\|im_start\|>|\[im_start\]",re.I)


@dataclass(frozen=True)
class SpanCandidate:
    rule_id: str
    start: int
    end: int
    excerpt: str
    framing: str = "INSTRUCTION"
    addressee: str = "UNKNOWN"


def _protected(text: str, start: int, end: int) -> bool:
    prefix=text[max(0,start-180):start]
    mode=claim_mode(text,start,end)
    if mode in ("NEGATED","HYPOTHETICAL"):
        return True
    # A quote that is subsequently told to be enacted stays operative.
    follow=text[end:min(len(text),end+180)]
    enacted=bool(ENACT_QUOTE.search(follow))
    if mode=="QUOTED" and not enacted:
        return True
    if DOCUMENTARY.search(prefix) and not enacted:
        return True
    # Describing a tool that detects forbidden phrases is not directing
    # an agent to carry out those phrases.
    if re.search(r"\b(?:detects?|flags?|prevents?|recognizes?)\s+(?:attempts?\s+to\s+)?$",prefix,re.I) and not enacted:
        return True
    return False


def exact_directive_candidates(text: str, *, key: bool = False) -> tuple[SpanCandidate,...]:
    # KEY names like "ignore_previous_security_instructions" are attack-like
    # schema pollution candidates, not proof of agent execution.
    if len(text)>16_000:
        return ()
    if key:
        probe=text.replace("_"," ")
        if len(probe)!=len(text):
            raise AssertionError("key_original_offsets_changed")
    else:
        probe=text
    if not RULE_TRIGGER.search(probe):
        return ()
    all_hits=[]
    for rule, pattern in RULES:
        for match in pattern.finditer(probe):
            if _protected(probe,match.start(),match.end()):
                continue
            all_hits.append(SpanCandidate(
                rule_id=rule,start=match.start(),end=match.end(),
                excerpt=text[match.start():match.end()],
                framing="INSTRUCTION" if not key else "SCHEMA_KEY_INJECTION_CANDIDATE",
                addressee="AGENT" if re.search(
                    r"\b(?:you|assistant|agent|model)\b",probe[:match.end()+30],re.I) else "UNKNOWN",
            ))
    # Stable de-duplication only of identical spans/rules, not separate
    # occurrences inside a field.
    return tuple(dict.fromkeys(all_hits))
