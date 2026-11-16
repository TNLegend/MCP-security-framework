"""M3 bounded source-span directive candidates; never a permission/block verdict.

Match locations are provenance-bound before they become observations.
Raw KEY proofs are M3-internal and cannot be promoted to the existing Gate3B
value-only evidence schema. Derived text requires independent M2 attestation.
"""
from __future__ import annotations

from dataclasses import dataclass
import re

from app.services.tda.m3_instructions.framing import source_frame

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
# A documentary word somewhere *nearby* is NOT an exemption. Only a
# grammatical governor in the same clause can classify the rule match as
# merely described/quoted. The quote matcher in claim_context remains intact.
DOCUMENTARY_GOVERNOR = re.compile(
    r"\b(?:detects?|flags?|prevents?|quotes?|documents?|describes?|"
    r"explains?|search(?:es)?\s+for|matches?)\s+"
    r"(?:attempts?\s+to\s+|an?\s+(?:example|attack|attempt)\s+(?:to\s+|of\s+)?"
    r"|a\s+quoted\s+(?:phrase|instruction)\s+|"
    r"(?:the\s+)?(?:literal|quoted)\s+(?:phrase|text)\s+)?$",re.I)
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
            frame=source_frame(probe,match.start(),match.end())
            all_hits.append(SpanCandidate(
                rule_id=rule,start=match.start(),end=match.end(),
                excerpt=text[match.start():match.end()],
                framing=frame if not key else "SCHEMA_KEY_INJECTION_CANDIDATE",
                addressee="AGENT" if re.search(
                    r"\b(?:you|assistant|agent|model)\b",probe[:match.end()+30],re.I) else "UNKNOWN",
            ))
    # Stable de-duplication only of identical spans/rules, not separate
    # occurrences inside a field.
    return tuple(dict.fromkeys(all_hits))
