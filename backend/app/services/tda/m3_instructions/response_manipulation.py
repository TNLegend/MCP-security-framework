"""M3 source-bound response-redirection candidates over existing Propositions.

A tool describing its capability or user-requested formatting is not sufficient
evidence. We require an *operative instruction* joined to a response target,
unrequested recommendation, or unsupported source/authority assertion.

The original Proposition extractor supplies local segments, polarity and
provenance; this module adds bounded relations, not a duplicate ontology.
No model, tool execution, BLOCK, cross-tool trust or other-module imports.
"""
from __future__ import annotations

from dataclasses import dataclass
import re

from app.services.tda.claim_context import quotation_spans
from app.services.tda.m3_instructions.framing import source_frame
from app.services.tda.security_guards.propositions import extract_propositions
from app.services.tda.m3_instructions.span_rules import SpanCandidate

MAX_INPUT_CHARS=16000
MAX_RELATION_CHARS=250

# Only directive verbs; general words like "source", "warning", "recommended"
# or "response" do not independently indicate an injection.
ACTION = re.compile(
    r"\b(?:include|insert|append|attach|add|put|print|state|say|claim|"
    r"present|describe|label|recommend|suggest|advise|warn)\b",re.I)
ANSWER = re.compile(
    r"\b(?:final|your|the|user-facing)\s+(?:answer|response|message|output)\b"
    r"|\b(?:answer|respond|response)\s+(?:to|for)\s+the\s+user\b",re.I)
RESPONSE_INSERT = re.compile(
    r"\b(?:include|insert|append|attach|add|put|print)\b",re.I)
EXACT_CONTENT = re.compile(
    r"\b(?:exact|specific|literal|marker|sentence|phrase|token|string|"
    r"secret|password|quote|quoted)\b",re.I)
RECOMMEND = re.compile(r"\b(?:recommend|suggest|advise)\b",re.I)
PACKAGE = re.compile(r"\b(?:install(?:ing)?|packages?|plugins?|libraries?|tools?|products?)\b",re.I)
UNSOLICITED = re.compile(
    r"\b(?:even\s+if\s+(?:the\s+)?user\s+(?:did\s+not|does\s+not)|regardless\s+of\s+(?:the\s+)?user(?:\x27s|\s+)?\s+question|without\s+(?:being\s+)?asked|"
    r"not\s+(?:ask(?:ed)?|request(?:ed)?)|did\s+not\s+ask|"
    r"without\s+(?:an?\s+)?(?:explicit\s+)?user\s+request|"
    r"whether\s+or\s+not\s+(?:the\s+)?user\s+(?:asked|requested))\b",re.I)
RELIABILITY = re.compile(
    r"\b(?:verified|authoritative|authenticated|certified|fully\s+trusted|"
    r"most\s+reliable|most\s+trusted|trusted\s+over|"
    r"prefer(?:red)?\s+over|outranks?)\b",re.I)
RELIABILITY_QUALIFIER = re.compile(
    r"\b(?:even\s+if|although|despite|without\s+verification|"
    r"unverified|ordinary\s+data|despite\s+(?:lacking|missing)\s+verification|over\s+other\s+sources|"
    r"rather\s+than\s+other\s+sources)\b",re.I)
DOCUMENTARY_ACTION_GOVERNOR = re.compile(
    r"\b(?:documentation|tutorial|example|report|scanner|detector)\s+"
    r"(?:describes?|explains?|illustrates?|shows?|flags?|detects?)\s+"
    r"(?:how\s+(?:an?\s+)?(?:attacker|adversary|malicious\s+user)\s+"
    r"(?:may|might|can|could)\s+|attempts?\s+to\s+|examples?\s+of\s+)?$",
    re.I)
AGENT_ANCHOR = re.compile(
    r"\b(?:you|your\s+assistant|assistant|agent|to\s+the\s+user|"
    r"when\s+(?:answering\b|this\s+tool\s+is\s+(?:used|called)|"
    r"using\s+this\s+tool|answering\s+the\s+user|"
    r"presenting\s+information\s+from\s+this\s+tool)|"
    r"final\s+(?:answer|response|message)|"
    r"user-facing\s+(?:answer|response|message))\b",re.I)
TRUST_PRESSURE = re.compile(
    r"\b(?:ignoring|disregarding|not\s+using)\b.{0,85}?"
    r"\b(?:tool(?:'s)?\s+(?:output|result)|this\s+tool)\b"
    r".{0,80}?\b(?:unsafe|incorrect|unreliable|dangerous|wrong)\b",re.I)

@dataclass(frozen=True)
class ResponseCandidate:
    span: SpanCandidate
    proposition_id: str
    action: str
    target: str
    uncertainty_reasons: tuple[str,...] = ()
    directive_eligible: bool = False


def _end_of_statement(raw: str, begin: int) -> int:
    """Honor punctuation inside quoted content, and never cross paragraphs."""
    quotes=quotation_spans(raw)
    end=min(len(raw),begin+MAX_RELATION_CHARS)
    for i in range(begin,end):
        if any(a<=i<b for a,b in quotes):
            continue
        if raw[i] in ".;!?\n":
            return i
    return end


def _classify(raw: str, start: int, end: int):
    chunk=raw[start:end]
    prefix=raw[max(0,start-150):start]
    # The qualifying 'when answering...' may be in the preceding segment;
    # an unrelated previous sentence cannot supply a target.
    governing_prefix=re.split(r"[.;!?\n]",prefix)[-1]
    joined=governing_prefix+" "+chunk
    if RESPONSE_INSERT.match(chunk):
        if ANSWER.search(joined) and (EXACT_CONTENT.search(joined) or
                                       "final answer" in joined.lower()):
            return ("response_content_insertion","compose","FINAL_ANSWER",())
    if RECOMMEND.match(chunk):
        if PACKAGE.search(joined) and UNSOLICITED.search(joined):
            return ("response_unsolicited_recommendation","recommend","USER_RECOMMENDATION",())
    if re.match(r"(?:state|say|claim|present|describe|label)\b",chunk,re.I):
        if RELIABILITY.search(joined) and RELIABILITY_QUALIFIER.search(joined):
            return ("response_source_reliability_spoof","claim","SOURCE_RELIABILITY",())
        if RELIABILITY.search(joined) and re.search(r"\b(?:this\s+tool|(?:other\s+)?sources?)\b",joined,re.I) and re.search(
            r"\b(?:most\s+reliable|most\s+trusted|trusted\s+over|outranks?)\b",joined,re.I):
            return ("response_source_priority_spoof","claim","SOURCE_PRIORITY",())
    if re.match(r"warn\b",chunk,re.I):
        if TRUST_PRESSURE.search(joined):
            return ("response_trust_pressure_uncertain","warn","USER_TRUST",
                    ("CONTEXT_REQUIRED_TO_VALIDATE_WARNING",))
    return None


def response_directive_candidates(raw: str) -> tuple[ResponseCandidate,...]:
    """Conservative exact-source observations with Proposition IDs.

    A negation or documentary quotation must govern the *same* proposition,
    not appear somewhere in the previous 180 characters. Never use a source
    string or marker value as the sole signal.
    """
    if len(raw)>MAX_INPUT_CHARS:
        return ()
    matches=list(ACTION.finditer(raw))
    if not matches:return ()
    # Explicitly fail the shadow pipeline (which records ERROR) rather than
    # silently truncating a pathological text with hundreds of imperatives.
    if len(matches)>64:
        raise ValueError("M3_RESPONSE_ACTION_BUDGET")
    candidates=[]
    found=set()
    for action in matches:
        begin=action.start()
        # Reuse the original Proposition semantics on a bounded *source
        # window*, never the entire 16k field. Original offsets are recovered
        # from 'window_start'. The local window is only an anchor; framing
        # decisions and evidence spans always use the full ORIGINAL string.
        window_start=max(0,begin-170)
        window_end=min(len(raw),action.end()+260)
        chunk=raw[window_start:window_end]
        extraction=extract_propositions({"description":chunk})
        if extraction.get("omissions"):
            raise ValueError("M3_RESPONSE_PROPOSITION_WINDOW_INCOMPLETE")
        relative=begin-window_start
        prop=next((
            p for p in extraction["propositions"]
            if (p["source_path"]=="/description"
                and p["start"]<=relative<p["end"])
        ),None)
        if prop is None or prop["quotation"]:
            continue
        # Proposition-level polarity may reflect a later qualifier such as
        # "without a user request". The negation must govern the ACTION,
        # checked below against its original local prefix, not the whole span.
        # A preceding sentence cannot exempt an unrelated later imperative.
        same_sentence=raw[max(0,max(raw.rfind(c,0,begin)
                      for c in ".;!?\n")+1):begin]
        local_frame=source_frame(raw,begin,begin+len(action.group()))
        if DOCUMENTARY_ACTION_GOVERNOR.search(same_sentence):
            local_frame="DOCUMENTARY"
        stop=_end_of_statement(raw,begin)
        if stop<=begin:
            continue
        classified=_classify(raw,begin,stop)
        if classified is None:
            continue
        rule,verb,target,uncertainty=classified
        key=(rule,begin,stop)
        if key in found:
            continue
        found.add(key)
        # An unanchored expression may describe tool output or formatting.
        # Keep it as a candidate, never an established agent directive.
        context=same_sentence+" "+raw[begin:stop]
        anchor=bool(AGENT_ANCHOR.search(context)) and local_frame=="INSTRUCTION"
        candidates.append(ResponseCandidate(
            span=SpanCandidate(rule_id=rule,start=begin,end=stop,
                excerpt=raw[begin:stop],
                framing=(local_frame if local_frame!="INSTRUCTION" else
                         ("CONTEXT_DEPENDENT" if uncertainty or not anchor
                          else "INSTRUCTION")),
                addressee="AGENT_OR_ASSISTANT_INFERRED" if anchor else "UNKNOWN"),
            proposition_id=prop["id"]+"@"+str(window_start),
            action=verb,target=target,
            uncertainty_reasons=uncertainty if anchor else
                tuple((*uncertainty,"AGENT_ADDRESSEE_UNVERIFIED")),
            directive_eligible=anchor,
        ))
    return tuple(candidates)
