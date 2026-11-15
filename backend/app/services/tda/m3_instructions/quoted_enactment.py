from __future__ import annotations
from app.services.tda.claim_context import metadata_texts
import re




_P3_DIRECTIVE = re.compile(
    "\\b(?:ignore|disregard|override)\\b.{0,45}\\b(?:previous|prior|earlier|system|developer|user)\\b.{0,45}\\b(?:instructions?|guidance|prompts?|rules?)\\b|\\b(?:disable|bypass|skip|remove)\\b.{0,40}\\b(?:safety|security|policy|checks?|guardrails?|protections?)\\b",
    re.I,
)
_P3_SEARCH = re.compile("\\b(?:search|find|locate|look\\s+up|retrieve)\\b", re.I)
_P3_FOLLOW = re.compile(
    "^\\s*(?:,?\\s*and\\s+)?then\\s+(?:follow|obey|execute|perform|apply)\\s+(?:that|this|the)\\s+(?:(?:quoted|exact)\\s+)?(?:phrase|instruction|command|text|message)\\b",
    re.I,
)
_P3_QUOTED_LITERAL = re.compile('"[^"\\n]{1,180}"|“[^”\\n]{1,180}”|«[^»\\n]{1,180}»')
_P3_ONLY_TRAILING_PUNCTUATION = re.compile("^\\s*[.!?]?\\s*$")


def _narrow_post_quote_enactment(snapshot: dict) -> list[dict]:
    result = []
    for path, raw in metadata_texts(snapshot):
        for quote in _P3_QUOTED_LITERAL.finditer(raw):
            body = quote.group()[1:-1]
            if not _P3_DIRECTIVE.search(body):
                continue
            prefix = raw[max(0, quote.start() - 100) : quote.start()]
            if not _P3_SEARCH.search(prefix):
                continue
            after = raw[quote.end() :]
            followed = _P3_FOLLOW.match(after)
            if not followed or not _P3_ONLY_TRAILING_PUNCTUATION.fullmatch(
                after[followed.end() :]
            ):
                continue
            start = quote.end() + followed.start()
            end = quote.end() + followed.end()
            evidence = [
                {
                    "source_path": path,
                    "start": quote.start(),
                    "end": quote.end(),
                    "excerpt": raw[quote.start() : quote.end()],
                    "role": "QUOTED_INSTRUCTION",
                },
                {
                    "source_path": path,
                    "start": start,
                    "end": end,
                    "excerpt": raw[start:end],
                    "role": "INSTRUCTION_TO_ENACT_QUOTE",
                },
            ]
            result.append(
                {
                    "code": "agent_enacts_quoted_instruction",
                    "proposition_id": "p3-narrow-relation",
                    "evidence": evidence,
                    "severity": "medium",
                    "claim": "Agent is explicitly instructed to enact the quoted instruction rather than return it as data.",
                }
            )
    return result


def instruction_concerns(extraction: dict) -> list[dict]:
    concerns = []
    for p in extraction["propositions"]:
        if p["quotation"] or p["speech_act"] in {
            "DOCUMENTARY",
            "PROTECTIVE_GUIDANCE",
            "USAGE_GUIDANCE",
        }:
            continue
        if p["actor"] != "AGENT" or p["addressee"] != "AGENT":
            continue
        reason = None
        if (
            p["concealment"] == "ACTION"
            and p.get("concealment_directive") != "FORBIDDEN"
        ):
            reason = "agent_conceals_action"
        elif p["speech_act"] == "ENACTMENT":
            reason = "agent_enacts_quoted_instruction"
        elif p["destination"] == "OTHER_TOOL":
            reason = "agent_cross_tool_dependency"
        elif p["action"] == "read" and p["object"] != "UNKNOWN":
            reason = "agent_precall_resource_access"
        if reason:
            concerns.append(
                {
                    "code": reason,
                    "proposition_id": p["id"],
                    "evidence": p["evidence"],
                    "severity": "high" if p["concealment"] == "ACTION" else "medium",
                    "claim": "instruction requires explicit review; not proof of unauthorized execution",
                }
            )
    return concerns
