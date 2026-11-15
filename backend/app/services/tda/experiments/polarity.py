"""Experimental clause-local polarity evidence, never an authorization source.

Provides hypotheses with exact source spans for a bounded EN/FR/ES grammar.
No alteration of Analyzer facts, decisions, contracts or tool permissions.
Not intended as general linguistic competence or independent qualification.
"""

from __future__ import annotations
from app.services.tda.security_guards.propositions import (
    DeterministicPropositionEngine,
    _ACTION,
)
import re
from typing import Any

REVISION = "clause-polarity-shadow-experiment-v1"
_EN_PRE = re.compile(
    "\\b(?:never|cannot|can\\s+not|should\\s+not|must\\s+not|do\\s+not|does\\s+not|did\\s+not|will\\s+not|won['’]t)\\b",
    re.I,
)
_ES_PRE = re.compile("\\b(?:no|nunca|jam[aá]s)\\b", re.I)
_FR_PRE = re.compile("\\bne\\b|(?<!\\w)n['’]", re.I)
_FR_POST = re.compile("\\b(?:pas|jamais|plus|point)\\b", re.I)
_NEG_COMPLEX = re.compile(
    "\\b(?:fail(?:s|ed|ing)?\\s+to|permit\\s+to|allow\\s+to|ask\\s+\\w+\\s+to|necessary\\s+to|necessarily)\\b",
    re.I,
)
_RESTRICTOR = re.compile(
    "\\b(?:not\\s+only|no\\s+solo|no\\s+solamente|no\\s+obstante)\\b", re.I
)
_CLAUSE_BREAK = re.compile("[;.!?\\n]|,\\s*(?:but|mais|pero)\\b", re.I)


def _word_count(text: str) -> int:
    return len(re.findall("\\b\\w+\\b", text))


def _pointer_value(snapshot: dict[str, Any], pointer: str) -> str:
    if not pointer.startswith("/"):
        raise ValueError("missing_json_pointer")
    node: Any = snapshot
    for token in pointer[1:].split("/"):
        key = token.replace("~1", "/").replace("~0", "~")
        node = node[int(key)] if isinstance(node, list) else node[key]
    if not isinstance(node, str):
        raise ValueError("source_span_not_text")
    return node


def _polarity_evidence(text: str, verb_start: int, verb_end: int) -> dict[str, Any]:
    before = text[:verb_start]
    after = text[verb_end:]
    prefix = _CLAUSE_BREAK.split(before)[-1]
    offset = len(before) - len(prefix)
    left_candidates = []

    def add_left(regex, kind):
        for m in regex.finditer(prefix):
            if _word_count(prefix[m.end() :]) <= 4:
                left_candidates.append(
                    (offset + m.start(), offset + m.end(), kind, m.group())
                )

    add_left(_EN_PRE, "EN_PRE")
    add_left(_ES_PRE, "ES_PRE")
    add_left(_FR_PRE, "FR_PRE")
    left_candidates.sort(reverse=True)
    for a, b, kind, word in left_candidates:
        between = text[b:verb_start]
        if _RESTRICTOR.search(text[a:verb_end]) or re.search(
            "\\b(?:not\\s+only|no\\s+solo)\\b", between, re.I
        ):
            continue
        if _NEG_COMPLEX.search(between):
            return {
                "polarity": "UNKNOWN",
                "reason": "intervening_verb_or_complex_negation_scope",
                "negators": [(a, b)],
                "confidence": "ABSTAIN",
            }
        if kind == "FR_PRE":
            before_post = [m for m in _FR_POST.finditer(between)]
            after_prefix = _CLAUSE_BREAK.split(after)[0]
            after_post = [
                m
                for m in _FR_POST.finditer(after_prefix)
                if _word_count(after_prefix[: m.start()]) <= 4
            ]
            if before_post:
                t = before_post[-1]
                return {
                    "polarity": "NEGATIVE",
                    "reason": "french_bipartite_negation",
                    "negators": [(a, b), (b + t.start(), b + t.end())],
                    "confidence": "BOUNDED_GRAMMAR",
                }
            if after_post:
                t = after_post[0]
                return {
                    "polarity": "NEGATIVE",
                    "reason": "french_bipartite_negation",
                    "negators": [(a, b), (verb_end + t.start(), verb_end + t.end())],
                    "confidence": "BOUNDED_GRAMMAR",
                }
            if re.search("\\bque\\b", after_prefix[:32], re.I):
                continue
            return {
                "polarity": "UNKNOWN",
                "reason": "french_ne_without_scoped_negator",
                "negators": [(a, b)],
                "confidence": "ABSTAIN",
            }
        if (
            kind == "ES_PRE"
            and word.lower() == "no"
            and re.search("\\b(?:solo|solamente|obstante)\\b", between, re.I)
        ):
            continue
        return {
            "polarity": "NEGATIVE",
            "reason": "local_preverbal_negator",
            "negators": [(a, b)],
            "confidence": "BOUNDED_GRAMMAR",
        }
    if re.search("\\bnot\\s+(?:necessarily|always)\\b", prefix, re.I):
        return {
            "polarity": "UNKNOWN",
            "reason": "qualified_negation_scope",
            "negators": [],
            "confidence": "ABSTAIN",
        }
    return {
        "polarity": "POSITIVE",
        "reason": "no_scoped_negation_in_supported_grammar",
        "negators": [],
        "confidence": "BOUNDED_GRAMMAR",
    }


class ClausePolarityShadowEngine:
    revision = REVISION

    def __init__(self):
        self.underlying = DeterministicPropositionEngine()

    def extract(self, snapshot: dict[str, Any]) -> dict[str, Any]:
        result = self.underlying.extract(snapshot)
        hypotheses = []
        for prop in result["propositions"]:
            pointer = prop["source_path"]
            original = _pointer_value(snapshot, pointer)
            start, end = (prop["start"], prop["end"])
            if original[start:end] != prop["excerpt"]:
                raise ValueError("original_evidence_span_mismatch")
            if (
                prop["quotation"]
                or not prop["operational"]
                or prop["action"] not in _ACTION
            ):
                hypotheses.append(
                    {
                        "proposition_id": prop["id"],
                        "source_path": pointer,
                        "polarity_hypothesis": "NOT_APPLICABLE",
                        "reason": "not_active_supported_operation",
                        "negator_evidence": [],
                    }
                )
                continue
            verb = _ACTION[prop["action"]].search(prop["excerpt"])
            if verb is None:
                hypotheses.append(
                    {
                        "proposition_id": prop["id"],
                        "source_path": pointer,
                        "polarity_hypothesis": "UNKNOWN",
                        "reason": "predicate_span_unavailable",
                        "negator_evidence": [],
                    }
                )
                continue
            local = _polarity_evidence(prop["excerpt"], verb.start(), verb.end())
            hypotheses.append(
                {
                    "proposition_id": prop["id"],
                    "source_path": pointer,
                    "polarity_hypothesis": local["polarity"],
                    "reason": local["reason"],
                    "scope": "CLAUSE_LOCAL_EXPERIMENT_NOT_AUTHORITY",
                    "predicate_evidence": {
                        "start": start + verb.start(),
                        "end": start + verb.end(),
                        "excerpt": original[start + verb.start() : start + verb.end()],
                    },
                    "negator_evidence": [
                        {
                            "start": start + a,
                            "end": start + b,
                            "excerpt": original[start + a : start + b],
                        }
                        for a, b in local["negators"]
                    ],
                }
            )
        return {
            "schema": "clause-polarity-shadow-v1",
            "engine": REVISION,
            "shadow_only": True,
            "creates_permissions": False,
            "base_engine": result["engine"],
            "base_propositions": result["propositions"],
            "base_omissions": result["omissions"],
            "polarity_hypotheses": hypotheses,
            "independent_semantic_completeness": "NOT_VERIFIED",
            "limitations": [
                "grammar-bounded EN/FR/ES",
                "action spans inherited from lexical extractor",
                "no implicit scope resolution",
                "never creates permission or decisions",
            ],
        }
