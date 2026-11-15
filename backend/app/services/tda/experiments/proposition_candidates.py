"""Research engines behind one extraction interface. No production model selection."""

from __future__ import annotations
from app.services.tda.security_guards.propositions import (
    DeterministicPropositionEngine,
    Proposition,
    _pointer,
)
import copy, re
from dataclasses import asdict

CANDIDATES = ("C0", "C1", "C2", "C3")
HYPOTHESES = {
    "AGENT": "instructions for the calling agent to perform an additional operation",
    "TOOL": "a description of an operation performed by the tool itself",
    "DOCUMENTARY": "a documentary quotation of an instruction without enacting it",
}
NLI_TEMPLATE = "This passage contains {}."
ASSISTANCE_THRESHOLD = 0.74


class MiniLMAssistedEngine:
    revision = "propositions-minilm-assistance-v1"

    def __init__(self, classifier):
        self.classifier = classifier

    def extract(self, snapshot):
        result = DeterministicPropositionEngine().extract(snapshot)
        result["engine"] = self.revision
        for p in result["propositions"]:
            if p["actor"] != "UNKNOWN" or not p["operational"] or p["quotation"]:
                continue
            out = self.classifier(
                p["excerpt"],
                list(HYPOTHESES.values()),
                multi_label=True,
                hypothesis_template=NLI_TEMPLATE,
            )
            scores = {
                key: float(dict(zip(out["labels"], out["scores"]))[label])
                for key, label in HYPOTHESES.items()
            }
            p["model_hypotheses"] = scores
            winner = max(scores, key=scores.get)
            if scores[winner] >= ASSISTANCE_THRESHOLD:
                p["model_actor_hypothesis"] = winner
                p["actor_prediction"] = (
                    winner if winner in {"AGENT", "TOOL"} else "UNKNOWN"
                )
                p["addressee_prediction"] = "AGENT" if winner == "AGENT" else "UNKNOWN"
                p["prediction_basis"] = "MODEL_HYPOTHESIS_NOT_OBSERVED_FACT"
                p["uncertainty"] = list(p["uncertainty"]) + [
                    "model_actor_hypothesis_requires_review"
                ]
        return result


class LexicalExpansionEngine:
    """Deliberately weak independent baseline; no discourse/role guarantees."""

    revision = "propositions-expanded-lexical-baseline-v1"

    def extract(self, snapshot):
        fields = []
        props = []
        texts = []
        todo = [("", snapshot, 0)]
        visited = 0
        chars = 0
        omissions = []
        seen = set()
        while todo and visited < 16384:
            pointer, value, depth = todo.pop()
            visited += 1
            if depth > 48:
                omissions.append({"source_path": pointer, "reason": "depth_budget"})
                continue
            if isinstance(value, (dict, list)):
                if id(value) in seen:
                    omissions.append(
                        {"source_path": pointer, "reason": "shared_or_cyclic_container"}
                    )
                    continue
                seen.add(id(value))
                from itertools import islice

                children = (
                    value.items() if isinstance(value, dict) else enumerate(value)
                )
                available = max(0, 16384 - visited - len(todo))
                if len(value) > available:
                    omissions.append({"source_path": pointer, "reason": "node_budget"})
                todo.extend(
                    (
                        (_pointer(pointer, k), v, depth + 1)
                        for k, v in islice(children, available)
                    )
                )
            elif isinstance(value, str):
                n = min(len(value), 16000, max(0, 64000 - chars))
                chars += n
                texts.append((pointer, value[:n]))
                if n < len(value):
                    omissions.append(
                        {"source_path": pointer, "reason": "character_budget"}
                    )
        if todo:
            omissions.append({"source_path": "", "reason": "node_budget"})
        for pointer, text in texts:
            fields.append({"source_path": pointer, "retained_chars": len(text)})
            collect = re.search(
                "\\b(?:read|collect|retrieve|fetch|obtain|gather)\\w*\\b", text, re.I
            )
            transfer = re.search(
                "\\b(?:send|pass|relay|attach|include|put|forward)\\w*\\b", text, re.I
            )
            conceal = re.search(
                "\\b(?:do not tell|never mention|hide|conceal|quietly|secretly|keep.+hidden)\\b",
                text,
                re.I,
            )
            if not collect and (not transfer):
                continue
            p = Proposition(
                f"p{len(props)}",
                pointer,
                0,
                len(text),
                text,
                "AGENT" if collect and transfer and conceal else "UNKNOWN",
                "AGENT" if collect and transfer and conceal else "UNKNOWN",
                "INSTRUCTION" if conceal else "UNKNOWN",
                "send" if transfer else "read",
                "UNKNOWN",
                "UNKNOWN",
                None,
                "POSITIVE",
                False,
                "ACTION" if conceal else "NONE",
                "UNRESOLVED",
                "PARTIAL",
                ("lexical_baseline_unresolved_roles",),
                "LEXICAL_HYPOTHESIS",
                (
                    {
                        "source_path": pointer,
                        "start": 0,
                        "end": len(text),
                        "excerpt": text,
                    },
                ),
                True,
            )
            props.append(asdict(p))
        return {
            "schema": "tool-propositions-v1",
            "engine": self.revision,
            "shadow_only": True,
            "creates_permissions": False,
            "fields": fields,
            "propositions": props,
            "omissions": omissions,
            "coverage": {
                "proposition_discovery": {"complete": None, "status": "NOT_VERIFIED"}
            },
            "limitations": [
                "expanded keyword baseline; no semantic completeness or source grammar guarantee"
            ],
        }


def effect_pairs(extraction):
    pairs = set()
    for p in extraction["propositions"]:
        if p["actor"] != "TOOL" or p["quotation"] or p["polarity"] == "NEGATIVE":
            continue
        if p["action"] not in {"read", "search", "send", "delete", "execute"}:
            continue
        obj = p["object"].casefold()
        resource = (
            "filesystem"
            if re.search("file|fichier|archivo|[/\\\\]", obj)
            else "document"
            if re.search("report|document|rapport|informe|note", obj)
            else None
        )
        if resource:
            pairs.add((p["action"], resource))
    return sorted(pairs)
