from __future__ import annotations
import re
from app.services.tda.claim_context import reference_span, comparative_span

_EXAMPLE_TAG_RE = re.compile(
    "<(?:example|examples)\\b[^>]*>.*?</(?:example|examples)\\s*>",
    re.IGNORECASE | re.DOTALL,
)


_MARKDOWN_HEADING_RE = re.compile("^\\s*(#{1,6})\\s+(.+?)\\s*$")


_EXAMPLE_HEADING_RE = re.compile(
    "^(?:examples?|samples?|usage\\s+examples?|example\\s+usage)\\b", re.IGNORECASE
)


def strip_documentation_examples(value: str | None) -> str:
    """Remove clearly marked documentation examples from operational semantic text.

    Examples remain available to deterministic metadata checks elsewhere; they simply
    cannot become evidence that the tool itself performs the example's actions.
    """
    text = str(value or "")
    if not text:
        return ""
    text = _EXAMPLE_TAG_RE.sub(" ", text)
    output: list[str] = []
    skipped_heading_level: int | None = None
    for line in text.splitlines():
        heading = _MARKDOWN_HEADING_RE.match(line)
        if heading is not None:
            level = len(heading.group(1))
            title = heading.group(2).strip().rstrip(":")
            if skipped_heading_level is not None:
                if level <= skipped_heading_level:
                    skipped_heading_level = None
                else:
                    continue
            if _EXAMPLE_HEADING_RE.match(title):
                skipped_heading_level = level
                continue
        if skipped_heading_level is None:
            output.append(line)
    return "\n".join(output)


def operational_pattern_search(pattern: str, text: str) -> re.Match[str] | None:
    import re

    for match in re.finditer(pattern, text, re.IGNORECASE):
        if not _match_is_non_operational(text, match):
            return match
    return None


def _match_is_non_operational(text: str, match: re.Match[str]) -> bool:
    import re

    if reference_span(text, match.start(), match.end()) or comparative_span(
        text, match.start(), match.end()
    ):
        return True
    before = re.split("[.;!?\\n]", text[max(0, match.start() - 120) : match.start()])[
        -1
    ]
    connector = re.search(
        "\\b(?P<link>and|et|but|mais|then|puis|ensuite|while|whereas|yet|however|alors\\s+que|pendant\\s+que)(?:\\s+(?:the\\s+)?(?:tool|service|it|elle|il))?\\s*$",
        before,
        re.IGNORECASE,
    )
    if connector is not None:
        link = connector.group("link").lower()
        verb = match.group(0).strip().lower().split()[0]
        finite_second_action = bool(
            re.fullmatch("[a-z]{2,}(?:s|ies)", verb, re.IGNORECASE)
            and verb not in {"access", "process", "status", "address", "cross"}
            or re.fullmatch(
                "(?:supprime|suppriment|modifie|modifient|envoie|envoient|écrit|écrivent)",
                verb,
                re.IGNORECASE,
            )
        )
        documentary_prefix = bool(
            re.search(
                "\\b(?:documentation|docs?|guides?|manuals?|manuels?|examples?|samples?|reports?|articles?|tutorials?)\\b.{0,100}\\b(?:about|on|regarding|concerning|explaining|describing|documenting|how\\s+to|sur|concernant|expliquant)\\b",
                before,
                re.IGNORECASE,
            )
        )
        if link not in {"and", "et"} or finite_second_action or documentary_prefix:
            before = before[connector.end() :]
    after = text[match.end() : min(len(text), match.end() + 50)]
    immediate_before = before[-48:]
    if re.search("\\bnot\\s*$", immediate_before, re.IGNORECASE):
        return True
    matched_text = match.group(0)
    if (
        re.search(
            "\\b(?:explain|describe|discuss)\\s+why\\s*$",
            immediate_before,
            re.IGNORECASE,
        )
        and re.search(
            "\\b(?:unsafe|risky|dangerous|insecure)\\b",
            matched_text + after[:80],
            re.IGNORECASE,
        )
        and re.search(
            "\\b(?:without|never|does\\s+not|do\\s+not)\\b.{0,60}\\b(?:collect|request|capture|expose|return)\\w*",
            matched_text + after[:80],
            re.IGNORECASE,
        )
    ):
        return True
    if re.search(
        "\\b(?:without|never|cannot|not|do\\s+not|does\\s+not|must\\s+not)\\s+(?:\\w+\\s+){0,3}$",
        immediate_before,
        re.IGNORECASE,
    ) and re.match(
        "(?:collect|request|ask|capture|extract|expose|steal|send|upload)\\w*\\b",
        matched_text,
        re.IGNORECASE,
    ):
        return True
    if re.search(
        "\\b(?:without|sans)\\b.{0,35}\\b(?:execut(?:e|es|ed|ing)|run(?:s|ning)?|launch(?:es|ed|ing)?|exécut(?:er|e|es|ent|é|ée|és|ées)|lanc(?:er|e|es|ent|é|ée|és|ées))\\b",
        matched_text,
        re.IGNORECASE,
    ):
        return True
    if re.search("\\bne\\s*$", immediate_before, re.IGNORECASE) and re.search(
        "\\b(?:pas|jamais|plus)\\b", matched_text, re.IGNORECASE
    ):
        return True
    if re.search(
        "\\b(?:not|never|pas|jamais)\\b.{0,25}\\b(?:execut(?:e|es|ed|ing)|run(?:s|ning)?|launch(?:es|ed|ing)?|exécut(?:er|e|es|ent|é|ée|és|ées)|lanc(?:er|e|es|ent|é|ée|és|ées))\\b",
        matched_text,
        re.IGNORECASE,
    ):
        return True
    if re.search(
        "(?:\\b(?:does|do|did|is|are|was|were|will|would|can|could|should|must)\\s+not|\\b(?:never|without)\\b|\\b(?:doesn't|don't|didn't|isn't|aren't|wasn't|weren't|won't|wouldn't|can't|couldn't|shouldn't|mustn't)\\b)(?:\\s+\\w+){0,3}\\s*$",
        immediate_before,
        re.IGNORECASE,
    ):
        return True
    if re.search(
        "\\bne\\s+(?:(?:\\w+)\\s+){0,3}(?:pas|jamais|plus)(?:\\s+(?:de|d['’]|à))?\\s*$",
        immediate_before,
        re.IGNORECASE,
    ):
        return True
    if re.search(
        "\\bne\\s+(?:\\w+\\s+){0,3}$", immediate_before, re.IGNORECASE
    ) and re.match("(?:\\s+\\w+){0,3}\\s+(?:pas|jamais|plus)\\b", after, re.IGNORECASE):
        return True
    if re.search(
        "\\bn['’][a-zà-ÿ]+(?:\\s+[a-zà-ÿ]+){0,3}\\s+(?:pas|jamais|plus)(?:\\s+(?:de|d['’]|à))?\\s*$",
        immediate_before,
        re.IGNORECASE,
    ):
        return True
    if re.search(
        "\\bn['’][a-zà-ÿ]+.{0,50}\\b(?:pas|jamais|plus)\\b.{0,50}$",
        before,
        re.IGNORECASE,
    ):
        return True
    if re.search("\\bn['’]\\s*$", immediate_before, re.IGNORECASE):
        french_tail = text[match.start() : min(len(text), match.end() + 40)]
        if re.search("\\b(?:pas|jamais|plus)\\b", french_tail, re.IGNORECASE):
            return True
    if re.search(
        "\\bsans(?:\\s+jamais)?(?:\\s+\\w+){0,3}\\s*$", immediate_before, re.IGNORECASE
    ):
        return True
    sentence_before = re.split("[.!?\\n]", before)[-1]
    if re.search(
        "\\b(?:documentation|docs?|guides?|manuals?|manuels?|examples?|samples?|reports?|articles?|tutorials?)\\b.{0,80}\\b(?:about|on|regarding|concerning|explaining|describing|documenting|how\\s+to|for|sur|concernant|expliquant|décrivant|comment)\\b.{0,80}$",
        sentence_before,
        re.IGNORECASE,
    ):
        return True
    if re.search(
        "\\b(?:documentation|docs?|guides?|manuals?|manuels?|examples?|samples?|reports?|articles?|tutorials?)\\b.{0,80}\\b(?:contains?|mentions?|quotes?|references?|includes?|contient|contiennent|mentionne|mentionnent|cite|citent|inclut|incluent)\\b.{0,80}(?:\\b(?:phrase|term|word|expression|terme|mot)\\b.{0,30})?$",
        sentence_before,
        re.IGNORECASE,
    ):
        return True
    return False
