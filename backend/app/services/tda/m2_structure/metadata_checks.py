from __future__ import annotations
from app.services.tda.types import AnalysisFinding
from app.services.tda.m2_structure.views import suspicious_invisible_at
from app.services.tda.findings import _finding
from app.services.tda.configuration import (
    INVISIBLE_RE,
    BIDI_RE,
    HTML_COMMENT_RE,
    FINDING_DECISION_BLOCK,
    FINDING_DECISION_REVIEW,
)
import re


def metadata_shape_findings(
    source: str, raw_text: str, text: str
) -> list[AnalysisFinding]:
    findings = []
    if any(suspicious_invisible_at(raw_text, m.start()) for m in INVISIBLE_RE.finditer(raw_text)):
        findings.append(
            _finding(
                "unicode_invisible_text",
                "obfuscation",
                source,
                "high",
                92,
                "invisible unicode character detected",
                "Remove invisible characters from tool metadata.",
                decision=FINDING_DECISION_BLOCK,
            )
        )
    if BIDI_RE.search(raw_text):
        findings.append(
            _finding(
                "unicode_bidi_text",
                "obfuscation",
                source,
                "high",
                94,
                "bidirectional control character detected",
                "Remove directional control characters from tool metadata.",
                decision=FINDING_DECISION_BLOCK,
            )
        )
    if HTML_COMMENT_RE.search(text):
        findings.append(
            _finding(
                "hidden_html_comment",
                "hidden_text",
                source,
                "medium",
                90,
                "HTML comment found in metadata",
                "Remove hidden comments from tool descriptions.",
                decision=FINDING_DECISION_REVIEW,
            )
        )
    return findings
