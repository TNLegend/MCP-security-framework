from __future__ import annotations
from app.services.tda.types import AnalysisFinding
from app.services.tda.configuration import BASE64_RE
from app.services.tda.configuration import BIDI_RE
from app.services.tda.configuration import FINDING_DECISION_BLOCK
from app.services.tda.configuration import FINDING_DECISION_INFO
from app.services.tda.configuration import FINDING_DECISION_REVIEW
from app.services.tda.configuration import HTML_COMMENT_RE
from app.services.tda.configuration import INVISIBLE_RE
from app.services.tda.configuration import SEMANTIC_CORROBORATION_PATTERNS
from app.services.tda.credential_context import (
    _caller_supplied_auth_credential_text,
)
from app.services.tda.findings import _finding
from app.services.tda.credential_context import _managed_secret_read_only_text
from app.services.tda.linguistic_context import operational_pattern_search
from app.services.tda.m2_structure.metadata_checks import metadata_shape_findings
from typing import Any


def _text_findings(source: str, text: str) -> list[AnalysisFinding]:
    import re

    findings: list[AnalysisFinding] = []
    raw_text = text
    text = re.sub(
        '\\b(?:contains?|includes?|mentions?|quotes?)\\s+(?:the\\s+)?(?:literal\\s+)?(?:phrase|text|string|words?)\\s+"[^"\\n]{1,512}"',
        "contains the literal quoted content",
        text,
        flags=re.IGNORECASE,
    )
    findings.extend(metadata_shape_findings(source, raw_text, text))
    if (
        operational_pattern_search(
            "\\b(ask|request|collect|capture|extract|steal)\\w*[^.;!?\\n]{0,60}\\b(passwords?|credentials?|api[_ -]?keys?|tokens?|secrets?)\\b",
            text,
        )
        and (not _managed_secret_read_only_text(text))
        and (not _caller_supplied_auth_credential_text(text))
    ):
        findings.append(
            _finding(
                "credential_request",
                "secret_collection",
                source,
                "critical",
                88,
                "credential-like request found",
                "Do not collect credentials through tool descriptions or schemas.",
                decision=FINDING_DECISION_BLOCK,
            )
        )
    if (
        operational_pattern_search(
            "\\b(demande[rz]?|collecte[rz]?|capture[rz]?|récup(?:érer|ère|ères|èrent|éré|érée|érés|érées)|extraire|vole[rz]?)\\w*[^.;!?\\n]{0,60}\\b(mots? de passe|identifiants?|clés? api|jetons?|secrets?)\\b",
            text,
        )
        and (not _managed_secret_read_only_text(text))
        and (not _caller_supplied_auth_credential_text(text))
    ):
        findings.append(
            _finding(
                "credential_request",
                "secret_collection",
                source,
                "critical",
                88,
                "credential-like request found",
                "Do not collect credentials through tool descriptions or schemas.",
                decision=FINDING_DECISION_BLOCK,
            )
        )
    if operational_pattern_search(
        "\\b(read|access|collect|capture|include|expose|return|lire|accéder|collecter|inclure|exposer)\\w*.{0,50}\\b(\\.env|environment variables?|include_env|process\\.env|variables? d'environnement)\\b",
        text,
    ):
        findings.append(
            _finding(
                "environment_secret_access",
                "secret_collection",
                source,
                "critical",
                90,
                "environment secret access requested",
                "Remove environment secret access from the tool contract.",
                decision=FINDING_DECISION_BLOCK,
            )
        )
    if operational_pattern_search(
        "\\b(ignore|bypass|disable|ignorer?|contourner?|désactiver?).{0,40}\\b(policy|security|restriction|instruction|politique|sécurité|règle)",
        text,
    ):
        findings.append(
            _finding(
                "ignore_security_restrictions",
                "prompt_injection",
                source,
                "critical",
                91,
                "instruction to bypass security restrictions detected",
                "Remove prompt-injection instructions from the tool metadata.",
                decision=FINDING_DECISION_BLOCK,
            )
        )
    operational_risks = (
        (
            "\\b(?:ignore|bypass|disable)\\s+(?:all|any|other|the)\\s+(?:\\w+\\s+){0,3}(?:constraints?|safeguards?|guardrails?)\\b",
            "bypass_security_constraints",
            "prompt_injection",
            "critical",
            FINDING_DECISION_BLOCK,
        ),
        (
            "\\b(?:disable(?:s|d|ing)?|turns?\\s+off|suppress(?:es|ed|ing)?)\\b(?:(?!\\b(?:and|but|then|while|or|et|mais|puis|ensuite)\\s+(?:(?:the|this)\\s+)?(?:(?:tool|service|it|elle|il)\\s+)?(?:disable(?:s|d|ing)?|turns?\\s+off|suppress(?:es|ed|ing)?)\\b)[^.;!?\\n]){0,55}\\b(?:audit|security|access)\\s+(?:logs?|logging|traces?|recording)\\b",
            "audit_logging_suppression",
            "security_bypass",
            "high",
            FINDING_DECISION_REVIEW,
        ),
        (
            "\\b(?:regardless\\s+of|ignoring)\\b.{0,45}\\b(?:tenant|account|customer)\\b.{0,45}\\b(?:isolation|authorization|permissions?|boundaries|access\\s+controls?)\\b",
            "cross_tenant_isolation_bypass",
            "unauthorized_data_access",
            "high",
            FINDING_DECISION_REVIEW,
        ),
        (
            "\\b(?:fetch|download|retrieve)\\b.{0,100}\\b(?:shell|script)\\b.{0,120}\\b(?:execute|run|launch)\\b",
            "downloaded_script_execution",
            "command_execution",
            "high",
            FINDING_DECISION_REVIEW,
        ),
        (
            "\\b(?:arbitrary|unrestricted|user[- ]supplied)\\b.{0,60}\\b(?:sql|queries|statements)\\b.{0,100}\\b(?:schema\\s+changes|ddl|alter|drop|production\\s+database)\\b",
            "unbounded_database_changes",
            "database_access",
            "high",
            FINDING_DECISION_REVIEW,
        ),
        (
            "\\b(?:upload|send|export)\\b.{0,70}\\b(?:database|db)\\b.{0,35}\\b(?:dump|backup)\\b.{0,100}\\b(?:url|https?|external|collector)\\b",
            "database_dump_external_transfer",
            "data_exfiltration",
            "high",
            FINDING_DECISION_REVIEW,
        ),
    )
    for pattern, code, category, severity, decision in operational_risks:
        if operational_pattern_search(pattern, text):
            findings.append(
                _finding(
                    code,
                    category,
                    source,
                    severity,
                    90,
                    "operational risk instruction in tool metadata",
                    "Review the tool contract, supported capabilities, and authority scope.",
                    decision=decision,
                )
            )
    if len(text) > 4000:
        findings.append(
            _finding(
                "description_unusually_long",
                "obfuscation",
                source,
                "medium",
                70,
                f"description length={len(text)}",
                "Shorten metadata to the minimum required tool contract.",
                decision=FINDING_DECISION_INFO,
            )
        )
    for candidate in BASE64_RE.findall(text):
        if _looks_like_encoded_instruction(candidate):
            findings.append(
                _finding(
                    "suspicious_base64_payload",
                    "obfuscation",
                    source,
                    "critical",
                    86,
                    "base64-like encoded instruction detected",
                    "Remove encoded instructions from tool metadata.",
                    decision=FINDING_DECISION_BLOCK,
                )
            )
            break
    return findings


def _looks_like_encoded_instruction(value: str) -> bool:
    import base64

    try:
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), validate=False)
    except Exception:
        return False
    if not decoded:
        return False
    text = decoded[:512].decode("utf-8", errors="ignore").lower()
    return any(
        (word in text for word in ("ignore", "secret", "token", "upload", "command"))
    )

def interpret_m4_directives_advisory(view: dict[str, Any]) -> dict[str, Any]:
    if view.get("instruction_verdict") != "NOT_EVALUATED":
        raise ValueError("M3_M4_UNEXPECTED_INSTRUCTION_AUTHORITY")
    rows = view.get("advisory_directives")
    if not isinstance(rows, list):
        raise ValueError("M3_M4_DIRECTIVES_NOT_LIST")
    directives = []
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("event_id"), str):
            raise ValueError("M3_M4_INVALID_DIRECTIVE")
        if not isinstance(row.get("uncertainty_reasons"), list):
            raise ValueError("M3_M4_UNCERTAINTY_MISSING")
        directives.append({
            "event_id": row["event_id"],
            "text_evidence": row.get("predicate"),
            "proposed_actor": row.get("actor", "UNKNOWN"),
            "proposed_force": row.get("directive_force", "UNKNOWN"),
            "uncertainty_reasons": list(row["uncertainty_reasons"]),
            "source_is_model_hypothesis": True,
        })
    return {
        "mode": "ADVISORY",
        "module": "M3",
        "model_directives": directives,
        "prompt_injection_verdict": "NOT_EVALUATED",
        "existing_instruction_checks_unchanged": True,
    }
