from __future__ import annotations
from app.services.tda.m2_structure.schema_checks import (
    schema_header_findings,
    schema_parameter_findings,
)
from app.services.tda.schema_traversal import iter_schema_fields
from app.services.tda.serialization import _safe_json
from app.services.tda.types import AnalysisFinding
from app.services.tda.security_guards.facts import ToolSemanticFacts
from app.services.tda.m3_instructions.detectors import _text_findings
from app.services.tda.m3_instructions.review import legacy_instruction_review_findings
from app.services.tda.m6_comparison.consistency import capabilities_from_profile
from app.services.tda.configuration import FINDING_DECISION_REVIEW
from app.services.tda.configuration import SEMANTIC_CORROBORATION_PATTERNS
from app.services.tda.findings import _finding
from app.services.tda.security_guards.risk_support import _semantic_fact_support
from app.services.tda.m3_instructions.semantic_input import _semantic_text
from app.services.tda.linguistic_context import operational_pattern_search
from app.services.tda.security_guards.transfer_relation import positive_external_transfers
from typing import Any


def _contextual_security_review_findings(
    tool_snapshot: dict[str, Any], facts: ToolSemanticFacts
) -> list[AnalysisFinding]:
    """Review explicit high-risk behavior even when the semantic model under-scores it.

    These checks are intentionally vendor-agnostic and require two independent signals:
    explicit abuse language in the operational semantic text plus corroborating structured
    facts extracted from the tool metadata/schema. They never BLOCK by themselves.
    """
    text = _semantic_text(tool_snapshot)
    checks = {
        "prompt_injection": (
            "contextual_prompt_injection",
            "Tool metadata explicitly gives tool-provided instructions precedence over platform safeguards.",
            "Reject tool metadata that attempts to override platform or security instructions.",
        ),
        "security_bypass": (
            "contextual_security_bypass",
            "Tool metadata explicitly describes bypassing security, policy, or authorization controls.",
            "Remove bypass behavior and require normal authorization checks.",
        ),
        "secret_collection": (
            "contextual_secret_collection",
            "Tool metadata explicitly describes collecting passwords, tokens, credentials, or other secrets.",
            "Require an explicit secret-access contract and restrict credential collection to the minimum authorized scope.",
        ),
        "data_exfiltration": (
            "contextual_data_exfiltration",
            "Sensitive data is explicitly described as being sent to an external destination.",
            "Require an explicit external-transfer contract and tightly scoped destination.",
        ),
        "hidden_additional_action": (
            "contextual_hidden_additional_action",
            "An additional side effect is explicitly described as hidden or undisclosed.",
            "Make all side effects explicit in the tool contract and user-visible purpose.",
        ),
        "unauthorized_data_access": (
            "contextual_unauthorized_data_access",
            "Access outside the authorized scope or without permission is explicitly described.",
            "Constrain resources to the authorized scope and reject out-of-scope access.",
        ),
        "user_deception": (
            "contextual_user_deception",
            "The tool explicitly describes concealing or misrepresenting its real behavior to the user.",
            "Require transparent behavior and remove deceptive instructions.",
        ),
        "privilege_escalation": (
            "contextual_privilege_escalation",
            "The tool explicitly describes granting or elevating administrator, owner, role, permission, or privilege authority.",
            "Require an explicit identity-management capability and bounded authorization scope.",
        ),
        "cross_tenant_access": (
            "contextual_cross_tenant_access",
            "Cross-tenant or cross-account access is explicitly described.",
            "Confirm tenant/account boundaries and require an explicit authorized scope.",
        ),
        "unexpected_destructive_operation": (
            "contextual_unexpected_destructive_operation",
            "Irreversible or confirmation-free destructive behavior is explicitly described.",
            "Require an explicit destructive contract, bounded resource scope, and confirmation policy.",
        ),
        "public_sharing": (
            "contextual_public_sharing",
            "The tool explicitly describes making a resource public or accessible to anyone.",
            "Require an explicit public-sharing capability and bounded resource scope.",
        ),
        "bulk_messaging": (
            "contextual_bulk_messaging",
            "Bulk or mass messaging behavior is explicitly described.",
            "Require explicit bulk-messaging authorization and bounded recipient scope.",
        ),
        "unauthorized_financial_transaction": (
            "contextual_unauthorized_financial_transaction",
            "A financial transaction without approval or consent is explicitly described.",
            "Require explicit user authorization and transaction constraints.",
        ),
        "server_side_request_forgery": (
            "contextual_server_side_request_forgery",
            "Access to a local, link-local, or metadata-service destination is explicitly described.",
            "Restrict destinations and block local, metadata, and other protected network ranges.",
        ),
        "shell_injection": (
            "contextual_shell_injection",
            "Untrusted or arbitrary input is explicitly described as influencing shell/script execution.",
            "Use fixed executable/argument templates and reject untrusted command construction.",
        ),
    }
    findings: list[AnalysisFinding] = legacy_instruction_review_findings(tool_snapshot)
    for category, (code, evidence, recommendation) in checks.items():
        patterns = SEMANTIC_CORROBORATION_PATTERNS.get(category, ())
        if not any((operational_pattern_search(pattern, text) for pattern in patterns)):
            continue
        if not _semantic_fact_support(category, facts, text):
            continue
        findings.append(
            _finding(
                code,
                category,
                "structured_context",
                "high",
                90,
                evidence,
                recommendation,
                decision=FINDING_DECISION_REVIEW,
            )
        )
    if not any((f.code == "contextual_data_exfiltration" for f in findings)):
        for relation in positive_external_transfers(tool_snapshot):
            proof = relation["evidence"]
            finding = _finding(
                "contextual_data_exfiltration",
                "data_exfiltration",
                relation["source_path"],
                "high",
                90,
                "Metadata explicitly describes sending sensitive information to an external destination.",
                "Require an explicit external-transfer contract and narrowly scoped destination.",
                decision=FINDING_DECISION_REVIEW,
            )
            finding.evidence.update(reason="positive_directed_transfer", spans=proof)
            findings.append(finding)
    return findings


def _schema_findings(
    schema: dict[str, Any],
    source: str,
    profile_capabilities: set[str] | None = None,
    semantic_facts: ToolSemanticFacts | None = None,
) -> list[AnalysisFinding]:
    findings = schema_header_findings(schema, source)
    for path, name, field in iter_schema_fields(schema):
        field_text = _safe_json(field)
        parameter_findings = schema_parameter_findings(
            path, name, field_text, source, profile_capabilities,
            semantic_facts is not None and "code_execution" in semantic_facts.values("side_effects")
        )
        findings.extend(parameter_findings)
        # The parameter-name exemption applies only to the structural finding.
        findings.extend(_text_findings(source, field_text))
    return findings
