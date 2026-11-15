from __future__ import annotations
from app.services.tda.credential_context import _caller_supplied_auth_credential_text, _managed_secret_read_only_text
from app.services.tda.configuration import SEMANTIC_CORROBORATION_PATTERNS
from app.services.tda.security_guards.facts import ToolSemanticFacts
from app.services.tda.security_guards.context import operational_pattern_search






def _privilege_escalation_abuse_evidenced(text: str) -> bool:
    import re

    explicit_escalation = bool(
        re.search(
            "\\b(?:elevate|escalate|promote|make|turn|élever|promouvoir|transformer)\\b.{0,60}\\b(?:admin(?:istrator)?|root|owner|superuser|administrateur|propriétaire)\\b",
            text,
            re.IGNORECASE,
        )
    )
    risky_scope = bool(
        re.search(
            "\\b(?:without|outside|beyond|exceeding|unauthori[sz]ed|unapproved)\\b.{0,60}\\b(?:approval|authorization|scope|role|permission|privilege|access)\\b|\\b(?:sans|hors|au-delà|non autoris[ée])\\b.{0,60}\\b(?:approbation|autorisation|périmètre|portée|rôle|permission|privilège|accès)\\b",
            text,
            re.IGNORECASE,
        )
    )
    high_authority_change = bool(
        re.search(
            "\\b(?:grant|assign|give|attribuer|accorder)\\b.{0,60}\\b(?:admin(?:istrator)?|root|owner|superuser|administrateur|propriétaire)\\b",
            text,
            re.IGNORECASE,
        )
    )
    return explicit_escalation or (high_authority_change and risky_scope)


def _defensive_cross_tenant_reference(text: str) -> bool:
    """Do not confuse investigating cross-tenant access attempts with performing one."""
    import re

    if not re.search(
        "\\b(?:audit|monitor|investigate|detect|inspect|review|analy[sz]e)\\b.{0,100}\\b(?:logs?|events?|attempts?|reports?)\\b",
        text,
        re.IGNORECASE,
    ):
        return False
    active = re.sub(
        "\\b(?:cannot|can't|does\\s+not|do\\s+not|never)\\s+(?:access|read|retrieve|fetch|query)\\b.{0,55}",
        "",
        text,
        flags=re.IGNORECASE,
    )
    return not bool(
        re.search(
            "\\b(?:access|read|retrieve|fetch|query|download|expose)\\b.{0,75}\\b(?:another|other|cross)[- ]?(?:tenant|customer|account|organization)\\b|\\b(?:another|other|cross)[- ]?(?:tenant|customer|account|organization)\\b.{0,65}\\b(?:files?|data|records?)\\b.{0,35}\\b(?:read|access|retrieve|fetch|query|download|expose)\\b",
            active,
            re.IGNORECASE,
        )
    )


def _offline_metadata_reference(text: str) -> bool:
    """Distinguish quoted metadata IPs in offline documents from network calls."""
    import re

    if not re.search(
        "\\b(?:search|read|inspect|review|summarize|explain|describe)\\b.{0,100}\\b(?:documents?|documentation|logs?|strings?|examples?|articles?|reports?)\\b",
        text,
        re.IGNORECASE,
    ):
        return False
    return not bool(
        operational_pattern_search(
            "\\b(?:request|fetch|connect|query|call|access|send)\\b.{0,100}\\b(?:169\\.254\\.169\\.254|metadata(?:[- ]service)?|instance[- ]metadata|imds)\\b",
            text,
        )
    )


def _semantic_fact_support(category: str, facts: ToolSemanticFacts, text: str) -> bool:
    import re

    actions = facts.values("actions")
    resources = facts.values("resources")
    data = facts.values("data_categories")
    side_effects = facts.values("side_effects")
    scopes = facts.values("scopes")
    privileges = facts.values("privileges")
    destinations = facts.values("external_destinations")
    sensitive_transfer_data = data.intersection(
        {
            "credentials",
            "personal_data",
            "financial_data",
            "source_code",
            "location",
            "sensitive_data",
        }
    )
    explicit_exfiltration = bool(
        re.search(
            "\\b(exfiltrat\\w*|collector|secretly|covertly|without (?:consent|notifying))\\b",
            text,
            re.IGNORECASE,
        )
        or any(("collector" in destination for destination in destinations))
    )
    requirements = {
        "prompt_injection": True,
        "security_bypass": True,
        "secret_collection": "credentials" in data
        and (not _managed_secret_read_only_text(text))
        and (not _caller_supplied_auth_credential_text(text)),
        "data_exfiltration": bool(
            (destinations or "external_transfer" in side_effects)
            and (sensitive_transfer_data or explicit_exfiltration)
        ),
        "hidden_additional_action": bool(side_effects),
        "command_execution": False,
        "unauthorized_data_access": bool(
            resources or actions.intersection({"read", "search", "list"})
        )
        and any(
            (
                operational_pattern_search(pattern, text)
                for pattern in SEMANTIC_CORROBORATION_PATTERNS[
                    "unauthorized_data_access"
                ]
            )
        ),
        "user_deception": True,
        "privilege_escalation": bool(privileges)
        and "authorize" in actions
        and _privilege_escalation_abuse_evidenced(text),
        "cross_tenant_access": "cross_tenant" in scopes
        and (not _defensive_cross_tenant_reference(text)),
        "unexpected_destructive_operation": "destructive" in side_effects,
        "public_sharing": "public_exposure" in side_effects or "public" in scopes,
        "bulk_messaging": "bulk" in scopes
        and "message" in resources
        and ("send" in actions),
        "server_side_request_forgery": bool(
            destinations or "network_endpoint" in resources
        )
        and (not _offline_metadata_reference(text)),
        "shell_injection": "process" in resources
        and any(
            (
                operational_pattern_search(pattern, text)
                for pattern in SEMANTIC_CORROBORATION_PATTERNS["shell_injection"]
            )
        ),
        "unauthorized_financial_transaction": "financial_transaction" in side_effects,
    }
    return requirements.get(category, True)
