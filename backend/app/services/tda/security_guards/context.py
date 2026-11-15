from __future__ import annotations
from app.services.tda.linguistic_context import strip_documentation_examples, operational_pattern_search, _match_is_non_operational
from app.services.tda.security_guards.facts import _TextSegment
from app.services.tda.claim_context import reference_span, comparative_span
from typing import Iterable
import re




def _url_is_documentation_example(text: str, raw_url: str) -> bool:
    import re

    start = text.find(raw_url)
    if start < 0:
        return False
    prefix = text[max(0, start - 120) : start]
    return bool(
        re.search(
            "(?:\\be\\.g\\.|\\bfor example\\b|\\bexample\\b|\\bsample\\b|\\bsuch as\\b)[^\\n]{0,100}$",
            prefix,
            re.IGNORECASE,
        )
    )


def _administrator_privilege_evidenced(segment: _TextSegment) -> bool:
    import re

    field_name = segment.path.rsplit(".", 1)[-1].lower()
    if field_name in {
        "role",
        "roles",
        "permission",
        "permissions",
        "privilege",
        "privileges",
        "admin",
        "administrator",
        "owner_role",
    }:
        return True
    return bool(
        re.search(
            "\\b(require[sd]?|need[sd]?|must have|restricted to)\\b.{0,45}\\b(admin(?:istrator)?|owner|root|superuser)\\b|\\b(grant|assign|elevate|escalate|promote)\\b.{0,45}\\b(admin(?:istrator)?|owner|root|superuser|role|permission|privilege)\\b",
            segment.text,
            re.IGNORECASE,
        )
    )




def _matches_any(text: str, patterns: Iterable[str]) -> bool:
    return any((operational_pattern_search(pattern, text) for pattern in patterns))




def _execution_is_explicitly_negated(text: str) -> bool:
    import re

    patterns = (
        "\\b(?:does|do|did|will|would|can|could|should|must)\\s+not\\s+(?:\\w+\\s+){0,3}(?:execute|run|launch|invoke)\\b",
        "\\b(?:never|without)\\s+(?:\\w+\\s+){0,3}(?:execut(?:e|ing)|run(?:ning)?|launch(?:ing)?|invok(?:e|ing))\\b",
        "\\bn['’]\\s*(?:exécute|execute|lance|invoque)\\b.{0,30}\\b(?:pas|jamais|plus)\\b",
        "\\bne\\s+(?:\\w+\\s+){0,3}(?:exécute|execute|lance|invoque)\\b.{0,30}\\b(?:pas|jamais|plus)\\b",
        "\\bsans\\s+(?:jamais\\s+)?(?:exécuter|executer|lancer|invoquer)\\b",
    )
    return any((re.search(pattern, text, re.IGNORECASE) for pattern in patterns))


def _financial_domain_unresolved(text: str, match: re.Match[str]) -> bool:
    import re

    before = text[: match.start()]
    after = text[match.end() :]
    clause = (
        re.split("[.;!?\\n]", before)[-1]
        + match.group()
        + re.split("[.;!?\\n]", after)[0]
    )
    if re.search(
        "\\b(?:money|funds|payments?|bank|accounts?|cards?|customers?|clients?|invoices?|billing|fees?|merchant|transactions?|refunds?|dollars?|euros?|argent|fonds|paiements?|banque|compte|facture)\\b|[$€£]",
        clause,
        re.IGNORECASE,
    ):
        return False
    if re.search(
        "\\b(?:the|a|an|its|their|la|le|sa|son|une|un|cette|ce)\\s*$",
        before,
        re.IGNORECASE,
    ):
        return False
    return True


def _fact_is_ignored(
    category: str,
    value: str,
    segment: _TextSegment,
    *,
    match: re.Match[str] | None = None,
) -> bool:
    import re

    if category == "privileges" and value == "administrator":
        return not _administrator_privilege_evidenced(segment)
    before = segment.text[: match.start()] if match is not None else ""
    after = segment.text[match.end() :] if match is not None else ""
    matched = match.group(0).lower() if match is not None else ""
    if category == "resources" and value == "identity" and (match is not None):
        if re.search(
            "\\b(?:return\\w*|respond\\w*|retourn\\w*|devuelv\\w*)\\b[^.;!?]{0,80}\\b(?:to|for|à|au|al|para)\\s+(?:the\\s+|l['’])?$",
            before,
            re.IGNORECASE,
        ):
            return True
    if category == "actions" and match is not None:
        local_before = re.split("[.;!?\\n]", before)[-1]
        if re.search(
            "\\b(?:includes?|contains?|mentions?|quotes?|lists?)\\s+(?:the\\s+)?(?:words?|terms?|verbs?|phrases?|strings?)\\b",
            local_before,
            re.IGNORECASE,
        ):
            return True
        if (
            matched in {"created", "updated", "deleted", "modified"}
            and re.match(
                "\\s+(?:date|time|timestamp|flag|status|field|column|property)\\b",
                after,
                re.IGNORECASE,
            )
            and re.search(
                "\\b(?:read(?:s|ing)?|inspect(?:s|ing)?|list(?:s|ing)?|metadata|fields?|attributes?|statuses?|dates?)\\b",
                local_before,
                re.IGNORECASE,
            )
        ):
            return True
    if (
        category == "actions"
        and value in {"create", "update"}
        and (segment.source == "input_schema")
        and (matched in {"created", "updated"})
        and re.search(
            "\\b(?:sort|order)\\b.{0,120}\\b(?:by|field|fields|results|records)\\b",
            segment.text,
            re.IGNORECASE,
        )
    ):
        return True
    if (
        category == "actions"
        and value == "delete"
        and (matched in {"drop", "drops", "dropped", "dropping"})
        and (segment.source == "input_schema")
        and re.search(
            "\\b(?:fields?|columns?|properties)\\s+to\\s+return|\\bsubset\\s+of\\s+(?:fields?|columns?)",
            segment.text,
            re.IGNORECASE,
        )
        and re.search(
            "\\b(?:response\\s+size|payload\\s+(?:bytes?|size)|per-result\\s+data|returned\\s+data)\\b",
            after[:88],
            re.IGNORECASE,
        )
    ):
        return True
    if (
        category == "resources"
        and value == "identity"
        and (segment.source == "input_schema")
        and (matched == "user")
        and after.startswith(":")
        and re.search("\\bexamples?\\s*:", before[-220:], re.IGNORECASE)
    ):
        return True
    if category == "actions" and value == "transact" and (match is not None):
        if re.fullmatch(
            "charg\\w*|transf(?:er|ers|erred|erring)", matched, re.IGNORECASE
        ):
            clause = (
                re.split("[.;!?\\n]", before)[-1]
                + matched
                + re.split("[.;!?\\n]", after)[0]
            )
            if _financial_domain_unresolved(segment.text, match) or not re.search(
                "\\b(?:money|funds|payments?|bank|accounts?|cards?|customers?|clients?|invoices?|billing|fees?|merchant|transactions?|refunds?|dollars?|euros?|argent|fonds|paiements?|banque|compte|facture)\\b|[$€£]",
                clause,
                re.IGNORECASE,
            ):
                return True
        verb = "(?:charg(?:e|es|ed|ing)|transf(?:er|ers|erred|erring)|pay(?:s|ing)?|debit(?:s|ed|ing)?)"
        if re.fullmatch(verb, matched, re.IGNORECASE):
            if re.search(
                "\\b(?:without|never|(?:does|do|did|will|would|must|should)\\s+not)\\s*$",
                before[-80:],
                re.IGNORECASE,
            ):
                return True
            if re.search(
                f"\\bwithout\\s+{verb}\\b(?:\\s+\\w+){{0,5}}\\s+(?:or|and)\\s*$",
                before[-110:],
                re.IGNORECASE,
            ):
                return True
    if category == "actions" and value in {
        "create",
        "update",
        "delete",
        "send",
        "transact",
    }:
        read_like_before = bool(
            re.search(
                "\\b(read(?:s|ing)?|fetch(?:es|ed|ing)?|get(?:s|ting)?|retrieve(?:s|d|ing)?|inspect(?:s|ed|ing)?|view(?:s|ed|ing)?|list(?:s|ed|ing)?|search(?:es|ed|ing)?|lire|lit|liste|consulter|rechercher)\\b.{0,28}$",
                before,
                re.IGNORECASE,
            )
        )
        nominal_after = bool(
            re.match(
                "\\s+(?:(?:payment|transaction|transfer|refund|charge|paiement|transaction|virement|remboursement|débit)\\s+(?:status|state|history|details?|id|identifier|reference|metadata|record(?:s)?|date|policy|statut|état|historique|détails?|identifiant|référence|métadonnées?|enregistrements?|date|politique)|status|state|history|details?|id|identifier|reference|metadata|record(?:s)?|date|flag|setting|option|mode|field|property|policy|permission(?:s)?|access|list|result|results|information|info|statut|état|historique|détails?|identifiant|référence|métadonnées?|drapeau|paramètre|option|champ|propriété|politique|permission(?:s)?|accès|liste|résultat(?:s)?)\\b",
                after,
                re.IGNORECASE,
            )
        )
        explicit_mutation_verb = bool(
            re.fullmatch(
                "(?:persist(?:s|ed|ing)?|writ(?:e|es|ing|ten)|updat(?:e|es|ed|ing)|commit(?:s|ted|ting)?)",
                matched,
                re.IGNORECASE,
            )
        )
        if read_like_before and nominal_after and (not explicit_mutation_verb):
            return True
        if (
            value == "send"
            and matched.startswith("post")
            and (
                re.search(
                    "\\b(?:blog|forum|article|social)\\s*$", before, re.IGNORECASE
                )
                or nominal_after
            )
        ):
            return True
    if category not in {"data_categories", "resources"} or value not in {
        "credentials",
        "secret_store",
    }:
        return False
    field_name = segment.path.rsplit(".", 1)[-1].lower()
    credential_field = bool(
        re.fullmatch("(?:api_?)?(?:key|token|secret|password|credential)s?", field_name)
    )
    conceptual_credential = bool(
        re.match(
            "\\s+(?:count|length|budget|usage|limit|estimate|statistics?|policy|policies|documentation|docs?|guide|rotation|format|schema|metadata|name|type|status|state|history|counting|compte|longueur|budget|usage|limite|estimation|statistiques?|politique|documentation|guide|rotation|format|schéma|métadonnées?|nom|type|statut|état|historique)\\b",
            after,
            re.IGNORECASE,
        )
    )
    if conceptual_credential and (not credential_field):
        return True
    credential_operation = bool(
        operational_pattern_search(
            "\\b(read(?:s|ing)?|get(?:s|ting)?|fetch(?:es|ed|ing)?|retrieve(?:s|d|ing)?|obtain(?:s|ed|ing)?|acquir(?:e|es|ed|ing)|harvest(?:s|ed|ing)?|gather(?:s|ed|ing)?|access(?:es|ed|ing)?|request(?:s|ed|ing)?|collect(?:s|ed|ing)?|capture(?:s|d|ing)?|extract(?:s|ed|ing)?|expose(?:s|d|ing)?|return(?:s|ed|ing)?|store(?:s|d|ing)?|retain(?:s|ed|ing)?|save(?:s|d|ing)?|lire|lit|récup(?:érer|ère|ères|èrent|éré|érée|érés|érées)|obtenir|obtiens|obtient|obtenez|acqu(?:érir|iert|iers|érez)|récolt(?:er|e|es|ent|é|ée|és|ées)|rassembl(?:er|e|es|ent|é|ée|és|ées)|accéder|demander|collecter|extraire|exposer|conserver|sauvegard(?:er|e|es|ent|é|ée|és|ées)|stock(?:er|e|es|ent|é|ée|és|ées))\\w*.{0,70}\\b(credentials?|tokens?|passwords?|api[_ -]?keys?|secrets?|authentication material|auth material|bearer credentials?|identifiants?|jetons?|mots? de passe|clés? api|matériel d'authentification)\\b",
            segment.text,
        )
    )
    if not credential_field and (not credential_operation):
        return True
    return bool(
        re.search(
            "\\b(credentials?|tokens?|passwords?|api[_ -]?keys?|secrets?)\\b.{0,70}\\b(not requested|not collected|never exposed|managed by|handled by)\\b|\\b(does not|do not|never)\\b.{0,40}\\b(request|collect|capture|expose)\\b.{0,30}\\b(credentials?|tokens?|passwords?|api[_ -]?keys?|secrets?)\\b",
            segment.text,
            re.IGNORECASE,
        )
    )


def _humanize_identifier(value: str) -> str:
    import re

    spaced = re.sub("([a-z0-9])([A-Z])", "\\1 \\2", value)
    return re.sub("[_\\-.]+", " ", spaced)


def _public_destination(raw_url: str) -> str:
    from urllib.parse import urlsplit

    parsed = urlsplit(raw_url.rstrip(".,;"))
    if not parsed.hostname:
        return "external_url"
    port = f":{parsed.port}" if parsed.port else ""
    return f"{parsed.scheme.lower()}://{parsed.hostname.lower()}{port}"


def _fact_safe_excerpt(value: str, limit: int = 180) -> str:
    import re

    text = re.sub("\\s+", " ", str(value)).strip()
    text = re.sub(
        "(?i)(token|password|secret|api[_ -]?key|credential)\\s*[=:]\\s*[^\\s,;]+",
        "\\1=<redacted>",
        text,
    )
    if len(text) > limit:
        return f"{text[:limit]}..."
    return text
