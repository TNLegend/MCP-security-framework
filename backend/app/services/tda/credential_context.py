from __future__ import annotations

def _caller_supplied_auth_credential_text(text: str) -> bool:
    import re

    credential = bool(
        re.search(
            "\\b(?:credentials?|bearer credentials?|tokens?|access tokens?|passwords?|api[_ -]?keys?|identifiants?|jetons?|mots? de passe|clés? api)\\b",
            text,
            re.IGNORECASE,
        )
    )
    supplied = bool(
        re.search(
            "\\b(?:supplied|provided|passed|given|furnished)\\b.{0,35}\\b(?:caller|user|operator|client|request)\\b|\\b(?:caller|user|operator|client)\\b.{0,35}\\b(?:supplied|provided|passed|given)\\b|\\b(?:fourni|fournie|fournis|fournies|transmis|transmise)\\b.{0,35}\\b(?:appelant|utilisateur|opérateur|client|requête)\\b",
            text,
            re.IGNORECASE,
        )
    )
    auth_use = bool(
        re.search(
            "\\b(?:authenticate|authentication|authorize|authorization|sign|verify|authentifier|authentification|autoriser|autorisation|signer|vérifier)\\b",
            text,
            re.IGNORECASE,
        )
        or re.search(
            "\\b(?:request|requête)\\b.{0,35}\\b(?:with|using|avec|via)\\b.{0,30}\\b(?:credentials?|tokens?|passwords?|api[_ -]?keys?|identifiants?|jetons?|mots? de passe|clés? api)\\b",
            text,
            re.IGNORECASE,
        )
    )
    retention = bool(
        re.search(
            "\\b(?:retain|save|store|persist|log|record|reuse|harvest|collect|capture|extract|steal|conserver|sauvegarder|stocker|persister|journaliser|enregistrer|réutiliser|collecter|capturer|extraire|voler)\\b",
            text,
            re.IGNORECASE,
        )
    )
    return credential and supplied and auth_use and (not retention)


def _managed_secret_read_only_text(text: str) -> bool:
    import re

    managed_source = bool(
        re.search(
            "\\b(?:approved|configured|managed|authorized|authorised|trusted)\\b.{0,40}\\b(?:vault|secret store|secret manager|coffre|coffre de secrets|gestionnaire de secrets)\\b|\\b(?:vault|secret store|secret manager|coffre|coffre de secrets|gestionnaire de secrets)\\b.{0,40}\\b(?:approved|configured|managed|authorized|authorised|trusted|configuré|autoris[ée])\\b",
            text,
            re.IGNORECASE,
        )
    )
    retrieval = bool(
        re.search(
            "\\b(?:read|retrieve|fetch|get|access|lire|récup(?:érer|ère|ères|èrent)|accéder|obtenir)\\b",
            text,
            re.IGNORECASE,
        )
    )
    abusive_collection = bool(
        re.search(
            "\\b(?:retain|save|store|harvest|steal|capture|collect|extract|reuse|persist|conserver|sauvegarder|stocker|collecter|capturer|extraire|réutiliser)\\b",
            text,
            re.IGNORECASE,
        )
        or re.search(
            "\\b(?:user|operator|caller|free[- ]form|note|prompt|input|content|session|utilisateur|opérateur|appelant|note|contenu|entrée|session)\\b.{0,50}\\b(?:passwords?|credentials?|tokens?|secrets?|api[_ -]?keys?|mots? de passe|identifiants?|jetons?|secrets?|clés? api)\\b",
            text,
            re.IGNORECASE,
        )
    )
    return managed_source and retrieval and (not abusive_collection)
