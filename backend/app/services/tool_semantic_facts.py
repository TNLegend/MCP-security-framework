from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Iterable
from urllib.parse import urlsplit


_EXAMPLE_TAG_RE = re.compile(
    r"<(?:example|examples)\b[^>]*>.*?</(?:example|examples)\s*>",
    re.IGNORECASE | re.DOTALL,
)
_MARKDOWN_HEADING_RE = re.compile(r"^\s*(#{1,6})\s+(.+?)\s*$")
_EXAMPLE_HEADING_RE = re.compile(
    r"^(?:examples?|samples?|usage\s+examples?|example\s+usage)\b",
    re.IGNORECASE,
)


_ACTION_PATTERNS = {
    "read": (
        r"\b(read(?:s|ing)?|fetch(?:es|ed|ing)?|get(?:s|ting)?|retrieve(?:s|d|ing)?|obtain(?:s|ed|ing)?|acquir(?:e|es|ed|ing)|inspect(?:s|ed|ing)?|view(?:s|ed|ing)?|download(?:s|ed|ing)?|lire|lit|lis(?:ent|ez|ons)?|lecture|récup(?:érer|ère|ères|èrent|éré|érée|érés|érées)|obtenir|obtiens|obtient|obtenez|obtiennent|obtenu|obtenue|acqu(?:érir|iert|iers|érez|ièrent|is|ise)|consult(?:er|e|es|ent|é|ée|és|ées)|télécharg(?:er|e|es|ent|é|ée|és|ées))\b",
    ),
    "search": (
        r"\b(search(?:es|ed|ing)?|query(?:ies|ied|ing)?|find(?:s|ing)?|found|lookup(?:s|ed|ing)?|filter(?:s|ed|ing)?|recherch(?:er|e|es|ent|é|ée|és|ées)|cherch(?:er|e|es|ent|é|ée|és|ées)|interrog(?:er|e|es|ent|é|ée|és|ées)|filtr(?:er|e|es|ent|é|ée|és|ées))\b",
    ),
    "list": (
        r"\b(list(?:s|ed|ing)?|enumerat(?:e|es|ed|ing)|brows(?:e|es|ed|ing)|list(?:er|e|es|ent|é|ée|és|ées)|énumér(?:er|e|es|ent|é|ée|és|ées)|parcourir|parcourt|parcourent|parcouru)\b",
    ),
    "create": (
        r"\b(creat(?:e|es|ed|ing)|add(?:s|ed|ing)?|insert(?:s|ed|ing)?|upload(?:s|ed|ing)?|publish(?:es|ed|ing)?|cré(?:er|e|es|ent|é|ée|és|ées)|ajout(?:er|e|es|ent|é|ée|és|ées)|insér(?:er|e|es|ent|é|ée|és|ées)|télévers(?:er|e|es|ent|é|ée|és|ées)|publi(?:er|e|es|ent|é|ée|és|ées))\b",
    ),
    "update": (
        r"\b(updat(?:e|es|ed|ing)|edit(?:s|ed|ing)?|modif(?:y|ies|ied|ying)|writ(?:e|es|ing|ten)|persist(?:s|ed|ing)?|commit(?:ted|ting)|mov(?:e|es|ed|ing)|renam(?:e|es|ed|ing)|set(?:s|ting)?|mettre à jour|mis à jour|modifi(?:er|e|es|ent|é|ée|és|ées)|écri(?:re|t|vent)|persist(?:er|e|es|ent|é|ée|és|ées)|valid(?:er|e|es|ent|é|ée|és|ées)|déplac(?:er|e|es|ent|é|ée|és|ées)|renomm(?:er|e|es|ent|é|ée|és|ées))\b",
        r"\bcommit\b(?=\s+(?:the\s+)?(?:changes?|updates?|writes?|transaction|state)\b)",
    ),
    "delete": (
        r"\b(delet(?:e|es|ed|ing)|remov(?:e|es|ed|ing)|eras(?:e|es|ed|ing)|wipe(?:s|d|ing)?|destroy(?:s|ed|ing)?|purge(?:s|d|ing)?|drop(?:s|ped|ping)?|truncat(?:e|es|ed|ing)|supprim(?:er|e|es|ent|é|ée|és|ées)|effac(?:er|e|es|ent|é|ée|és|ées)|détru(?:ire|it|isent)|purg(?:er|e|es|ent|é|ée|és|ées))\b",
    ),
    "send": (
        r"\b(send(?:s|ing)?|sent|contact(?:ed|ing)?|forward(?:s|ed|ing)?|transmit(?:s|ted|ting)?|relay(?:s|ed|ing)?|upload(?:s|ed|ing)?|post(?:s|ed|ing)?|broadcast(?:s|ed|ing)?|mirror(?:s|ed|ing)?|notif(?:y|ies|ied|ying)|envoy(?:er|é|ée|és|ées)|envoi(?:e|ent)|contact(?:er|e|es|ent|é|ée|és|ées)|transmettre|transmet|transmis|relay(?:er|e|es|ent|é|ée|és|ées)|diffus(?:er|e|es|ent|é|ée|és|ées)|copi(?:er|e|es|ent|é|ée|és|ées)|télévers(?:er|e|es|ent|é|ée|és|ées)|notifi(?:er|e|es|ent|é|ée|és|ées))\b",
    ),
    "execute": (
        r"\b(execut(?:e|es|ed|ing)|run(?:s|ning)?|launch(?:es|ed|ing)?|invok(?:e|es|ed|ing)|exécut(?:er|e|es|ent|é|ée|és|ées)|lanc(?:er|e|es|ent|é|ée|és|ées)|invoqu(?:er|e|es|ent|é|ée|és|ées))\b.{0,35}\b(shell|scripts?|process(?:es)?|executables?|operating system commands?|processus|exécutables?|commandes? système)\b",
        r"\b(shell|scripts?|process(?:es)?|executables?|operating system commands?|processus|exécutables?|commandes? système)\b.{0,25}\b(execution|execut(?:e|es|ed|ing)|run(?:s|ning)?|exécution|exécut(?:er|e|es|ent|é|ée|és|ées)|lanc(?:er|e|es|ent|é|ée|és|ées))\b",
    ),
    "authorize": (
        r"\b(grant(?:s|ed|ing)?|give(?:s|n|ing)?|revok(?:e|es|ed|ing)|authoriz(?:e|es|ed|ing)|assign(?:s|ed|ing)?|elevat(?:e|es|ed|ing)|promot(?:e|es|ed|ing)|make|accord(?:er|e|es|ent|é|ée|és|ées)|donn(?:er|e|es|ent|é|ée|és|ées)|révoqu(?:er|e|es|ent|é|ée|és|ées)|autoris(?:er|e|es|ent|é|ée|és|ées)|attribu(?:er|e|es|ent|é|ée|és|ées)|promouv(?:oir|e|es|ent)|transform(?:er|e|es|ent|é|ée|és|ées)|élèv(?:e|es|ent)|élev(?:er|é|ée|és|ées))\b.{0,45}\b(admin(?:istrator)?s?|owners?|root|superuser|roles?|permissions?|access|privileges?|administrateurs?|propriétaires?|rôles?|autorisations?|accès|privilèges?)\b",
    ),
    "transact": (
        r"\b(pay(?:s|ing)?|paid|charg(?:e|es|ed|ing)|debit(?:s|ed|ing)?|transfer(?:s|red|ring)?|purchas(?:e|es|ed|ing)|refund(?:s|ed|ing)?|payer|paie|paient|payé|payée|payés|payées|factur(?:er|e|es|ent|é|ée|és|ées)|débit(?:er|e|es|ent|é|ée|és|ées)|vir(?:er|e|es|ent|é|ée|és|ées)|achet(?:er|e|es|ent|é|ée|és|ées)|achète|achètent|rembours(?:er|e|es|ent|é|ée|és|ées))\b",
        r"\b(initiat(?:e|es|ed|ing)|creat(?:e|es|ed|ing)|issu(?:e|es|ed|ing)|start(?:s|ed|ing)?|mak(?:e|es|ing)|perform(?:s|ed|ing)?|execut(?:e|es|ed|ing)|initi(?:er|e|es|ent|é|ée|és|ées)|cré(?:er|e|es|ent|é|ée|és|ées)|émett(?:re|ent)|émis(?:e|es)?|démarr(?:er|e|es|ent|é|ée|és|ées)|effectu(?:er|e|es|ent|é|ée|és|ées))\b.{0,30}\b(payments?|transfers?|refunds?|paiements?|virements?|remboursements?)\b",
    ),
    "health_check": (r"\b(ping(?:s|ed|ing)?|health(?:check)?|readiness|liveness|status check)\b",),
}

_RESOURCE_PATTERNS = {
    "filesystem": (r"\b(filesystem|files?|folders?|directories|paths?|système de fichiers|fichiers?|dossiers?|répertoires?|chemins?)\b",),
    "document": (r"\b(documents?|documentation|docs?|guides?|manuals?|manuels?|pages?|notes?|wikis?|content|markdown|contenu)\b",),
    "database": (r"\b(databases?|schemas?|tables?|rows?|records?|collections?|sql|bases? de données|enregistrements?)\b",),
    "message": (
        r"\b(emails?|messages?|comments?|mailboxes?|recipients?|contacts?|address books?|courriels?|commentaires?|destinataires?|contacts?|carnets? d'adresses?)\b",
    ),
    "calendar": (r"\b(calendars?|events?|meetings?|calendriers?|événements?|réunions?)\b",),
    "cloud_storage": (r"\b(buckets?|containers?|cloud objects?|blobs?|storage|stockage|objets? cloud)\b",),
    "identity": (r"\b(users?|identity|identities|utilisateurs?|identité|identités)\b",),
    "secret_store": (
        r"\b(secrets?|credentials?|tokens?|passwords?|api[_ -]?keys?|vault|authentication material|auth material|bearer credentials?|identifiants?|jetons?|mots? de passe|clés? api|matériel d'authentification)\b",
    ),
    "source_code": (r"\b(repositories|repository|commits?|branches?|pull requests?|source code|dépôts?|code source)\b",),
    "payment": (r"\b(payments?|transactions?|invoices?|refunds?|merchant|paiements?|virements?|factures?|remboursements?)\b",),
    "network_endpoint": (
        r"\b(urls?|uris?|endpoints?|webhooks?|hosts?|api endpoints?|points? de terminaison)\b",
        r"\b(localhost|loopback|link-local|metadata service|service de métadonnées|169\.254\.169\.254)\b",
    ),
    "process": (r"\b(shell|bash|powershell|scripts?|process(?:es)?|executables?|system commands?|operating system commands?|command lines?|processus|exécutables?|commandes? système|lignes? de commande)\b", r"\bshell\s+commands?\b"),
}

_DATA_PATTERNS = {
    "credentials": (
        r"\b(credentials?|login credentials?|bearer credentials?|authentication credentials?|authentication secrets?|auth(?:entication|orization)? tokens?|access tokens?|refresh tokens?|tokens?|passwords?|api[_ -]?keys?|secrets?|authentication material|auth material|identifiants?|identifiants? de connexion|jetons?|mots? de passe|clés? api|matériel d'authentification)\b",
    ),
    "personal_data": (r"\b(personal data|personally identifiable|pii|phone numbers?|home addresses?|postal addresses?|données personnelles|adresses? postales|coordonnées personnelles)\b",),
    "financial_data": (r"\b(financial data|bank accounts?|card numbers?|balances?|données financières|comptes? bancaires|soldes?)\b",),
    "source_code": (r"\b(source code|repositories|commits?|code source|dépôts?)\b",),
    "document_content": (r"\b(document content|page content|file contents?|markdown|contenu (?:du )?(?:document|fichier|page))\b",),
    "communications": (r"\b(email bodies|message content|comments?|correspondence|contenu des messages|commentaires?|correspondance)\b",),
    "location": (r"\b(location data|coordinates|latitude|longitude|gps|données de localisation|coordonnées gps)\b",),
    "sensitive_data": (
        r"\b(confidential|private|sensitive)\b.{0,40}\b(?:data|records?|documents?|files?|content|information)\b",
        r"\b(données?|enregistrements?|documents?|fichiers?|contenu|informations?)\s+(?:confidentielles?|privées?|sensibles?)\b",
    ),
}

_SCOPE_PATTERNS = {
    "bulk": (
        r"\b(bulk|mass|batch|broadcast|every recipient|all recipients|entire recipient list|complete recipient list|entire address book|complete address book|address book|en masse|diffusion générale|liste complète des destinataires|carnet d'adresses complet|carnet d'adresses|tous les|toutes les|chaque destinataire)\b",
        r"\ball(?:\s+[a-z0-9_-]+){0,2}\s+(?:users|contacts|records|files|messages|objects|documents|items)\b",
    ),
    "cross_tenant": (
        r"\b(other|another|cross|different|neighboring|neighbouring)[ -]?(tenant|account|organization|project)\b",
        r"\b(?:belong(?:s|ing)?\s+to|owned\s+by).{0,30}\b(?:another|other|different|neighboring|neighbouring)\s+(?:tenant|account|organization|project)\b",
        r"\b(autre|inter|différent(?:e)?|voisin(?:e)?)[ -]?(tenant|compte|organisation|projet)\b",
        r"\bappartenant\s+à.{0,30}\b(?:une?\s+)?autre\s+(?:tenant|compte|organisation|projet)\b",
    ),
    "recursive": (r"\b(recursive(?:ly)?|entire subtree|all descendants|récursi(?:f|ve|vement)|tous les descendants)\b",),
    "public": (
        r"\b(world-readable|tout le monde)\b",
        r"\b(public access|public internet|publicly accessible|accessible to (?:the )?public|access(?:ible)? to anyone|everyone|everybody|anonymous access|accessible anonymously|anonymous visitors?|without authentication|accès public|internet public|accessible à tout le monde|tout le monde peut y accéder|accès anonyme|sans authentification)\b",
        r"\b(visibility|scope|sharing|access|visibilité|portée|partage|accès)\b.{0,20}\b(public|publique?|anonyme)\b",
        r"\b(?:anonymous|unauthenticated)\s+users?\b.{0,40}\b(?:can|may|able to)\s+(?:read|view|access|download)\b",
        r"\butilisateurs?\s+(?:anonymes?|non authentifiés?)\b.{0,40}\b(?:peuvent?|pourront?)\s+(?:lire|voir|accéder|télécharger)\b",
        r"\b(?:anonymous|unauthenticated)\s+users?\b.{0,40}\b(?:can|may|able to)\s+(?:read|view|access|download)\b",
        r"\butilisateurs?\s+(?:anonymes?|non authentifiés?)\b.{0,40}\b(?:peuvent?|pourront?)\s+(?:lire|voir|accéder|télécharger)\b",
    ),
}

_PRIVILEGE_PATTERNS = {
    "administrator": (r"\b(admin(?:istrator)?|owner|root|superuser|administrateur|propriétaire)\b",),
    "access_control": (r"\b(roles?|permissions?|authorization|access control|rôles?|autorisations?|contrôle d'accès)\b",),
    "delegated_identity": (r"\b(impersonat(?:e|ion)|service account|assume role|délégation|compte de service)\b",),
}

_IRREVERSIBLE_PATTERNS = (
    r"\b(permanent(?:ly)?|irreversible|cannot be undone|without recovery|définiti(?:f|ve|vement)|irréversible|sans récupération)\b",
)
_REVERSIBLE_PATTERNS = (
    r"\b(reversible|undo|restore|recover|trash|corbeille|annuler|restaurer|récupérer)\b",
)
_EXTERNAL_TRANSFER_PATTERNS = (
    r"\b(send|forward|transmit|relay|upload|post|share|mirror|copy|envoyer|transmettre|relayer|téléverser|partager|copi(?:er|e|es|ent|é|ée|és|ées))\b.{0,80}\b(external|remote|off-site|third-party|off-platform|outside|url|endpoint|webhook|collector|recipient|public|externe|distant|hors site|tiers|hors plateforme|collecteur|destinataire)\b",
    r"\b(external|remote|off-site|third-party|off-platform|outside|url|endpoint|webhook|collector|recipient|public|externe|distant|hors site|tiers|hors plateforme|collecteur|destinataire)\b.{0,80}\b(send|forward|transmit|relay|upload|post|share|mirror|copy|envoyer|transmettre|relayer|téléverser|partager|copi(?:er|e|es|ent|é|ée|és|ées))\b",
)
_PUBLIC_EXPOSURE_PATTERNS = (
    r"\b(make|publish|share|expose|rendre|publier|partager|exposer)\b.{0,60}\b(public(?:ly)?|accessible to anyone|anyone|anonymous(?:ly)?|anonymous visitors?|without authentication|public(?:que)?|tout le monde|anonyme|sans authentification)\b",
)

_URL_RE = re.compile(r"https?://[^\s)>\]\"']+", re.IGNORECASE)
_SENSITIVE_DATA = {"credentials", "personal_data", "financial_data", "location", "sensitive_data"}
_SENSITIVE_ACTIONS = {"delete", "execute", "authorize", "transact"}
_SENSITIVE_SIDE_EFFECTS = {
    "destructive",
    "external_transfer",
    "code_execution",
    "access_control_change",
    "financial_transaction",
    "public_exposure",
}


@dataclass(frozen=True)
class FactEvidence:
    source: str
    path: str
    excerpt: str

    def to_dict(self) -> dict[str, str]:
        return {
            "source": self.source,
            "path": self.path,
            "excerpt": self.excerpt,
        }


@dataclass(frozen=True)
class SemanticFact:
    value: str
    confidence: float
    evidence: tuple[FactEvidence, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "confidence": round(self.confidence, 3),
            "evidence": [item.to_dict() for item in self.evidence],
        }


@dataclass(frozen=True)
class ToolSemanticFacts:
    actions: tuple[SemanticFact, ...]
    resources: tuple[SemanticFact, ...]
    data_categories: tuple[SemanticFact, ...]
    side_effects: tuple[SemanticFact, ...]
    external_destinations: tuple[SemanticFact, ...]
    privileges: tuple[SemanticFact, ...]
    scopes: tuple[SemanticFact, ...]
    reversibility: str
    unknown_reasons: tuple[str, ...]

    def values(self, category: str, *, sources: set[str] | None = None) -> set[str]:
        facts = getattr(self, category, ())
        if sources is None:
            return {fact.value for fact in facts}
        return {
            fact.value
            for fact in facts
            if any(evidence.source in sources for evidence in fact.evidence)
        }

    @property
    def is_sensitive(self) -> bool:
        return bool(
            self.values("data_categories").intersection(_SENSITIVE_DATA)
            or self.values("actions").intersection(_SENSITIVE_ACTIONS)
            or self.values("side_effects").intersection(_SENSITIVE_SIDE_EFFECTS)
            or self.values("privileges")
            or self.values("scopes").intersection({"bulk", "cross_tenant", "public"})
        )

    @property
    def sensitivity(self) -> str:
        if not self.is_sensitive:
            return "normal"
        if self.values("side_effects").intersection(
            {"code_execution", "access_control_change", "financial_transaction"}
        ) or "credentials" in self.values("data_categories"):
            return "high"
        return "sensitive"

    def to_dict(self) -> dict[str, Any]:
        return {
            "actions": [item.to_dict() for item in self.actions],
            "resources": [item.to_dict() for item in self.resources],
            "data_categories": [item.to_dict() for item in self.data_categories],
            "side_effects": [item.to_dict() for item in self.side_effects],
            "external_destinations": [
                item.to_dict() for item in self.external_destinations
            ],
            "privileges": [item.to_dict() for item in self.privileges],
            "scopes": [item.to_dict() for item in self.scopes],
            "reversibility": self.reversibility,
            "unknown_reasons": list(self.unknown_reasons),
            "is_sensitive": self.is_sensitive,
            "sensitivity": self.sensitivity,
        }


@dataclass(frozen=True)
class _TextSegment:
    source: str
    path: str
    text: str
    confidence: float


class _FactCollector:
    def __init__(self) -> None:
        self._facts: dict[str, dict[str, tuple[float, list[FactEvidence]]]] = {}

    def add(self, category: str, value: str, segment: _TextSegment) -> None:
        category_facts = self._facts.setdefault(category, {})
        confidence, evidence = category_facts.setdefault(value, (0.0, []))
        item = FactEvidence(
            source=segment.source,
            path=segment.path,
            excerpt=_safe_excerpt(segment.text),
        )
        if item not in evidence and len(evidence) < 5:
            evidence.append(item)
        source_bonus = 0.08 if evidence and len({entry.source for entry in evidence}) > 1 else 0.0
        category_facts[value] = (max(confidence, segment.confidence) + source_bonus, evidence)

    def facts(self, category: str) -> tuple[SemanticFact, ...]:
        return tuple(
            SemanticFact(
                value=value,
                confidence=min(0.99, confidence),
                evidence=tuple(evidence),
            )
            for value, (confidence, evidence) in sorted(
                self._facts.get(category, {}).items()
            )
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


def _url_is_documentation_example(text: str, raw_url: str) -> bool:
    start = text.find(raw_url)
    if start < 0:
        return False
    prefix = text[max(0, start - 120) : start]
    return bool(
        re.search(
            r"(?:\be\.g\.|\bfor example\b|\bexample\b|\bsample\b|\bsuch as\b)[^\n]{0,100}$",
            prefix,
            re.IGNORECASE,
        )
    )


def _administrator_privilege_evidenced(segment: _TextSegment) -> bool:
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
            r"\b(require[sd]?|need[sd]?|must have|restricted to)\b.{0,45}"
            r"\b(admin(?:istrator)?|owner|root|superuser)\b"
            r"|\b(grant|assign|elevate|escalate|promote)\b.{0,45}"
            r"\b(admin(?:istrator)?|owner|root|superuser|role|permission|privilege)\b",
            segment.text,
            re.IGNORECASE,
        )
    )


def extract_tool_semantic_facts(tool_snapshot: dict[str, Any]) -> ToolSemanticFacts:
    segments = list(_tool_segments(tool_snapshot))
    collector = _FactCollector()
    for segment in segments:
        _collect_patterns(collector, "actions", _ACTION_PATTERNS, segment)
        _collect_patterns(collector, "resources", _RESOURCE_PATTERNS, segment)
        _collect_patterns(collector, "data_categories", _DATA_PATTERNS, segment)
        _collect_patterns(collector, "scopes", _SCOPE_PATTERNS, segment)
        _collect_patterns(collector, "privileges", _PRIVILEGE_PATTERNS, segment)
        for raw_url in _URL_RE.findall(segment.text):
            if _url_is_documentation_example(segment.text, raw_url):
                continue
            collector.add(
                "external_destinations",
                _public_destination(raw_url),
                segment,
            )
        if _matches_any(segment.text, _EXTERNAL_TRANSFER_PATTERNS):
            collector.add("side_effects", "external_transfer", segment)
        if _matches_any(segment.text, _PUBLIC_EXPOSURE_PATTERNS):
            collector.add("side_effects", "public_exposure", segment)
        if (
            segment.source == "execution"
            and _matches_any(segment.text, _RESOURCE_PATTERNS["process"])
            and not _execution_is_explicitly_negated(segment.text)
        ):
            collector.add("actions", "execute", segment)

    action_values = {item.value for item in collector.facts("actions")}

    external_destinations = collector.facts("external_destinations")
    if "send" in action_values and external_destinations:
        send_fact = next(
            item for item in collector.facts("actions") if item.value == "send"
        )
        for evidence in send_fact.evidence:
            collector.add(
                "side_effects",
                "external_transfer",
                _TextSegment(
                    source=evidence.source,
                    path=evidence.path,
                    text=evidence.excerpt,
                    confidence=send_fact.confidence,
                ),
            )

    public_exposure = next(
        (
            item
            for item in collector.facts("side_effects")
            if item.value == "public_exposure"
        ),
        None,
    )
    if public_exposure is not None:
        for evidence in public_exposure.evidence:
            collector.add(
                "scopes",
                "public",
                _TextSegment(
                    source=evidence.source,
                    path=evidence.path,
                    text=evidence.excerpt,
                    confidence=public_exposure.confidence,
                ),
            )
    for action, side_effect in {
        "create": "state_change",
        "update": "state_change",
        "delete": "destructive",
        "send": "communication",
        "execute": "code_execution",
        "authorize": "access_control_change",
        "transact": "financial_transaction",
    }.items():
        if action not in action_values:
            continue
        action_fact = next(
            item for item in collector.facts("actions") if item.value == action
        )
        for evidence in action_fact.evidence:
            collector.add(
                "side_effects",
                side_effect,
                _TextSegment(
                    source=evidence.source,
                    path=evidence.path,
                    text=evidence.excerpt,
                    confidence=action_fact.confidence,
                ),
            )

    combined_text = " ".join(segment.text for segment in segments)
    if _matches_any(combined_text, _IRREVERSIBLE_PATTERNS):
        reversibility = "irreversible"
    elif _matches_any(combined_text, _REVERSIBLE_PATTERNS):
        reversibility = "reversible"
    elif "destructive" in {
        item.value for item in collector.facts("side_effects")
    }:
        reversibility = "unknown"
    elif action_values.intersection({"create", "update", "send", "authorize", "transact"}):
        reversibility = "unknown"
    else:
        reversibility = "not_applicable"

    meaningful_sources = {"description", "input_schema", "output_schema", "annotations", "execution"}
    evidenced_actions = {
        fact.value
        for fact in collector.facts("actions")
        if any(item.source in meaningful_sources for item in fact.evidence)
    }
    evidenced_resources = {
        fact.value
        for fact in collector.facts("resources")
        if any(item.source in meaningful_sources for item in fact.evidence)
    }
    unknown_reasons: list[str] = []
    if not evidenced_actions:
        unknown_reasons.append("action_not_evidenced")
    if "health_check" not in evidenced_actions and not evidenced_resources:
        unknown_reasons.append("resource_not_evidenced")

    return ToolSemanticFacts(
        actions=collector.facts("actions"),
        resources=collector.facts("resources"),
        data_categories=collector.facts("data_categories"),
        side_effects=collector.facts("side_effects"),
        external_destinations=collector.facts("external_destinations"),
        privileges=collector.facts("privileges"),
        scopes=collector.facts("scopes"),
        reversibility=reversibility,
        unknown_reasons=tuple(unknown_reasons),
    )


def iter_schema_fields(schema: dict[str, Any]) -> Iterable[tuple[str, str, dict[str, Any]]]:
    yield from _walk_schema(schema, "$")


def _tool_segments(tool_snapshot: dict[str, Any]) -> Iterable[_TextSegment]:
    name = str(tool_snapshot.get("name") or "")
    if name:
        yield _TextSegment("name", "$.name", _humanize_identifier(name), 0.55)
    description = strip_documentation_examples(
        str(tool_snapshot.get("description") or "")
    )
    if description.strip():
        yield _TextSegment("description", "$.description", description, 0.82)
    for source, key in (("input_schema", "input_schema"), ("output_schema", "output_schema")):
        schema = tool_snapshot.get(key)
        if not isinstance(schema, dict):
            continue
        for path, field_name, field in iter_schema_fields(schema):
            fragments = [_humanize_identifier(field_name)]
            for metadata_key in ("title", "description", "format", "const"):
                value = field.get(metadata_key)
                if isinstance(value, (str, int, float, bool)):
                    fragments.append(str(value))
            enum_values = field.get("enum")
            if isinstance(enum_values, list):
                fragments.extend(str(value) for value in enum_values[:20])
            yield _TextSegment(source, path, " ".join(fragments), 0.76)
    for source, key, confidence in (
        ("annotations", "annotations", 0.76),
        ("execution", "execution", 0.9),
    ):
        value = tool_snapshot.get(key)
        for path, text in _metadata_values(value, f"$.{key}"):
            yield _TextSegment(source, path, text, confidence)


def _walk_schema(
    node: Any,
    path: str,
    *,
    field_name: str = "",
) -> Iterable[tuple[str, str, dict[str, Any]]]:
    if not isinstance(node, dict):
        return
    if field_name:
        yield path, field_name, node
    properties = node.get("properties")
    if isinstance(properties, dict):
        for name, child in properties.items():
            if isinstance(child, dict):
                yield from _walk_schema(
                    child,
                    f"{path}.properties.{name}",
                    field_name=str(name),
                )
    for keyword in ("items", "contains", "additionalProperties", "not", "if", "then", "else"):
        child = node.get(keyword)
        if isinstance(child, dict):
            yield from _walk_schema(child, f"{path}.{keyword}", field_name=field_name)
    for keyword in ("allOf", "anyOf", "oneOf", "prefixItems"):
        children = node.get(keyword)
        if isinstance(children, list):
            for index, child in enumerate(children):
                if isinstance(child, dict):
                    yield from _walk_schema(
                        child,
                        f"{path}.{keyword}[{index}]",
                        field_name=field_name,
                    )
    for keyword in ("$defs", "definitions", "dependentSchemas", "patternProperties"):
        children = node.get(keyword)
        if isinstance(children, dict):
            for name, child in children.items():
                if isinstance(child, dict):
                    yield from _walk_schema(
                        child,
                        f"{path}.{keyword}.{name}",
                        field_name=str(name),
                    )


def _metadata_values(value: Any, path: str) -> Iterable[tuple[str, str]]:
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, (int, float, bool)):
        yield path, str(value)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _metadata_values(child, f"{path}[{index}]")
    elif isinstance(value, dict):
        for key, child in value.items():
            yield from _metadata_values(child, f"{path}.{key}")


def _collect_patterns(
    collector: _FactCollector,
    category: str,
    patterns_by_value: dict[str, tuple[str, ...]],
    segment: _TextSegment,
) -> None:
    for value, patterns in patterns_by_value.items():
        accepted = False
        for pattern in patterns:
            for match in re.finditer(pattern, segment.text, re.IGNORECASE):
                if _match_is_non_operational(segment.text, match):
                    continue
                if _fact_is_ignored(category, value, segment, match=match):
                    continue
                collector.add(category, value, segment)
                accepted = True
                break
            if accepted:
                break


def operational_pattern_search(pattern: str, text: str) -> re.Match[str] | None:
    for match in re.finditer(pattern, text, re.IGNORECASE):
        if not _match_is_non_operational(text, match):
            return match
    return None


def _matches_any(text: str, patterns: Iterable[str]) -> bool:
    return any(operational_pattern_search(pattern, text) for pattern in patterns)


def _match_is_non_operational(text: str, match: re.Match[str]) -> bool:
    before = text[max(0, match.start() - 120) : match.start()]
    after = text[match.end() : min(len(text), match.end() + 50)]
    immediate_before = before[-48:]
    matched_text = match.group(0)
    if re.search(
        r"\b(?:without|sans)\b.{0,35}\b(?:execut(?:e|es|ed|ing)|run(?:s|ning)?|launch(?:es|ed|ing)?|exécut(?:er|e|es|ent|é|ée|és|ées)|lanc(?:er|e|es|ent|é|ée|és|ées))\b",
        matched_text,
        re.IGNORECASE,
    ):
        return True
    if re.search(r"\bne\s*$", immediate_before, re.IGNORECASE) and re.search(
        r"\b(?:pas|jamais|plus)\b",
        matched_text,
        re.IGNORECASE,
    ):
        return True
    if re.search(
        r"\b(?:not|never|pas|jamais)\b.{0,25}\b(?:execut(?:e|es|ed|ing)|run(?:s|ning)?|launch(?:es|ed|ing)?|exécut(?:er|e|es|ent|é|ée|és|ées)|lanc(?:er|e|es|ent|é|ée|és|ées))\b",
        matched_text,
        re.IGNORECASE,
    ):
        return True
    if re.search(
        r"(?:\b(?:does|do|did|is|are|was|were|will|would|can|could|should|must)\s+not"
        r"|\b(?:never|without)\b|\b(?:doesn't|don't|didn't|isn't|aren't|wasn't|weren't|won't|wouldn't|can't|couldn't|shouldn't|mustn't)\b)"
        r"(?:\s+\w+){0,3}\s*$",
        immediate_before,
        re.IGNORECASE,
    ):
        return True
    if re.search(
        r"\bne\s+(?:(?:\w+)\s+){0,3}(?:pas|jamais|plus)(?:\s+(?:de|d['’]|à))?\s*$",
        immediate_before,
        re.IGNORECASE,
    ):
        return True
    if re.search(r"\bne\s+(?:\w+\s+){0,3}$", immediate_before, re.IGNORECASE) and re.match(
        r"(?:\s+\w+){0,3}\s+(?:pas|jamais|plus)\b",
        after,
        re.IGNORECASE,
    ):
        return True
    if re.search(
        r"\bn['’][a-zà-ÿ]+(?:\s+[a-zà-ÿ]+){0,3}\s+(?:pas|jamais|plus)(?:\s+(?:de|d['’]|à))?\s*$",
        immediate_before,
        re.IGNORECASE,
    ):
        return True
    if re.search(
        r"\bn['’][a-zà-ÿ]+.{0,50}\b(?:pas|jamais|plus)\b.{0,50}$",
        before,
        re.IGNORECASE,
    ):
        return True
    if re.search(r"\bn['’]\s*$", immediate_before, re.IGNORECASE):
        french_tail = text[match.start() : min(len(text), match.end() + 40)]
        if re.search(r"\b(?:pas|jamais|plus)\b", french_tail, re.IGNORECASE):
            return True
    if re.search(r"\bsans(?:\s+jamais)?(?:\s+\w+){0,3}\s*$", immediate_before, re.IGNORECASE):
        return True

    sentence_before = re.split(r"[.!?\n]", before)[-1]
    if re.search(
        r"\b(?:documentation|docs?|guides?|manuals?|manuels?|examples?|samples?)\b"
        r".{0,80}\b(?:about|on|regarding|concerning|explaining|describing|how\s+to|for|sur|concernant|expliquant|décrivant|comment)\b"
        r".{0,80}$",
        sentence_before,
        re.IGNORECASE,
    ):
        return True
    if re.search(
        r"\b(?:documentation|docs?|guides?|manuals?|manuels?|examples?|samples?)\b"
        r".{0,80}\b(?:contains?|mentions?|quotes?|references?|includes?|contient|contiennent|mentionne|mentionnent|cite|citent|inclut|incluent)\b"
        r".{0,80}(?:\b(?:phrase|term|word|expression|terme|mot)\b.{0,30})?$",
        sentence_before,
        re.IGNORECASE,
    ):
        return True
    return False


def _execution_is_explicitly_negated(text: str) -> bool:
    patterns = (
        r"\b(?:does|do|did|will|would|can|could|should|must)\s+not\s+(?:\w+\s+){0,3}(?:execute|run|launch|invoke)\b",
        r"\b(?:never|without)\s+(?:\w+\s+){0,3}(?:execut(?:e|ing)|run(?:ning)?|launch(?:ing)?|invok(?:e|ing))\b",
        r"\bn['’]\s*(?:exécute|execute|lance|invoque)\b.{0,30}\b(?:pas|jamais|plus)\b",
        r"\bne\s+(?:\w+\s+){0,3}(?:exécute|execute|lance|invoque)\b.{0,30}\b(?:pas|jamais|plus)\b",
        r"\bsans\s+(?:jamais\s+)?(?:exécuter|executer|lancer|invoquer)\b",
    )
    return any(re.search(pattern, text, re.IGNORECASE) for pattern in patterns)


def _fact_is_ignored(
    category: str,
    value: str,
    segment: _TextSegment,
    *,
    match: re.Match[str] | None = None,
) -> bool:
    if category == "privileges" and value == "administrator":
        return not _administrator_privilege_evidenced(segment)

    before = segment.text[: match.start()] if match is not None else ""
    after = segment.text[match.end() :] if match is not None else ""
    matched = match.group(0).lower() if match is not None else ""

    if category == "actions" and value in {"create", "update", "delete", "send", "transact"}:
        read_like_before = bool(
            re.search(
                r"\b(read(?:s|ing)?|fetch(?:es|ed|ing)?|get(?:s|ting)?|retrieve(?:s|d|ing)?|inspect(?:s|ed|ing)?|view(?:s|ed|ing)?|list(?:s|ed|ing)?|search(?:es|ed|ing)?|lire|lit|liste|consulter|rechercher)\b.{0,28}$",
                before,
                re.IGNORECASE,
            )
        )
        nominal_after = bool(
            re.match(
                r"\s+(?:"
                r"(?:payment|transaction|transfer|refund|charge|paiement|transaction|virement|remboursement|débit)\s+"
                r"(?:status|state|history|details?|id|identifier|reference|metadata|record(?:s)?|date|policy|"
                r"statut|état|historique|détails?|identifiant|référence|métadonnées?|enregistrements?|date|politique)"
                r"|status|state|history|details?|id|identifier|reference|metadata|record(?:s)?|date|flag|setting|"
                r"option|mode|field|property|policy|permission(?:s)?|access|list|result|results|information|info|"
                r"statut|état|historique|détails?|identifiant|référence|métadonnées?|drapeau|paramètre|option|champ|"
                r"propriété|politique|permission(?:s)?|accès|liste|résultat(?:s)?)\b",
                after,
                re.IGNORECASE,
            )
        )
        if read_like_before and nominal_after:
            return True
        if value == "send" and matched.startswith("post") and (
            re.search(r"\b(?:blog|forum|article|social)\s*$", before, re.IGNORECASE)
            or nominal_after
        ):
            return True

    if category not in {"data_categories", "resources"} or value not in {
        "credentials",
        "secret_store",
    }:
        return False

    field_name = segment.path.rsplit(".", 1)[-1].lower()
    credential_field = bool(
        re.fullmatch(
            r"(?:api_?)?(?:key|token|secret|password|credential)s?",
            field_name,
        )
    )
    conceptual_credential = bool(
        re.match(
            r"\s+(?:count|length|budget|usage|limit|estimate|statistics?|policy|policies|documentation|docs?|guide|rotation|format|schema|metadata|name|type|status|state|history|counting|compte|longueur|budget|usage|limite|estimation|statistiques?|politique|documentation|guide|rotation|format|schéma|métadonnées?|nom|type|statut|état|historique)\b",
            after,
            re.IGNORECASE,
        )
    )
    if conceptual_credential and not credential_field:
        return True

    credential_operation = bool(
        operational_pattern_search(
            r"\b(read(?:s|ing)?|get(?:s|ting)?|fetch(?:es|ed|ing)?|retrieve(?:s|d|ing)?|obtain(?:s|ed|ing)?|acquir(?:e|es|ed|ing)|harvest(?:s|ed|ing)?|gather(?:s|ed|ing)?|access(?:es|ed|ing)?|request(?:s|ed|ing)?|collect(?:s|ed|ing)?|capture(?:s|d|ing)?|extract(?:s|ed|ing)?|expose(?:s|d|ing)?|return(?:s|ed|ing)?|store(?:s|d|ing)?|retain(?:s|ed|ing)?|save(?:s|d|ing)?|lire|lit|récup(?:érer|ère|ères|èrent|éré|érée|érés|érées)|obtenir|obtiens|obtient|obtenez|acqu(?:érir|iert|iers|érez)|récolt(?:er|e|es|ent|é|ée|és|ées)|rassembl(?:er|e|es|ent|é|ée|és|ées)|accéder|demander|collecter|extraire|exposer|conserver|sauvegard(?:er|e|es|ent|é|ée|és|ées)|stock(?:er|e|es|ent|é|ée|és|ées))\w*"
            r".{0,70}\b(credentials?|tokens?|passwords?|api[_ -]?keys?|secrets?|authentication material|auth material|bearer credentials?|identifiants?|jetons?|mots? de passe|clés? api|matériel d'authentification)\b",
            segment.text,
        )
    )
    if not credential_field and not credential_operation:
        return True
    return bool(
        re.search(
            r"\b(credentials?|tokens?|passwords?|api[_ -]?keys?|secrets?)\b"
            r".{0,70}\b(not requested|not collected|never exposed|managed by|handled by)\b"
            r"|\b(does not|do not|never)\b.{0,40}\b(request|collect|capture|expose)\b"
            r".{0,30}\b(credentials?|tokens?|passwords?|api[_ -]?keys?|secrets?)\b",
            segment.text,
            re.IGNORECASE,
        )
    )


def _humanize_identifier(value: str) -> str:
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", value)
    return re.sub(r"[_\-.]+", " ", spaced)


def _public_destination(raw_url: str) -> str:
    parsed = urlsplit(raw_url.rstrip(".,;"))
    if not parsed.hostname:
        return "external_url"
    port = f":{parsed.port}" if parsed.port else ""
    return f"{parsed.scheme.lower()}://{parsed.hostname.lower()}{port}"


def _safe_excerpt(value: str, limit: int = 180) -> str:
    text = re.sub(r"\s+", " ", str(value)).strip()
    text = re.sub(
        r"(?i)(token|password|secret|api[_ -]?key|credential)\s*[=:]\s*[^\s,;]+",
        r"\1=<redacted>",
        text,
    )
    if len(text) > limit:
        return f"{text[:limit]}..."
    return text
