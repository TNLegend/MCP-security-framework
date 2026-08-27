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
        r"\b(read|fetch|get|retrieve|inspect|view|download|lire|récupérer|consulter|télécharger)\b",
    ),
    "search": (
        r"\b(search|query|find|lookup|filter|rechercher|chercher|interroger|filtrer)\b",
    ),
    "list": (r"\b(list|enumerate|browse|lister|énumérer|parcourir)\b",),
    "create": (r"\b(create|add|insert|upload|publish|créer|ajouter|insérer|téléverser|publier)\b",),
    "update": (r"\b(update|edit|modify|move|rename|set|mettre à jour|modifier|déplacer|renommer)\b",),
    "delete": (r"\b(delete|remove|erase|drop|truncate|supprimer|effacer)\b",),
    "send": (r"\b(send|forward|transmit|upload|post|notify|envoyer|transmettre|téléverser|notifier)\b",),
    "execute": (
        r"\b(execute|run|launch|invoke|exécuter|lancer|invoquer)\b.{0,35}\b(shell|scripts?|process(?:es)?|executables?|operating system commands?|scripts?|processus|exécutables?|commandes? système)\b",
        r"\b(shell|scripts?|process(?:es)?|executables?|operating system commands?|processus|exécutables?|commandes? système)\b.{0,25}\b(execution|execute|run|exécution|exécuter|lancer)\b",
        r"\bshell\s+commands?\b",
    ),
    "authorize": (
        r"\b(grant|revoke|authorize|assign|elevate|accorder|révoquer|autoriser|attribuer|élever)\b.{0,35}\b(role|permission|access|privilege|rôle|autorisation|accès|privilège)\b",
    ),
    "transact": (
        r"\b(pay|charge|transfer|purchase|refund|payer|facturer|virer|acheter|rembourser)\b",
        r"\b(initiate|create|issue|start|initier|créer|émettre)\b.{0,30}\b(payment|transfer|refund|paiement|virement|remboursement)\b",
    ),
    "health_check": (r"\b(ping|health(?:check)?|readiness|liveness|status check)\b",),
}

_RESOURCE_PATTERNS = {
    "filesystem": (r"\b(filesystem|files?|folders?|directories|paths?|système de fichiers|fichiers?|dossiers?|répertoires?|chemins?)\b",),
    "document": (r"\b(documents?|pages?|notes?|wikis?|content|markdown|documents?|contenu)\b",),
    "database": (r"\b(databases?|schemas?|tables?|rows?|records?|collections?|sql|bases? de données|enregistrements?)\b",),
    "message": (r"\b(emails?|messages?|comments?|mailboxes?|recipients?|courriels?|commentaires?|destinataires?)\b",),
    "calendar": (r"\b(calendars?|events?|meetings?|calendriers?|événements?|réunions?)\b",),
    "cloud_storage": (r"\b(buckets?|containers?|cloud objects?|blobs?|storage|stockage|objets? cloud)\b",),
    "identity": (r"\b(users?|identities|utilisateurs?|identités)\b",),
    "secret_store": (r"\b(secrets?|credentials?|tokens?|passwords?|api[_ -]?keys?|vault|identifiants?|jetons?|mots? de passe|clés? api)\b",),
    "source_code": (r"\b(repositories|repository|commits?|branches?|pull requests?|source code|dépôts?|code source)\b",),
    "payment": (r"\b(payments?|transactions?|invoices?|refunds?|merchant|paiements?|virements?|factures?|remboursements?)\b",),
    "network_endpoint": (r"\b(urls?|uris?|endpoints?|webhooks?|hosts?|api endpoints?|points? de terminaison)\b",),
    "process": (r"\b(shell|scripts?|process(?:es)?|executables?|operating system commands?|processus|exécutables?|commandes? système)\b", r"\bshell\s+commands?\b"),
}

_DATA_PATTERNS = {
    "credentials": (r"\b(credentials?|tokens?|passwords?|api[_ -]?keys?|secrets?|identifiants?|jetons?|mots? de passe|clés? api)\b",),
    "personal_data": (r"\b(personal data|personally identifiable|pii|phone numbers?|home addresses?|postal addresses?|données personnelles|adresses? postales|coordonnées personnelles)\b",),
    "financial_data": (r"\b(financial data|bank accounts?|card numbers?|balances?|données financières|comptes? bancaires|soldes?)\b",),
    "source_code": (r"\b(source code|repositories|commits?|code source|dépôts?)\b",),
    "document_content": (r"\b(document content|page content|file contents?|markdown|contenu (?:du )?(?:document|fichier|page))\b",),
    "communications": (r"\b(email bodies|message content|comments?|correspondence|contenu des messages|commentaires?|correspondance)\b",),
    "location": (r"\b(location data|coordinates|latitude|longitude|gps|données de localisation|coordonnées gps)\b",),
}

_SCOPE_PATTERNS = {
    "bulk": (r"\b(bulk|mass|batch|all (?:users|contacts|records)|every recipient|en masse|tous les|toutes les)\b",),
    "cross_tenant": (r"\b(other|another|cross)[ -]?(tenant|account|organization|project)\b", r"\b(autre|inter)[ -]?(tenant|compte|organisation|projet)\b"),
    "recursive": (r"\b(recursive(?:ly)?|entire subtree|all descendants|récursi(?:f|ve|vement)|tous les descendants)\b",),
    "public": (r"\b(public|anyone|anonymous|world-readable|tout le monde|anonyme)\b",),
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
    r"\b(send|forward|transmit|upload|post|share|envoyer|transmettre|téléverser|partager)\b.{0,60}\b(external|remote|url|endpoint|webhook|recipient|public|externe|distant|destinataire)\b",
    r"\b(external|remote|url|endpoint|webhook|recipient|public|externe|distant|destinataire)\b.{0,60}\b(send|forward|transmit|upload|post|share|envoyer|transmettre|téléverser|partager)\b",
)
_PUBLIC_EXPOSURE_PATTERNS = (
    r"\b(make|publish|share|rendre|publier|partager)\b.{0,40}\b(public|anyone|anonymous|tout le monde|anonyme)\b",
)

_URL_RE = re.compile(r"https?://[^\s)>\]\"']+", re.IGNORECASE)
_SENSITIVE_DATA = {"credentials", "personal_data", "financial_data", "location"}
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
        if segment.source == "execution" and _matches_any(
            segment.text,
            _RESOURCE_PATTERNS["process"],
        ):
            collector.add("actions", "execute", segment)

    action_values = {item.value for item in collector.facts("actions")}
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
    if evidenced_actions.difference({"health_check"}) and not evidenced_resources:
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
        if _matches_any(segment.text, patterns) and not _fact_is_ignored(
            category,
            value,
            segment,
        ):
            collector.add(category, value, segment)


def _matches_any(text: str, patterns: Iterable[str]) -> bool:
    return any(re.search(pattern, text, re.IGNORECASE) for pattern in patterns)


def _fact_is_ignored(
    category: str,
    value: str,
    segment: _TextSegment,
) -> bool:
    if category == "privileges" and value == "administrator":
        return not _administrator_privilege_evidenced(segment)
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
    credential_operation = bool(
        re.search(
            r"\b(read|access|request|collect|capture|extract|expose|return|lire|accéder|demander|collecter|extraire|exposer)\w*"
            r".{0,50}\b(credentials?|tokens?|passwords?|api[_ -]?keys?|secrets?|identifiants?|jetons?|mots? de passe|clés? api)\b",
            segment.text,
            re.IGNORECASE,
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
