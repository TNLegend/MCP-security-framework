"""Clause-level MCP metadata extraction experiment. SHADOW ONLY.

Does not import or alter the operational analysis, contract or admission path.
All outputs are untrusted hypotheses, never permissions or executable findings.
"""

from __future__ import annotations
from app.services.tda.security_guards.patterns import _ACTION_PATTERNS
from app.services.tda.security_guards.patterns import _RESOURCE_PATTERNS
from app.services.tda.security_guards.propositions import extract_propositions
from dataclasses import dataclass, asdict
from enum import StrEnum
from hashlib import sha256
from pathlib import Path
from typing import Any, Protocol
import importlib
from itertools import islice
import re

REVISION = "clause-ir-proto-v0.2-shadow"


@dataclass(frozen=True)
class Budgets:
    nodes: int = 16384
    depth: int = 48
    total_chars: int = 8000
    field_chars: int = 3000
    clauses: int = 512


@dataclass(frozen=True)
class Span:
    source_path: str
    start: int
    end: int
    excerpt: str


class Mood(StrEnum):
    DECLARATIVE = "DECLARATIVE"
    IMPERATIVE = "IMPERATIVE"
    MODAL_ADDRESSED = "MODAL_ADDRESSED"
    FRAGMENT = "FRAGMENT"
    UNPARSED = "UNPARSED"


class Party(StrEnum):
    TOOL = "TOOL"
    AGENT = "AGENT"
    USER = "USER"
    THIRD_PARTY = "THIRD_PARTY"
    UNKNOWN = "UNKNOWN"


class Framing(StrEnum):
    ACTIVE = "ACTIVE"
    QUOTED = "QUOTED"
    EXAMPLE = "EXAMPLE"
    HYPOTHETICAL = "HYPOTHETICAL"


@dataclass(frozen=True)
class Predicate:
    lemma: str
    surface: Span
    action_class: str | None
    negated: bool
    negation_cue: Span | None


@dataclass(frozen=True)
class Argument:
    role: str
    span: Span
    resource_class: str | None
    referenced_tool: str | None = None
    parameter_name: str | None = None
    literal_value: str | None = None


@dataclass(frozen=True)
class Clause:
    id: str
    span: Span
    lang: str
    mood: Mood
    addressee: Party
    actor: Party
    actor_evidence: Span | None
    predicates: tuple[Predicate, ...]
    arguments: tuple[Argument, ...]
    condition: Span | None
    framing: Framing
    coordinated_with: tuple[str, ...]
    unresolved: tuple[str, ...]
    condition_scope: Span | None = None
    condition_relation: str | None = None
    actor_alternatives: tuple[Party, ...] = ()


@dataclass(frozen=True)
class ClauseIR:
    revision: str
    parser: dict[str, Any]
    clauses: tuple[Clause, ...]
    coverage: dict[str, Any]
    omissions: tuple[dict[str, Any], ...]
    shadow_only: bool = True
    creates_permissions: bool = False


class ParserBackend(Protocol):
    def parse(self, text: str, lang: str) -> Any: ...

    def identity(self) -> dict[str, Any]: ...


_LANGUAGE_MARKERS = {
    "en": re.compile(
        "\\b(?:the|this|tool|before|after|when|and|file|reads|using|must)\\b", re.I
    ),
    "fr": re.compile(
        "\\b(?:les|des|cet|outil|avant|après|quand|lorsque|fichier|vous|utilisez)\\b",
        re.I,
    ),
    "es": re.compile(
        "\\b(?:los|las|esta|herramienta|antes|después|cuando|archivo|usa|para)\\b", re.I
    ),
}
_AGENT = {
    "you",
    "agent",
    "assistant",
    "model",
    "vous",
    "tu",
    "agente",
    "asistente",
    "usted",
}
_TOOL = {
    "tool",
    "service",
    "server",
    "outil",
    "serveur",
    "herramienta",
    "servicio",
    "servidor",
}
_USER = {"user", "utilisateur", "usuario"}
_COND = {
    "if",
    "unless",
    "when",
    "before",
    "after",
    "si",
    "quand",
    "lorsque",
    "avant",
    "après",
    "cuando",
    "antes",
    "después",
}
_NEG = {"not", "n't", "never", "ne", "pas", "jamais", "no", "nunca"}
_EXAMPLES = re.compile("(?im)^\\s*(?:examples?|samples?|exemples?|ejemplos?)\\s*:")
_REFS = re.compile("[\\w.-]+", re.UNICODE)


def detect_language(text: str) -> str:
    scores = {
        lang: len(p.findall(text[:3000])) for lang, p in _LANGUAGE_MARKERS.items()
    }
    top = max(scores.values(), default=0)
    return (
        next((lang for lang, n in scores.items() if n == top))
        if top and list(scores.values()).count(top) == 1
        else "other"
    )


def _ptr(base: str, key: Any) -> str:
    return base + "/" + str(key).replace("~", "~0").replace("/", "~1")


def _span(path: str, raw: str, a: int, b: int) -> Span:
    if not 0 <= a <= b <= len(raw):
        raise ValueError("invalid original-source offsets")
    return Span(path, a, b, raw[a:b])


def _fields(snapshot: dict, budgets: Budgets):
    fields, omissions = ([], [])
    stack = [
        (_ptr("", k), snapshot[k], 1, frozenset())
        for k in reversed(
            (
                "name",
                "description",
                "input_schema",
                "output_schema",
                "annotations",
                "execution",
            )
        )
        if k in snapshot
    ]
    total, visited = (0, 0)
    while stack and visited < budgets.nodes:
        path, value, depth, parents = stack.pop()
        visited += 1
        if depth > budgets.depth:
            omissions.append({"source_path": path, "reason": "depth_budget"})
            continue
        if isinstance(value, (dict, list)):
            if id(value) in parents:
                omissions.append({"source_path": path, "reason": "cyclic_metadata"})
                continue
            remaining = max(0, budgets.nodes - visited - len(stack))
            children = list(
                islice(
                    value.items() if isinstance(value, dict) else enumerate(value),
                    remaining,
                )
            )
            if len(value) > remaining:
                omissions.append({"source_path": path, "reason": "node_budget"})
            for key, item in reversed(children):
                stack.append((_ptr(path, key), item, depth + 1, parents | {id(value)}))
            continue
        if not isinstance(value, str):
            continue
        if not path.endswith("/description"):
            if re.search("/(?:examples?|default)(?:/|$)", path, re.I):
                omissions.append(
                    {
                        "source_path": path,
                        "reason": "example_or_default_not_semantically_parsed",
                    }
                )
            continue
        if re.search("/(?:examples?|default)(?:/|$)", path, re.I):
            omissions.append(
                {
                    "source_path": path,
                    "reason": "example_or_default_not_semantically_parsed",
                }
            )
            continue
        n = min(len(value), budgets.field_chars, max(0, budgets.total_chars - total))
        if n < len(value):
            omissions.append(
                {
                    "source_path": path,
                    "reason": "character_budget",
                    "original_chars": len(value),
                    "retained_chars": n,
                }
            )
        if n:
            fields.append((path, value, n))
            total += n
        if total >= budgets.total_chars:
            omissions.append({"source_path": "", "reason": "total_chars_budget"})
            break
    if stack:
        omissions.append(
            {
                "source_path": "",
                "reason": "unprocessed_metadata_nodes",
                "count": len(stack),
            }
        )
    return (fields, omissions, visited)


class SpacyParserBackend:
    """Explicit locally installed spaCy model loading, no auto-download.

    The manifest must list every model file with its SHA-256 for pinned mode.
    In an unpinned lab run identity clearly says NOT_ATTESTED.
    """

    _ALLOWED = {
        "en_core_web_sm",
        "fr_core_news_sm",
        "fr_core_news_md",
        "es_core_news_sm",
        "es_core_news_md",
    }

    def __init__(
        self, model_names: dict[str, str], *, pinned_manifest: dict | None = None
    ) -> None:
        import spacy

        if not model_names or set(model_names) - {"en", "fr", "es"}:
            raise ValueError("unsupported model language mapping")
        self._name = dict(model_names)
        self._models = {}
        self._version = spacy.__version__
        for lang, name in model_names.items():
            if name not in self._ALLOWED or not name.startswith(lang + "_"):
                raise ValueError("unapproved spaCy model name")
            if pinned_manifest is not None:
                entry = next(
                    (
                        m
                        for m in pinned_manifest.get("models", [])
                        if m.get("name") == name
                    ),
                    None,
                )
                if not entry or not entry.get("file_entries"):
                    raise ValueError("model not present in pinned manifest")
                mod = importlib.import_module(name)
                folder = Path(mod.__file__).resolve().parent
                expected = {f["name"]: f["sha256"] for f in entry["file_entries"]}
                actual = {
                    p.relative_to(folder).as_posix()
                    for p in folder.rglob("*")
                    if p.is_file() and "__pycache__" not in p.parts
                }
                if actual != set(expected):
                    raise ValueError("model file inventory changed")
                for rel, digest in expected.items():
                    f = folder.joinpath(*rel.split("/"))
                    if sha256(f.read_bytes()).hexdigest() != digest:
                        raise ValueError("model sha256 mismatch")
            self._models[lang] = spacy.load(name, disable=["ner"])
        self._pinned = pinned_manifest is not None

    def parse(self, text: str, lang: str) -> Any:
        if lang not in self._models:
            raise LookupError("model_not_available")
        return self._models[lang](text)

    def identity(self) -> dict[str, Any]:
        return {
            "backend": "spaCy",
            "version": self._version,
            "models": self._name,
            "attestation": "LOCAL_SHA256_VERIFIED" if self._pinned else "NOT_ATTESTED",
        }


class UnavailableParserBackend:
    """Explicit unavailable parser state; no inference and no permission."""

    def __init__(self, reason: str = "model_not_available") -> None:
        self.reason = reason

    def parse(self, text: str, lang: str) -> Any:
        raise RuntimeError(self.reason)

    def identity(self) -> dict[str, Any]:
        return {
            "backend": "UNAVAILABLE",
            "reason": self.reason,
            "attestation": "NOT_AVAILABLE",
        }


_ACTION_LEMMAS = {
    "read": {
        "read",
        "retrieve",
        "fetch",
        "download",
        "get",
        "inspect",
        "lire",
        "récupérer",
        "consulter",
        "obtenir",
        "télécharger",
        "leer",
        "obtener",
        "recuperar",
        "descargar",
        "consultar",
    },
    "search": {
        "search",
        "find",
        "query",
        "lookup",
        "explore",
        "rechercher",
        "chercher",
        "trouver",
        "explorer",
        "buscar",
        "encontrar",
        "consultar",
        "explorar",
    },
    "list": {
        "list",
        "enumerate",
        "browse",
        "lister",
        "énumérer",
        "listar",
        "enumerar",
        "mostrar",
    },
    "create": {
        "create",
        "add",
        "insert",
        "publish",
        "generate",
        "créer",
        "ajouter",
        "générer",
        "publicar",
        "crear",
        "agregar",
        "generar",
    },
    "update": {
        "update",
        "edit",
        "modify",
        "write",
        "set",
        "apply",
        "save",
        "store",
        "record",
        "enregistrer",
        "appliquer",
        "modifier",
        "mettre",
        "écrire",
        "guardar",
        "registrar",
        "aplicar",
        "editar",
        "modificar",
        "actualizar",
    },
    "delete": {
        "delete",
        "remove",
        "erase",
        "destroy",
        "purge",
        "supprimer",
        "effacer",
        "détruire",
        "eliminar",
        "borrar",
        "suprimir",
        "destruir",
    },
    "send": {
        "send",
        "transmit",
        "forward",
        "notify",
        "post",
        "envoyer",
        "transmettre",
        "notifier",
        "enviar",
        "mandar",
        "transmitir",
        "notificar",
    },
    "execute": {"execute", "run", "launch", "exécuter", "lancer", "ejecutar", "lanzar"},
    "authorize": {
        "authorize",
        "grant",
        "revoke",
        "assign",
        "autoriser",
        "accorder",
        "révoquer",
        "autorizar",
        "conceder",
        "revocar",
    },
    "transact": {
        "pay",
        "charge",
        "transfer",
        "refund",
        "payer",
        "facturer",
        "rembourser",
        "pagar",
        "cobrar",
        "transferir",
        "reembolsar",
    },
}
_ROOT_FALLBACKS = {
    "en": {
        "search",
        "list",
        "read",
        "send",
        "delete",
        "create",
        "update",
        "fetch",
        "retrieve",
        "apply",
    },
    "fr": {
        "recherche",
        "liste",
        "lisez",
        "envoyez",
        "supprimez",
        "applique",
        "appliquez",
        "créez",
        "utilisez",
    },
    "es": {
        "busca",
        "enumera",
        "enumere",
        "lee",
        "envia",
        "envía",
        "elimina",
        "aplica",
        "llama",
        "usa",
        "crea",
    },
}


def _subjects(verb: Any) -> list[Any]:
    return [t for t in verb.children if t.dep_.startswith(("nsubj", "csubj"))]


def _actor(verb: Any, lang: str):
    subjects = _subjects(verb)
    inherited = False
    if not subjects and verb.dep_.split(":")[0] in {"conj", "xcomp", "advcl"}:
        head = verb.head
        if head is not verb:
            subjects = _subjects(head)
            inherited = bool(subjects)
    tokens = {str(x.text).lower() for x in subjects} | {
        str(x.lemma_).lower() for x in subjects
    }
    reasons = ("inherited_subject_unverified",) if inherited else ()
    if tokens & _AGENT:
        return (Party.AGENT, Mood.MODAL_ADDRESSED, subjects[0], reasons)
    if tokens & _TOOL:
        return (Party.TOOL, Mood.DECLARATIVE, subjects[0], reasons)
    if tokens & _USER:
        return (Party.USER, Mood.DECLARATIVE, subjects[0], reasons)
    if subjects:
        return (
            Party.UNKNOWN,
            Mood.DECLARATIVE,
            subjects[0],
            reasons + ("actor_unresolved",),
        )
    imperative = "Imp" in verb.morph.get("Mood")
    if (
        not imperative
        and lang == "en"
        and (verb.tag_ == "VB")
        and (verb.dep_ in {"ROOT", "conj"})
        and (verb.pos_ == "VERB")
    ):
        imperative = True
    if imperative:
        return (Party.AGENT, Mood.IMPERATIVE, None, ("implicit_addressee_unverified",))
    if verb.dep_ in {"ROOT", "conj"} and (not subjects):
        return (Party.UNKNOWN, Mood.FRAGMENT, None, ("elliptical_tool_or_agent_claim",))
    return (Party.UNKNOWN, Mood.FRAGMENT, None, ("actor_unresolved",))


def _action(token: Any) -> str | None:
    lemma = str(token.lemma_).casefold()
    word = str(token.text).casefold()
    for name, terms in _ACTION_LEMMAS.items():
        if lemma in terms or word in terms:
            return name
    for name, patterns in _ACTION_PATTERNS.items():
        if name not in _ACTION_LEMMAS:
            continue
        if any(
            (
                re.fullmatch(pat, word, re.I) or re.fullmatch(pat, lemma, re.I)
                for pat in patterns
            )
        ):
            return name
    return None


def _resource(text: str) -> str | None:
    for name, patterns in _RESOURCE_PATTERNS.items():
        if any((re.search(pat, text, re.I) for pat in patterns)):
            return name
    return None


def _sent_verbs(sent: Any, lang: str = "en") -> list[Any]:
    predicates = []
    allowed = {"ROOT", "conj", "xcomp", "ccomp", "pcomp", "advcl", "acl", "relcl"}
    for t in sent:
        dep = t.dep_.split(":")[0]
        if t.pos_ == "VERB" and dep in allowed or (t.pos_ == "AUX" and dep == "ROOT"):
            predicates.append(t)
    root = sent.root
    if not predicates and root.pos_ in {"NOUN", "PROPN", "ADJ"}:
        first = next(iter(sent), root)
        if root is first and root.text.casefold() in _ROOT_FALLBACKS.get(lang, set()):
            predicates.append(root)
    return predicates


def _negation(verb: Any):
    relatives = [verb, *list(verb.children)]
    for t in list(verb.children):
        if t.pos_ == "AUX":
            relatives.extend(list(t.children))
    neg = [
        t
        for t in relatives
        if t is not verb
        and t.lower_ in _NEG
        and (t.dep_.split(":")[0] in {"neg", "advmod", "mark"})
    ]
    return neg[0] if neg else None


def _condition_scope(path: str, raw: str, sent: Any, verb: Any):
    candidates = [
        t
        for t in sent
        if t.lower_ in _COND
        and t.dep_.split(":")[0] in {"mark", "case", "advmod", "prep", "fixed"}
    ]
    if not candidates:
        return (None, None, None)
    cue = candidates[0]
    if cue.dep_.split(":")[0] in {"mark", "case"} and cue.head is not verb:
        group = [*cue.head.subtree]
    else:
        group = [*cue.subtree]
    group = [t for t in group if sent.start_char <= t.idx < sent.end_char]
    if not group:
        group = [cue]
    left = min(cue.idx, *(t.idx for t in group))
    right = max(cue.idx + len(cue.text), *(t.idx + len(t.text) for t in group))
    kind = (
        "TEMPORAL"
        if cue.lower_
        in {
            "before",
            "after",
            "when",
            "avant",
            "après",
            "lorsque",
            "quand",
            "antes",
            "después",
            "cuando",
        }
        else "CONDITIONAL"
    )
    return (
        _span(path, raw, cue.idx, cue.idx + len(cue.text)),
        _span(path, raw, left, right),
        kind,
    )


def _argument_nodes(verb: Any):
    acceptable = {"dobj", "obj", "iobj", "obl", "nmod", "prep", "attr", "oprd"}
    for ch in verb.children:
        if ch.dep_.split(":")[0] in acceptable and ch.lower_ not in _COND:
            yield ch


def _build_predicate_clause(
    path: str, raw: str, sent: Any, verb: Any, lang: str, ident: str
) -> Clause:
    span = _span(path, raw, sent.start_char, sent.end_char)
    actor, mood, evidence_token, reasons = _actor(verb, lang)
    reasons = list(reasons)
    if verb.dep_.split(":")[0] in {"advcl", "xcomp", "ccomp", "acl", "relcl"}:
        reasons.append("subordinate_predicate_not_standalone_effect")
    if verb.pos_ != "VERB":
        reasons.append("parser_root_pos_fallback_unverified")
    neg = _negation(verb)
    pred = Predicate(
        str(verb.lemma_).casefold(),
        _span(path, raw, verb.idx, verb.idx + len(verb.text)),
        _action(verb),
        neg is not None,
        _span(path, raw, neg.idx, neg.idx + len(neg.text)) if neg else None,
    )
    cue, condition_scope, condition_relation = _condition_scope(path, raw, sent, verb)
    if cue is not None:
        reasons.append("condition_scope_unverified")
    arguments = []
    for child in _argument_nodes(verb):
        sub = list(child.subtree)
        if not sub:
            continue
        a = min((t.idx for t in sub))
        z = max((t.idx + len(t.text) for t in sub))
        if a <= verb.idx < z:
            reasons.append("argument_overlap_unresolved")
            continue
        sp = _span(path, raw, a, z)
        dep = child.dep_.split(":")[0]
        role = "OBJECT" if dep in {"dobj", "obj", "iobj", "attr", "oprd"} else "OBLIQUE"
        arguments.append(Argument(role, sp, _resource(sp.excerpt)))
    if not arguments and pred.action_class:
        reasons.append("action_object_unresolved")
    quoted = any((ch in span.excerpt for ch in ('"', "“", "”")))
    if quoted:
        reasons.append("quotation_scope_unverified")
    example = bool(_EXAMPLES.search(raw[max(0, span.start - 80) : span.end]))
    frame = Framing.EXAMPLE if example else Framing.QUOTED if quoted else Framing.ACTIVE
    return Clause(
        ident,
        span,
        lang,
        mood,
        actor if actor == Party.AGENT else Party.UNKNOWN,
        actor,
        _span(
            path, raw, evidence_token.idx, evidence_token.idx + len(evidence_token.text)
        )
        if evidence_token
        else None,
        (pred,),
        tuple(arguments),
        cue,
        frame,
        (),
        tuple(dict.fromkeys(reasons)),
        condition_scope,
        condition_relation,
        (Party.TOOL, Party.AGENT)
        if actor == Party.UNKNOWN and "elliptical_tool_or_agent_claim" in reasons
        else (),
    )


def build_clause_ir(
    snapshot: dict,
    *,
    backend: ParserBackend,
    budgets: Budgets | None = None,
    language: str | None = None,
) -> ClauseIR:
    if not isinstance(snapshot, dict):
        raise TypeError("tool metadata must be dict")
    b = budgets or Budgets()
    if any((not isinstance(n, int) or n < 1 for n in asdict(b).values())):
        raise ValueError("invalid budgets")
    if language is not None and language not in {"en", "fr", "es", "other"}:
        raise ValueError("unsupported language")
    fields, omissions, visited = _fields(snapshot, b)
    clauses = []
    for path, raw, retained in fields:
        if len(clauses) >= b.clauses:
            omissions.append({"source_path": path, "reason": "clause_budget"})
            break
        lang = language or detect_language(raw[:retained])
        if lang == "other":
            clauses.append(
                Clause(
                    "c" + str(len(clauses)),
                    _span(path, raw, 0, retained),
                    lang,
                    Mood.UNPARSED,
                    Party.UNKNOWN,
                    Party.UNKNOWN,
                    None,
                    (),
                    (),
                    None,
                    Framing.ACTIVE,
                    (),
                    ("language_unsupported",),
                )
            )
            omissions.append({"source_path": path, "reason": "language_unsupported"})
            continue
        try:
            parsed = backend.parse(raw[:retained], lang)
            sents = list(parsed.sents)
            if not sents and retained:
                raise ValueError("empty_parsed_document")
        except Exception as exc:
            clauses.append(
                Clause(
                    "c" + str(len(clauses)),
                    _span(path, raw, 0, retained),
                    lang,
                    Mood.UNPARSED,
                    Party.UNKNOWN,
                    Party.UNKNOWN,
                    None,
                    (),
                    (),
                    None,
                    Framing.ACTIVE,
                    (),
                    ("parser_failed",),
                )
            )
            omissions.append(
                {
                    "source_path": path,
                    "reason": "parser_failed",
                    "error_type": type(exc).__name__,
                }
            )
            continue
        for sent in sents:
            if len(clauses) >= b.clauses:
                omissions.append({"source_path": path, "reason": "clause_budget"})
                break
            verbs = _sent_verbs(sent, lang)
            if not verbs:
                clauses.append(
                    Clause(
                        "c" + str(len(clauses)),
                        _span(path, raw, sent.start_char, sent.end_char),
                        lang,
                        Mood.UNPARSED,
                        Party.UNKNOWN,
                        Party.UNKNOWN,
                        None,
                        (),
                        (),
                        None,
                        Framing.ACTIVE,
                        (),
                        ("predicate_unparsed",),
                    )
                )
                continue
            from dataclasses import replace

            start = len(clauses)
            ids = ["c" + str(start + i) for i in range(len(verbs))]
            for i, verb in enumerate(verbs):
                if len(clauses) >= b.clauses:
                    omissions.append({"source_path": path, "reason": "clause_budget"})
                    break
                cl = _build_predicate_clause(path, raw, sent, verb, lang, ids[i])
                clauses.append(
                    replace(
                        cl,
                        coordinated_with=tuple(
                            (other for other in ids if other != ids[i])
                        ),
                    )
                )
        if len(clauses) >= b.clauses:
            omissions.append({"source_path": path, "reason": "clause_budget"})
            break
    return ClauseIR(
        REVISION,
        backend.identity(),
        tuple(clauses),
        {
            "fields": len(fields),
            "visited_nodes": visited,
            "clauses": len(clauses),
            "budgets": asdict(b),
            "complete": not omissions,
            "recall_verified": False,
        },
        tuple(omissions),
    )


def agent_claims_for_contract_view(ir: ClauseIR):
    """Shadow-only: exclusions are INTENTIONALLY EMPTY, to avoid altering V0."""
    uncertain = [
        {
            "source_path": c.span.source_path,
            "start": c.span.start,
            "end": c.span.end,
            "excerpt": c.span.excerpt,
            "actor": c.actor.value,
            "reason": "shadow_not_authorized_to_mask",
        }
        for c in ir.clauses
        if c.actor == Party.AGENT
    ]
    return ([], uncertain)


def facts_supplement(ir: ClauseIR) -> dict:
    """Bounded relation hypotheses, never executable or authoritative facts.

    Preserve exact object spans. An unknown resource category remains None;
    a negated predicate cannot enter the positive candidate-relations list.
    """
    positive, negative, unclassified = ([], [], [])
    for c in ir.clauses:
        for pred in c.predicates:
            for arg in c.arguments:
                row = {
                    "action": pred.action_class,
                    "action_lemma": pred.lemma,
                    "resource": arg.resource_class,
                    "resource_text": arg.span.excerpt,
                    "resource_typed": arg.resource_class is not None,
                    "actor": c.actor.value,
                    "negated": pred.negated,
                    "source": asdict(c.span),
                    "predicate_span": asdict(pred.surface),
                    "resource_span": asdict(arg.span),
                    "source_role": "TOOL_DESCRIPTION"
                    if c.span.source_path == "/description"
                    else "NESTED_METADATA_DESCRIPTION",
                    "validated": False,
                    "shadow_only": True,
                }
                if pred.negated:
                    negative.append(row)
                elif pred.action_class is None:
                    unclassified.append(row)
                else:
                    positive.append(row)
    return {
        "shadow_only": True,
        "creates_permissions": False,
        "may_remove_v0_facts": False,
        "candidate_relations": positive,
        "negated_relation_mentions": negative,
        "unclassified_predicate_arguments": unclassified,
    }


def classify_directives(
    ir: ClauseIR,
    *,
    inventory_tool_names: frozenset[str] = frozenset(),
    schema_parameters: frozenset[str] = frozenset(),
):
    out = []
    for c in ir.clauses:
        if (
            c.actor != Party.AGENT
            or c.framing != Framing.ACTIVE
            or c.mood == Mood.UNPARSED
        ):
            continue
        low = c.span.excerpt.lower()
        names = sorted(
            (
                n
                for n in inventory_tool_names
                if re.search(
                    "(?<!\\w)" + re.escape(n) + "(?!\\w)", c.span.excerpt, re.I
                )
            )
        )
        params = sorted(
            (
                n
                for n in schema_parameters
                if re.search(
                    "(?<!\\w)" + re.escape(n) + "(?!\\w)", c.span.excerpt, re.I
                )
            )
        )
        if names and re.search("\\b(call|invoke|appeler|appelez|llama)\\b", low):
            kind = "CROSS_TOOL_CALL"
        elif re.search("\\b(hide|conceal|cacher|ocultar|do not tell)\\b", low):
            kind = "USER_CONCEALMENT"
        elif re.search(
            "\\b(ignore|override|system instructions|priorité|prioridad)\\b", low
        ):
            kind = "PRIORITY_CLAIM"
        elif re.search("\\b(secret|credentials|password|token|contraseña)\\b", low):
            kind = "SENSITIVE_RESOURCE_ACCESS"
        elif params and re.search("\\b(set|pass|use|définir|establece)\\b", low):
            kind = "PARAMETER_PRESCRIPTION"
        elif c.condition:
            kind = "SEQUENCING_PREREQUISITE"
        else:
            kind = "USAGE_GUIDANCE"
        out.append(
            {
                "kind": kind,
                "source_path": c.span.source_path,
                "start": c.span.start,
                "end": c.span.end,
                "excerpt": c.span.excerpt,
                "referenced_tools": names,
                "parameters": params,
                "outside_declared_function": "UNKNOWN",
                "review_decision": None,
                "shadow_only": True,
                "claim_id": c.id,
            }
        )
    return tuple(out)


def to_comparison_records(ir: ClauseIR):
    return [
        {
            "id": c.id,
            "source_path": c.span.source_path,
            "start": c.span.start,
            "end": c.span.end,
            "excerpt": c.span.excerpt,
            "actor": c.actor.value,
            "addressee": c.addressee.value,
            "actor_alternatives": [a.value for a in c.actor_alternatives],
            "actions": [p.action_class for p in c.predicates],
            "resources": [a.resource_class for a in c.arguments],
            "negated": [p.negated for p in c.predicates],
            "condition_present": c.condition is not None,
            "condition_scope": asdict(c.condition_scope) if c.condition_scope else None,
            "condition_relation": c.condition_relation,
            "framing": c.framing.value,
            "unresolved": list(c.unresolved),
        }
        for c in ir.clauses
    ]


def v0_to_comparison_records(snapshot: dict):
    rows = extract_propositions(snapshot)
    return [
        {
            "id": p["id"],
            "source_path": p["source_path"],
            "start": p["start"],
            "end": p["end"],
            "excerpt": p["excerpt"],
            "actor": p["actor"],
            "addressee": p["addressee"],
            "actions": [p["action"]],
            "resources": [p["object"]],
            "negated": [p["polarity"] == "NEGATIVE"],
            "condition_present": p["condition"] is not None,
            "framing": "QUOTED" if p["quotation"] else "ACTIVE",
            "unresolved": list(p["uncertainty"]),
        }
        for p in rows["propositions"]
    ]
