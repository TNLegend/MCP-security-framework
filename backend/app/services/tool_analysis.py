from __future__ import annotations

import base64
from dataclasses import dataclass, replace
from datetime import datetime
from hashlib import sha256
import math
from pathlib import Path
import re
from typing import Any, Protocol

from common.canonical_json import canonical_json_bytes
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.runtime_paths import MODEL_CACHE_DIR, configure_runtime_environment
from app.models.audit_event import AuditEvent
from app.models.mcp_tool import MCPTool
from app.models.tool_analysis import (
    ToolAnalysis,
    ToolAnalysisFinding,
    ToolApprovedBaseline,
    ToolHumanReview,
    ToolObservedVersion,
    ToolProtocolObservation,
)
from app.services.tool_semantic_facts import (
    ToolSemanticFacts,
    extract_tool_semantic_facts,
    iter_schema_fields,
    strip_documentation_examples,
)
from proxy.protocol_profiles import LEGACY_PROFILE_ID, ProtocolProfileError, ProtocolProfileRegistry
from proxy.security_packs import SecurityPackRegistry


ANALYZER_REVISION = "tool-description-analyzer-v7"
SEMANTIC_MODEL_NAME = "MoritzLaurer/multilingual-MiniLMv2-L6-mnli-xnli"
EMBEDDING_MODEL_NAME = "intfloat/multilingual-e5-small"
SEMANTIC_MODEL_VERSION = "local-cache"
EMBEDDING_MODEL_VERSION = "local-cache"
SEMANTIC_REVIEW_THRESHOLD = 0.74
MIN_REVIEW_JUSTIFICATION_LENGTH = 8
INVALID_ANALYSIS_CONTEXT_PREFIX = "invalid:"

FINDING_DECISION_BLOCK = "block"
FINDING_DECISION_REVIEW = "review"
FINDING_DECISION_INFO = "info"

STATUS_PENDING_ANALYSIS = "PENDING_ANALYSIS"
STATUS_QUARANTINED = "QUARANTINED"
STATUS_REVIEW_REQUIRED = "REVIEW_REQUIRED"
STATUS_APPROVED = "APPROVED"
STATUS_ADMIN_ALLOWED = "ADMIN_ALLOWED"
STATUS_BLOCKED = "BLOCKED"
STATUS_ANALYSIS_FAILED = "ANALYSIS_FAILED"
STATUS_STALE = "STALE"
APPROVAL_SOURCE_FRAMEWORK = "FRAMEWORK"
APPROVAL_SOURCE_ADMIN = "ADMIN"

DRIFT_NONE = "NONE"
DRIFT_BENIGN = "BENIGN"
DRIFT_LOW = "LOW"
DRIFT_MEDIUM = "MEDIUM"
DRIFT_HIGH = "HIGH"
DRIFT_CRITICAL = "CRITICAL"

SEMANTIC_CATEGORIES = [
    "normal_tool_description",
    "prompt_injection",
    "security_bypass",
    "secret_collection",
    "data_exfiltration",
    "hidden_additional_action",
    "command_execution",
    "unauthorized_data_access",
    "user_deception",
    "privilege_escalation",
    "cross_tenant_access",
    "unexpected_destructive_operation",
    "public_sharing",
    "bulk_messaging",
    "server_side_request_forgery",
    "shell_injection",
    "unauthorized_financial_transaction",
]

SEMANTIC_CATEGORY_LABELS = {
    "normal_tool_description": "a normal and transparent tool description",
    "prompt_injection": "instructions that override or manipulate platform instructions",
    "security_bypass": "instructions to bypass safeguards, policy, or authorization",
    "secret_collection": "collection of passwords, tokens, credentials, or secrets",
    "data_exfiltration": "sending or uploading data to an external destination",
    "hidden_additional_action": "a concealed additional action beyond the stated purpose",
    "command_execution": "execution of shell commands, scripts, or operating system processes",
    "unauthorized_data_access": "access to data without permission or outside the authorized scope",
    "user_deception": "misleading the user or concealing the tool's real behavior",
    "privilege_escalation": "changing privileges or identity authority beyond the declared purpose",
    "cross_tenant_access": "accessing another tenant, account, project, or organization without authorization",
    "unexpected_destructive_operation": "deleting or irreversibly modifying data beyond the declared purpose",
    "public_sharing": "making private data or resources publicly accessible",
    "bulk_messaging": "sending messages to many recipients or performing unsolicited outreach",
    "server_side_request_forgery": "requesting internal, local, metadata, or restricted network destinations",
    "shell_injection": "allowing untrusted input to alter a command, shell, or executable invocation",
    "unauthorized_financial_transaction": "an unauthorized payment, transfer, purchase, or refund",
}

SEMANTIC_CORROBORATION_PATTERNS = {
    "prompt_injection": (
        r"\b(ignore|override|disregard|forget).{0,50}\b(instructions?|rules?|policy|safeguards?)\b",
        r"\b(system|developer|platform)\s+(prompt|instructions?)\b",
        r"\b(ignore[rz]?|contourne[rz]?|oublie[rz]?).{0,50}\b(instructions?|règles?|politique|sécurité)\b",
        r"\b(prefer|follow).{0,40}\b(tool|embedded).{0,20}\b(directions?|guidance).{0,40}\b(safeguards?|policy|platform)\b",
        r"\b(safeguards?|policy|platform).{0,60}\bprefer.{0,30}\btool\s+(directions?|guidance|instructions?)\b",
    ),
    "security_bypass": (
        r"\b(bypass|disable|evade|circumvent).{0,50}\b(security|policy|authorization|safeguards?|restrictions?)\b",
        r"\b(prefer|follow|obey).{0,50}\b(tool|embedded|provided)\s+instructions?.{0,50}\b(over|instead of)\b.{0,50}\b(platform|security|policy|safeguards?)\b",
    ),
    "secret_collection": (
        r"\b(collect|capture|retrieve|request|extract|steal).{0,50}\b(passwords?|tokens?|credentials?|secrets?|api[_ -]?keys?)\b",
        r"\b(collecte[rz]?|capture[rz]?|récup[ée]re[rz]?|demande[rz]?|extraire|vole[rz]?).{0,50}\b(mots? de passe|jetons?|identifiants?|secrets?|clés? api)\b",
    ),
    "data_exfiltration": (
        r"\b(exfiltrate|upload|transmit|forward|send).{0,60}\b(data|files?|contents?|records?|secrets?)\b",
        r"\b(data|files?|contents?|records?|secrets?).{0,60}\b(external|remote|collector|webhook|upload|transmit|forward|send)\b",
        r"\b(upload|transmit|forward|send).{0,80}\b(to|toward)\s+https?://",
    ),
    "hidden_additional_action": (
        r"\b(secretly|silently|covertly|without (?:telling|notifying)|hidden additional action)\b",
        r"\b(in addition|also).{0,40}\b(delete|execute|upload|send|modify|collect)\b",
    ),
    "command_execution": (
        r"\b(execute|run|launch|invoke).{0,40}\b(commands?|shell|scripts?|process(?:es)?)\b",
        r"\b(shell|command|script)\s+execution\b",
    ),
    "unauthorized_data_access": (
        r"\b(without (?:permission|authorization)|unauthori[sz]ed|outside.{0,20}(?:scope|permissions?))\b",
    ),
    "user_deception": (
        r"\b(deceive|mislead|impersonate|pretend|conceal|hide).{0,50}\b(user|behavior|action|purpose|identity)\b",
    ),
    "privilege_escalation": (
        r"\b(grant|elevate|escalate|assign).{0,50}\b(admin|owner|privilege|role|permission)\b",
        r"\b(accorder|élever|attribuer).{0,50}\b(admin|propriétaire|privilège|rôle|permission)\b",
    ),
    "cross_tenant_access": (
        r"\b(other|another|cross)[ -]?(tenant|account|organization|project)\b",
        r"\b(autre|inter)[ -]?(tenant|compte|organisation|projet)\b",
    ),
    "unexpected_destructive_operation": (
        r"\b(permanently|irreversibly|without confirmation).{0,50}\b(delete|remove|erase|overwrite)\b",
        r"\b(définitivement|irréversiblement|sans confirmation).{0,50}\b(supprimer|effacer|écraser)\b",
    ),
    "public_sharing": (
        r"\b(make|publish|share).{0,40}\b(public|anyone|anonymous)\b",
        r"\b(rendre|publier|partager).{0,40}\b(public|tout le monde|anonyme)\b",
    ),
    "bulk_messaging": (
        r"\b(bulk|mass|all contacts|every recipient|unsolicited)\b",
        r"\b(en masse|tous les contacts|chaque destinataire|non sollicit[ée])\b",
    ),
    "server_side_request_forgery": (
        r"\b(localhost|loopback|link-local|metadata service|169\.254\.169\.254)\b",
    ),
    "shell_injection": (
        r"\b(untrusted|user supplied|arbitrary).{0,40}\b(shell|command|script)\b",
        r"\b(shell|command|script).{0,60}\b(untrusted|user supplied|arbitrary)\b",
        r"\b(non fiable|fourni par l'utilisateur|arbitraire).{0,40}\b(shell|commande|script)\b",
    ),
    "unauthorized_financial_transaction": (
        r"\b(unauthori[sz]ed|without\s+(approval|consent)).{0,60}\b(payment|transfer|purchase|refund)\b",
        r"\b(payment|transfer|purchase|refund).{0,60}\b(without.{0,20}(approval|consent)|unauthori[sz]ed)\b",
        r"\b(paiement|virement|achat|remboursement).{0,60}\b(sans\s+(autorisation|consentement)|non\s+autoris[ée])\b",
    ),
}

CRITICAL_DETERMINISTIC_CODES = {
    "credential_request",
    "environment_secret_access",
    "ignore_security_restrictions",
    "unexpected_process_execution",
    "unexpected_secret_access",
    "unexpected_destructive_operation",
    "suspicious_base64_payload",
}

SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")

SENSITIVE_PARAMETER_NAMES = {
    "command",
    "shell",
    "script",
    "upload_url",
    "callback_url",
    "destination_url",
    "include_env",
    "credentials",
    "token",
    "delete",
    "overwrite",
}

INVISIBLE_RE = re.compile(
    "[\u200b\u200c\u200d\u2060\ufeff\u00ad]",
)
BIDI_RE = re.compile("[\u202a-\u202e\u2066-\u2069]")
HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
BASE64_RE = re.compile(r"\b[A-Za-z0-9+/]{32,}={0,2}\b")


@dataclass(frozen=True)
class AnalysisFinding:
    code: str
    category: str
    source: str
    severity: str
    confidence: int
    evidence: dict[str, Any]
    recommendation: str


@dataclass(frozen=True)
class SemanticResult:
    scores: dict[str, float]
    best_category: str
    confidence: float
    model_name: str
    model_version: str
    flagged: bool


@dataclass(frozen=True)
class DriftResult:
    status: str
    changes: list[dict[str, Any]]
    similarity: float | None


class SemanticModel(Protocol):
    def classify(self, text: str, categories: list[str]) -> SemanticResult:
        ...


class EmbeddingModel(Protocol):
    def similarity(self, previous_text: str, current_text: str) -> float:
        ...


class SemanticModelUnavailable(RuntimeError):
    pass


class LocalZeroShotSemanticModel:
    def __init__(
        self,
        model_name: str = SEMANTIC_MODEL_NAME,
        *,
        cache_dir: Path | None = None,
    ) -> None:
        self.model_name = model_name
        self.cache_dir = cache_dir or MODEL_CACHE_DIR
        self.model_version = SEMANTIC_MODEL_VERSION
        self._classifier = None

    def classify(self, text: str, categories: list[str]) -> SemanticResult:
        classifier = self._load_classifier()
        labels_by_category = {
            category: SEMANTIC_CATEGORY_LABELS.get(category, category.replace("_", " "))
            for category in categories
        }
        categories_by_label = {label: category for category, label in labels_by_category.items()}
        result = classifier(text, list(categories_by_label), multi_label=True)
        labels = result.get("labels", [])
        scores = result.get("scores", [])
        score_map = {
            categories_by_label[str(label)]: float(score)
            for label, score in zip(labels, scores)
            if str(label) in categories_by_label
        }
        for category in categories:
            score_map.setdefault(category, 0.0)
        best_category = max(score_map, key=score_map.get)
        confidence = score_map[best_category]
        return SemanticResult(
            scores=score_map,
            best_category=best_category,
            confidence=confidence,
            model_name=self.model_name,
            model_version=self.model_version,
            flagged=best_category != "normal_tool_description"
            and confidence >= SEMANTIC_REVIEW_THRESHOLD,
        )

    def _load_classifier(self):
        if self._classifier is not None:
            return self._classifier
        configure_runtime_environment()
        model_ref = _local_snapshot_path(self.cache_dir, self.model_name)
        if model_ref is None:
            model_ref = Path(self.model_name)
        try:
            from transformers import pipeline
        except Exception as exc:
            raise SemanticModelUnavailable("semantic_model_dependency_unavailable") from exc
        try:
            self._classifier = pipeline(
                "zero-shot-classification",
                model=str(model_ref),
                tokenizer=str(model_ref),
                cache_dir=str(self.cache_dir),
                local_files_only=True,
            )
            self.model_version = _model_version_from_config(
                getattr(self._classifier, "model", None),
                SEMANTIC_MODEL_VERSION,
            )
        except Exception as exc:
            raise SemanticModelUnavailable("semantic_model_unavailable") from exc
        return self._classifier


class LocalEmbeddingModel:
    def __init__(
        self,
        model_name: str = EMBEDDING_MODEL_NAME,
        *,
        cache_dir: Path | None = None,
    ) -> None:
        self.model_name = model_name
        self.cache_dir = cache_dir or MODEL_CACHE_DIR
        self.model_version = EMBEDDING_MODEL_VERSION
        self._model = None

    def similarity(self, previous_text: str, current_text: str) -> float:
        model = self._load_model()
        embeddings = model.encode(
            [f"query: {previous_text}", f"passage: {current_text}"],
            normalize_embeddings=True,
        )
        return float(sum(a * b for a, b in zip(embeddings[0], embeddings[1])))

    def _load_model(self):
        if self._model is not None:
            return self._model
        configure_runtime_environment()
        model_ref = _local_snapshot_path(self.cache_dir, self.model_name)
        if model_ref is None:
            model_ref = Path(self.model_name)
        try:
            from sentence_transformers import SentenceTransformer
        except Exception as exc:
            raise SemanticModelUnavailable("embedding_model_dependency_unavailable") from exc
        try:
            self._model = SentenceTransformer(
                str(model_ref),
                cache_folder=str(self.cache_dir),
                local_files_only=True,
            )
            self.model_version = _sentence_transformer_version(
                self._model,
                EMBEDDING_MODEL_VERSION,
            )
        except Exception as exc:
            raise SemanticModelUnavailable("embedding_model_unavailable") from exc
        return self._model


class HashingEmbeddingModel:
    """Deterministic local fallback for tests and reports; not used for final decisions."""

    def similarity(self, previous_text: str, current_text: str) -> float:
        left = set(_tokens(previous_text))
        right = set(_tokens(current_text))
        if not left and not right:
            return 1.0
        if not left or not right:
            return 0.0
        return len(left & right) / len(left | right)


def tool_fingerprint_payload(
    *,
    server_ref: str,
    tool_name: str,
    description: str | None,
    input_schema: dict[str, Any] | None,
    output_schema: dict[str, Any] | None,
    annotations: dict[str, Any] | None,
    execution: dict[str, Any] | None = None,
    profile: dict[str, Any] | None = None,
) -> dict[str, Any]:
    # Profile and registry identity are deliberately separate approval artifacts.
    _ = server_ref, profile
    return {
        "tool_name": tool_name,
        "description": normalize_description(description),
        "input_schema": input_schema or {},
        "output_schema": output_schema or {},
        "annotations": annotations or {},
        "execution": execution or {},
    }


def compute_tool_fingerprint(payload: dict[str, Any]) -> str:
    return sha256(canonical_json_bytes(payload)).hexdigest()


def analysis_context_payload(profile_snapshot: dict[str, Any] | None) -> dict[str, Any]:
    if profile_snapshot is None:
        return {"schema_version": 0, "profile": None}

    contract_hash = profile_snapshot.get("contract_hash")
    if isinstance(contract_hash, str) and SHA256_HEX_RE.fullmatch(contract_hash):
        return {
            "schema_version": 2,
            "contract_hash": contract_hash,
        }
    return {
        "schema_version": 2,
        "invalid_context": "missing_or_invalid_contract_hash",
    }


def compute_analysis_context_hash(profile_snapshot: dict[str, Any] | None) -> str:
    payload = analysis_context_payload(profile_snapshot)
    digest = sha256(canonical_json_bytes(payload)).hexdigest()
    if payload.get("invalid_context"):
        return f"{INVALID_ANALYSIS_CONTEXT_PREFIX}{digest[:56]}"
    return digest


def reusable_analysis_context_hash(value: str | None) -> bool:
    return isinstance(value, str) and SHA256_HEX_RE.fullmatch(value) is not None


def analyze_tool_version(
    *,
    tool_snapshot: dict[str, Any],
    profile_snapshot: dict[str, Any] | None,
    baseline_snapshot: dict[str, Any] | None = None,
    semantic_model: SemanticModel | None = None,
    embedding_model: EmbeddingModel | None = None,
) -> dict[str, Any]:
    semantic_facts = extract_tool_semantic_facts(tool_snapshot)
    findings = deterministic_findings(
        tool_snapshot,
        profile_snapshot,
        semantic_facts=semantic_facts,
    )
    active_embedding_model = embedding_model or LocalEmbeddingModel()
    consistency = consistency_result(
        tool_snapshot,
        profile_snapshot,
        semantic_facts=semantic_facts,
    )
    drift = drift_result(
        baseline_snapshot,
        tool_snapshot,
        active_embedding_model,
    )
    findings.extend(consistency["findings"])
    findings.extend(_drift_findings(drift))
    findings = _deduplicate_findings(findings)

    deterministic_blocking = any(
        _finding_decision(finding) == FINDING_DECISION_BLOCK
        for finding in findings
    )
    deterministic_review = any(
        _finding_decision(finding) == FINDING_DECISION_REVIEW
        for finding in findings
    )
    deterministic_critical = deterministic_blocking
    categories = _semantic_categories(profile_snapshot)
    if deterministic_blocking:
        model_semantic_result = SemanticResult(
            scores={category: 0.0 for category in categories},
            best_category="not_run_deterministic",
            confidence=0.0,
            model_name="not_run_deterministic",
            model_version=ANALYZER_REVISION,
            flagged=False,
        )
        semantic_result = model_semantic_result
    else:
        active_semantic_model = semantic_model or LocalZeroShotSemanticModel()
        semantic_text = _semantic_text(tool_snapshot)
        model_semantic_result = active_semantic_model.classify(semantic_text, categories)
        semantic_result = _corroborate_semantic_result(
            model_semantic_result,
            semantic_text,
            semantic_facts,
        )
    unresolved_unknown_reasons = _unresolved_semantic_unknown_reasons(
        semantic_facts.unknown_reasons,
        profile_snapshot,
    )
    risk_score = _risk_score(findings, semantic_result, drift)
    risk_level = _risk_level(risk_score)
    if deterministic_blocking:
        status = STATUS_BLOCKED
        review_status = STATUS_BLOCKED
    elif semantic_result.flagged or deterministic_review:
        status = STATUS_REVIEW_REQUIRED
        review_status = STATUS_REVIEW_REQUIRED
    elif profile_snapshot is None or unresolved_unknown_reasons:
        status = STATUS_QUARANTINED
        review_status = STATUS_REVIEW_REQUIRED
    else:
        status = STATUS_APPROVED
        review_status = STATUS_APPROVED

    model_risk_scores = {
        category: score
        for category, score in model_semantic_result.scores.items()
        if category != "normal_tool_description"
    }
    highest_model_risk = max(model_risk_scores.values(), default=0.0)
    semantic_abstained = (
        not semantic_result.flagged
        and (
            bool(unresolved_unknown_reasons)
            or highest_model_risk >= SEMANTIC_REVIEW_THRESHOLD
        )
    )

    return {
        "analysis_status": status,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "semantic_flagged": semantic_result.flagged,
        "deterministic_critical_finding": deterministic_critical,
        "consistency_status": consistency["status"],
        "drift_status": drift.status,
        "review_status": review_status,
        "semantic_scores": {
            "scores": semantic_result.scores,
            "best_category": semantic_result.best_category,
            "confidence": semantic_result.confidence,
            "threshold": SEMANTIC_REVIEW_THRESHOLD,
            "model_best_category": model_semantic_result.best_category,
            "model_flagged": highest_model_risk >= SEMANTIC_REVIEW_THRESHOLD,
            "corroborated": semantic_result.flagged,
            "flagged": semantic_result.flagged,
            "abstained": semantic_abstained,
            "facts": semantic_facts.to_dict(),
            "unresolved_unknown_reasons": list(unresolved_unknown_reasons),
        },
        "consistency_result": consistency,
        "drift_result": {
            "status": drift.status,
            "changes": drift.changes,
            "similarity": drift.similarity,
        },
        "model_versions": {
            "semantic": {
                "name": semantic_result.model_name,
                "version": semantic_result.model_version,
            },
            "embedding": {
                "name": getattr(active_embedding_model, "model_name", EMBEDDING_MODEL_NAME),
                "version": getattr(
                    active_embedding_model,
                    "model_version",
                    EMBEDDING_MODEL_VERSION,
                ),
            },
        },
        "findings": findings,
    }


def deterministic_findings(
    tool_snapshot: dict[str, Any],
    profile_snapshot: dict[str, Any] | None,
    *,
    semantic_facts: ToolSemanticFacts | None = None,
) -> list[AnalysisFinding]:
    findings: list[AnalysisFinding] = []
    facts = semantic_facts or extract_tool_semantic_facts(tool_snapshot)
    profile_capabilities = capabilities_from_profile(profile_snapshot or {})
    text_sources = {
        "description": tool_snapshot.get("description") or "",
        "annotation": _annotation_text(tool_snapshot.get("annotations") or {}),
        "execution": _annotation_text(tool_snapshot.get("execution") or {}),
    }
    for source, text in text_sources.items():
        findings.extend(_text_findings(source, text))

    schema = tool_snapshot.get("input_schema") or {}
    output_schema = tool_snapshot.get("output_schema") or {}
    findings.extend(
        _schema_findings(
            schema,
            "input_schema",
            profile_capabilities,
            facts,
        )
    )
    findings.extend(
        _schema_findings(
            output_schema,
            "output_schema",
            profile_capabilities,
            facts,
        )
    )
    findings.extend(_contextual_security_review_findings(tool_snapshot, facts))

    return _deduplicate_findings(findings)


def _contextual_security_review_findings(
    tool_snapshot: dict[str, Any],
    facts: ToolSemanticFacts,
) -> list[AnalysisFinding]:
    """Review explicit high-risk behavior even when the semantic model under-scores it.

    These checks are intentionally vendor-agnostic and require two independent signals:
    explicit abuse language in the operational semantic text plus corroborating structured
    facts extracted from the tool metadata/schema. They never BLOCK by themselves.
    """
    text = _semantic_text(tool_snapshot)
    checks = {
        "cross_tenant_access": (
            "contextual_cross_tenant_access",
            "Cross-tenant or cross-account access is explicitly described.",
            "Confirm tenant/account boundaries and require an explicit authorized scope.",
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
    findings: list[AnalysisFinding] = []
    for category, (code, evidence, recommendation) in checks.items():
        patterns = SEMANTIC_CORROBORATION_PATTERNS.get(category, ())
        if not any(re.search(pattern, text, re.IGNORECASE) for pattern in patterns):
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
    return findings


def consistency_result(
    tool_snapshot: dict[str, Any],
    profile_snapshot: dict[str, Any] | None,
    *,
    semantic_facts: ToolSemanticFacts | None = None,
) -> dict[str, Any]:
    facts = semantic_facts or extract_tool_semantic_facts(tool_snapshot)
    description_caps = capabilities_from_text(tool_snapshot.get("description") or "")
    schema_caps = capabilities_from_schema(tool_snapshot.get("input_schema") or {})
    annotation_caps = capabilities_from_text(_annotation_text(tool_snapshot.get("annotations") or {}))
    execution_caps = capabilities_from_execution(tool_snapshot.get("execution") or {})
    profile_caps = capabilities_from_profile(profile_snapshot or {})
    findings: list[AnalysisFinding] = []

    if profile_snapshot is None:
        return {
            "status": "unconfigured",
            "description_capabilities": sorted(description_caps),
            "schema_capabilities": sorted(schema_caps),
            "annotation_capabilities": sorted(annotation_caps),
            "execution_capabilities": sorted(execution_caps),
            "profile_capabilities": [],
            "semantic_facts": facts.to_dict(),
            "findings": findings,
        }

    technical_caps = schema_caps | annotation_caps | execution_caps
    extra_schema_caps = {
        capability
        for capability in technical_caps
        if not _capability_covered_by_contract(capability, profile_caps)
    }
    extra_description_caps = set()
    if _description_capability_inference_reliable(facts):
        extra_description_caps = {
            capability
            for capability in description_caps
            if not _capability_covered_by_contract(capability, profile_caps)
        }

    if extra_schema_caps:
        for capability in sorted(extra_schema_caps):
            code = _capability_mismatch_code({capability})
            findings.append(
                _finding(
                    code,
                    "consistency",
                    "schema",
                    "critical" if code in CRITICAL_DETERMINISTIC_CODES else "high",
                    88,
                    f"schema capability exceeds profile: {capability}",
                    "Narrow the schema or update the official Tool Security Profile.",
                    decision=FINDING_DECISION_BLOCK,
                )
            )
    if extra_description_caps:
        for capability in sorted(extra_description_caps):
            findings.append(
                _finding(
                    _capability_mismatch_code({capability}),
                    "consistency",
                    "description",
                    "medium",
                    78,
                    f"description capability exceeds profile: {capability}",
                    "Review whether the profile authorizes the described behavior.",
                    decision=FINDING_DECISION_REVIEW,
                )
            )
    status = "consistent" if not findings else "mismatch"
    return {
        "status": status,
        "description_capabilities": sorted(description_caps),
        "schema_capabilities": sorted(schema_caps),
        "annotation_capabilities": sorted(annotation_caps),
        "execution_capabilities": sorted(execution_caps),
        "profile_capabilities": sorted(profile_caps),
        "semantic_facts": facts.to_dict(),
        "findings": findings,
    }


def _capability_covered_by_contract(
    observed: str,
    declared: set[str],
) -> bool:
    if observed in declared:
        return True
    aliases = {
        "secret.access": {"secret.read"},
        "secret.read": {"secret.access"},
        "database.select": {"database.read"},
        "database.read": {"database.select"},
        "database.modify": {"database.write"},
        "database.write": {"database.modify"},
        "network.send": {"message.send"},
        "message.send": {"network.send"},
    }
    if declared.intersection(aliases.get(observed, set())):
        return True
    if observed == "filesystem.delete":
        return any(capability.endswith(".delete") for capability in declared)
    return False


def _description_capability_inference_reliable(
    facts: ToolSemanticFacts,
) -> bool:
    resources = facts.values("resources", sources={"description"})
    actions = facts.values("actions", sources={"description"})
    return bool(actions) and len(resources) == 1 and len(actions) <= 2


def drift_result(
    baseline_snapshot: dict[str, Any] | None,
    current_snapshot: dict[str, Any],
    embedding_model: EmbeddingModel,
) -> DriftResult:
    if baseline_snapshot is None:
        return DriftResult(status=DRIFT_NONE, changes=[], similarity=None)

    unchanged_security_definition = all(
        (baseline_snapshot.get(field) or default) == (current_snapshot.get(field) or default)
        for field, default in (
            ("name", ""),
            ("description", ""),
            ("input_schema", {}),
            ("output_schema", {}),
            ("annotations", {}),
            ("execution", {}),
        )
    )
    if unchanged_security_definition:
        return DriftResult(status=DRIFT_NONE, changes=[], similarity=1.0)

    changes: list[dict[str, Any]] = []
    previous_schema = baseline_snapshot.get("input_schema") or {}
    current_schema = current_snapshot.get("input_schema") or {}
    changes.extend(_schema_diff(previous_schema, current_schema))

    if (baseline_snapshot.get("annotations") or {}) != (current_snapshot.get("annotations") or {}):
        changes.append({"type": "annotations_modified", "severity": "medium"})

    previous_caps = capabilities_from_schema(previous_schema)
    current_caps = capabilities_from_schema(current_schema)
    added_caps = sorted(current_caps - previous_caps)
    for capability in added_caps:
        severity = "critical" if capability in {"process.execute", "secret.access", "filesystem.delete"} else "high"
        changes.append(
            {
                "type": "capability_added",
                "capability": capability,
                "severity": severity,
            }
        )

    similarity = embedding_model.similarity(
        baseline_snapshot.get("description") or "",
        current_snapshot.get("description") or "",
    )
    if similarity < 0.72:
        changes.append({"type": "semantic_description_shift", "severity": "medium"})

    status = _drift_status(changes, similarity)
    return DriftResult(status=status, changes=changes, similarity=similarity)


class ToolAnalysisService:
    def __init__(
        self,
        *,
        semantic_model: SemanticModel | None = None,
        embedding_model: EmbeddingModel | None = None,
    ) -> None:
        self.semantic_model = semantic_model or LocalZeroShotSemanticModel()
        self.embedding_model = embedding_model or LocalEmbeddingModel()

    def observe_and_analyze(
        self,
        *,
        db: Session,
        tool: MCPTool,
        server_ref: str,
        profile_snapshot: dict[str, Any] | None,
        upstream_protocol_profile_id: str = LEGACY_PROFILE_ID,
    ) -> ToolAnalysis:
        now = datetime.utcnow()
        snapshot = tool_snapshot_from_model(tool)
        fingerprint_payload = tool_fingerprint_payload(
            server_ref=server_ref,
            tool_name=tool.name,
            description=tool.description,
            input_schema=tool.input_schema,
            output_schema=tool.output_schema,
            annotations=tool.annotations,
            execution=tool.execution,
            profile=profile_snapshot,
        )
        fingerprint = compute_tool_fingerprint(fingerprint_payload)
        analysis_context_hash = compute_analysis_context_hash(profile_snapshot)
        baseline = baseline_for_tool(db, tool.id)
        approved_match = (
            baseline is not None
            and baseline.fingerprint == fingerprint
            and reusable_analysis_context_hash(baseline.analysis_context_hash)
            and baseline.analysis_context_hash == analysis_context_hash
            and baseline.analyzer_revision == ANALYZER_REVISION
            and approved_protocol_observation_exists(
                db,
                tool_id=tool.id,
                upstream_protocol_profile_id=upstream_protocol_profile_id,
                fingerprint=fingerprint,
            )
        )

        version = db.scalar(
            select(ToolObservedVersion).where(
                ToolObservedVersion.tool_id == tool.id,
                ToolObservedVersion.fingerprint == fingerprint,
            )
        )
        if version is None:
            version = ToolObservedVersion(
                tool_id=tool.id,
                server_ref=server_ref,
                tool_name=tool.name,
                fingerprint=fingerprint,
                status="new" if baseline is None else "changed",
                snapshot=snapshot,
                profile_snapshot=profile_snapshot,
                profile_revision=(profile_snapshot or {}).get("revision", "unknown"),
                first_seen_at=now,
                last_seen_at=now,
            )
            db.add(version)
            db.flush()
        else:
            version.status = "identical"
            version.last_seen_at = now

        tool.current_fingerprint = fingerprint
        tool.approved_fingerprint = baseline.fingerprint if baseline else None
        tool.approved_fingerprint_match = approved_match
        approved_status = _approval_status_for_baseline(baseline) if baseline else None
        tool.analysis_status = approved_status if approved_match else STATUS_QUARANTINED
        tool.review_status = approved_status if approved_match else STATUS_REVIEW_REQUIRED
        tool.status = approved_status if approved_match else STATUS_QUARANTINED
        tool.last_analyzed_at = now

        if approved_match:
            analysis = self._record_approved_observation(
                db,
                tool,
                version,
                baseline,
                analysis_context_hash,
                now,
            )
            self._record_protocol_observation(
                db,
                tool=tool,
                server_ref=server_ref,
                upstream_protocol_profile_id=upstream_protocol_profile_id,
                canonical_tool_definition=fingerprint_payload,
                fingerprint=fingerprint,
                analysis=analysis,
                now=now,
            )
            return analysis

        reusable_analysis = None
        if baseline is None:
            reusable_analysis = db.scalar(
                select(ToolAnalysis)
                .where(
                    ToolAnalysis.version_id == version.id,
                    ToolAnalysis.analysis_context_hash == analysis_context_hash,
                    ToolAnalysis.analyzer_revision == ANALYZER_REVISION,
                    ToolAnalysis.analysis_status != STATUS_ANALYSIS_FAILED,
                )
                .order_by(ToolAnalysis.id.desc())
            )
        if reusable_analysis is not None:
            apply_analysis_to_tool(
                tool,
                reusable_analysis,
                baseline,
                protocol_approved_match=approved_protocol_observation_exists(
                    db,
                    tool_id=tool.id,
                    upstream_protocol_profile_id=upstream_protocol_profile_id,
                    fingerprint=fingerprint,
                ),
            )
            self._record_protocol_observation(
                db,
                tool=tool,
                server_ref=server_ref,
                upstream_protocol_profile_id=upstream_protocol_profile_id,
                canonical_tool_definition=fingerprint_payload,
                fingerprint=fingerprint,
                analysis=reusable_analysis,
                now=now,
            )
            return reusable_analysis

        baseline_snapshot = None
        if baseline is not None:
            baseline_version = db.get(ToolObservedVersion, baseline.version_id)
            baseline_snapshot = baseline_version.snapshot if baseline_version else None

        try:
            result = analyze_tool_version(
                tool_snapshot=snapshot,
                profile_snapshot=profile_snapshot,
                baseline_snapshot=baseline_snapshot,
                semantic_model=self.semantic_model,
                embedding_model=self.embedding_model,
            )
        except Exception as exc:
            result = {
                "analysis_status": STATUS_ANALYSIS_FAILED,
                "risk_score": 100,
                "risk_level": "critical",
                "semantic_flagged": False,
                "deterministic_critical_finding": False,
                "consistency_status": "unknown",
                "drift_status": DRIFT_NONE,
                "review_status": STATUS_ANALYSIS_FAILED,
                "semantic_scores": None,
                "consistency_result": None,
                "drift_result": {"status": DRIFT_NONE, "changes": [], "similarity": None},
                "model_versions": {
                    "semantic": {"name": SEMANTIC_MODEL_NAME, "version": "unavailable"},
                    "embedding": {"name": EMBEDDING_MODEL_NAME, "version": "unavailable"},
                },
                "findings": [
                    _finding(
                        "analysis_failed",
                        "analyzer",
                        "description",
                        "critical",
                        100,
                        str(exc.__class__.__name__),
                        "Keep the tool blocked until analysis succeeds.",
                    )
                ],
            }

        if profile_snapshot is None and result["analysis_status"] == STATUS_APPROVED:
            result["analysis_status"] = STATUS_QUARANTINED
            result["review_status"] = STATUS_REVIEW_REQUIRED

        analysis = ToolAnalysis(
            tool_id=tool.id,
            version_id=version.id,
            fingerprint=fingerprint,
            analysis_context_hash=analysis_context_hash,
            analysis_status=result["analysis_status"],
            risk_score=result["risk_score"],
            risk_level=result["risk_level"],
            semantic_flagged=str(bool(result["semantic_flagged"])).lower(),
            deterministic_critical_finding=str(
                bool(result["deterministic_critical_finding"])
            ).lower(),
            consistency_status=result["consistency_status"],
            drift_status=result["drift_status"],
            review_status=result["review_status"],
            semantic_scores=result["semantic_scores"],
            consistency_result=_json_safe(result["consistency_result"]),
            drift_result=result["drift_result"],
            model_versions=result["model_versions"],
            analyzer_revision=ANALYZER_REVISION,
            created_at=now,
            completed_at=now,
        )
        db.add(analysis)
        db.flush()

        for finding in result["findings"]:
            db.add(
                ToolAnalysisFinding(
                    analysis_id=analysis.id,
                    code=finding.code,
                    category=finding.category,
                    source=finding.source,
                    severity=finding.severity,
                    confidence=finding.confidence,
                    evidence=finding.evidence,
                    recommendation=finding.recommendation,
                )
            )

        if result["analysis_status"] == STATUS_APPROVED:
            baseline = _upsert_framework_baseline(
                db=db,
                tool_id=tool.id,
                version=version,
                analysis=analysis,
            )

        apply_analysis_to_tool(
            tool,
            analysis,
            baseline,
            protocol_approved_match=(
                result["analysis_status"] == STATUS_APPROVED
                or approved_protocol_observation_exists(
                    db,
                    tool_id=tool.id,
                    upstream_protocol_profile_id=upstream_protocol_profile_id,
                    fingerprint=fingerprint,
                )
            ),
        )
        self._record_protocol_observation(
            db,
            tool=tool,
            server_ref=server_ref,
            upstream_protocol_profile_id=upstream_protocol_profile_id,
            canonical_tool_definition=fingerprint_payload,
            fingerprint=fingerprint,
            analysis=analysis,
            now=now,
        )
        return analysis

    def _record_protocol_observation(
        self,
        db: Session,
        *,
        tool: MCPTool,
        server_ref: str,
        upstream_protocol_profile_id: str,
        canonical_tool_definition: dict[str, Any],
        fingerprint: str,
        analysis: ToolAnalysis,
        now: datetime,
    ) -> ToolProtocolObservation:
        try:
            protocol_profile = ProtocolProfileRegistry().get(upstream_protocol_profile_id)
        except ProtocolProfileError as exc:
            raise ValueError("unsupported_mcp_protocol_profile") from exc
        observation = db.scalar(
            select(ToolProtocolObservation).where(
                ToolProtocolObservation.tool_id == tool.id,
                ToolProtocolObservation.upstream_protocol_profile_id
                == upstream_protocol_profile_id,
                ToolProtocolObservation.tool_fingerprint == fingerprint,
            )
        )
        if observation is None:
            observation = ToolProtocolObservation(
                tool_id=tool.id,
                server_ref=server_ref,
                upstream_protocol_profile_id=upstream_protocol_profile_id,
                protocol_era=protocol_profile.protocol_era.value,
                protocol_version=protocol_profile.protocol_version,
                transport_kind=protocol_profile.transport_kind.value,
                tool_name=tool.name,
                canonical_tool_definition=canonical_tool_definition,
                tool_fingerprint=fingerprint,
                analysis_state=analysis.analysis_status,
                analysis_id=analysis.id,
                observed_at=now,
                last_seen_at=now,
            )
            db.add(observation)
        else:
            observation.protocol_era = protocol_profile.protocol_era.value
            observation.protocol_version = protocol_profile.protocol_version
            observation.transport_kind = protocol_profile.transport_kind.value
            observation.analysis_state = analysis.analysis_status
            observation.analysis_id = analysis.id
            observation.last_seen_at = now
        db.flush()
        return observation

    def _record_approved_observation(
        self,
        db: Session,
        tool: MCPTool,
        version: ToolObservedVersion,
        baseline: ToolApprovedBaseline,
        analysis_context_hash: str,
        now: datetime,
    ) -> ToolAnalysis:
        source_analysis = db.get(ToolAnalysis, baseline.analysis_id)
        if source_analysis is None or source_analysis.completed_at is None:
            raise ValueError("approved_baseline_evidence_missing")

        analysis = ToolAnalysis(
            tool_id=tool.id,
            version_id=version.id,
            fingerprint=version.fingerprint,
            analysis_context_hash=analysis_context_hash,
            analysis_status=_approval_status_for_baseline(baseline),
            risk_score=source_analysis.risk_score,
            risk_level=source_analysis.risk_level,
            semantic_flagged=source_analysis.semantic_flagged,
            deterministic_critical_finding=source_analysis.deterministic_critical_finding,
            consistency_status=source_analysis.consistency_status,
            drift_status=source_analysis.drift_status,
            review_status=_approval_status_for_baseline(baseline),
            semantic_scores=source_analysis.semantic_scores,
            consistency_result=source_analysis.consistency_result,
            drift_result=source_analysis.drift_result,
            model_versions=source_analysis.model_versions,
            analyzer_revision=baseline.analyzer_revision,
            created_at=now,
            completed_at=now,
        )
        db.add(analysis)
        db.flush()
        apply_analysis_to_tool(tool, analysis, baseline, protocol_approved_match=True)
        return analysis


class ToolReviewService:
    def approve(
        self,
        *,
        db: Session,
        tool_id: int,
        fingerprint: str,
        reviewer: str,
        justification: str,
    ) -> ToolApprovedBaseline:
        analysis = latest_analysis_for_tool(db, tool_id)
        if analysis is None or analysis.fingerprint != fingerprint:
            raise ValueError("fingerprint does not match the latest analysis.")
        _validate_review(reviewer, justification)
        version = db.get(ToolObservedVersion, analysis.version_id)
        if version is None:
            raise ValueError("observed version is missing.")
        _validate_approvable_analysis(db, tool_id, fingerprint, analysis, version)
        baseline = baseline_for_tool(db, tool_id)
        if baseline is None:
            baseline = ToolApprovedBaseline(
                tool_id=tool_id,
                version_id=version.id,
                analysis_id=analysis.id,
                fingerprint=fingerprint,
                analysis_context_hash=analysis.analysis_context_hash,
                approval_source=APPROVAL_SOURCE_ADMIN,
                reviewer=reviewer,
                justification=justification,
                analyzer_revision=analysis.analyzer_revision,
                model_versions=analysis.model_versions,
            )
            db.add(baseline)
        else:
            baseline.version_id = version.id
            baseline.analysis_id = analysis.id
            baseline.fingerprint = fingerprint
            baseline.analysis_context_hash = analysis.analysis_context_hash
            baseline.approval_source = APPROVAL_SOURCE_ADMIN
            baseline.reviewer = reviewer
            baseline.justification = justification
            baseline.analyzer_revision = analysis.analyzer_revision
            baseline.model_versions = analysis.model_versions
            baseline.approved_at = datetime.utcnow()
        analysis.analysis_status = STATUS_ADMIN_ALLOWED
        analysis.review_status = STATUS_ADMIN_ALLOWED
        self._record_review(
            db=db,
            action="allow",
            analysis=analysis,
            reviewer=reviewer,
            justification=justification,
        )
        tool = db.get(MCPTool, tool_id)
        if tool is not None:
            apply_analysis_to_tool(tool, analysis, baseline)
        return baseline

    def block(
        self,
        *,
        db: Session,
        tool_id: int,
        fingerprint: str,
        reviewer: str,
        justification: str,
    ) -> ToolHumanReview:
        analysis = latest_analysis_for_tool(db, tool_id)
        if analysis is None or analysis.fingerprint != fingerprint:
            raise ValueError("fingerprint does not match the latest analysis.")
        _validate_review(reviewer, justification)
        analysis.analysis_status = STATUS_BLOCKED
        analysis.review_status = STATUS_BLOCKED
        review = self._record_review(
            db=db,
            action="block",
            analysis=analysis,
            reviewer=reviewer,
            justification=justification,
        )
        tool = db.get(MCPTool, tool_id)
        if tool is not None:
            apply_analysis_to_tool(
                tool,
                analysis,
                baseline_for_tool(db, tool_id),
                protocol_approved_match=True,
            )
        return review

    def keep_review_required(
        self,
        *,
        db: Session,
        tool_id: int,
        fingerprint: str,
        reviewer: str,
        justification: str,
    ) -> ToolHumanReview:
        analysis = latest_analysis_for_tool(db, tool_id)
        if analysis is None or analysis.fingerprint != fingerprint:
            raise ValueError("fingerprint does not match the latest analysis.")
        _validate_review(reviewer, justification)
        analysis.analysis_status = STATUS_REVIEW_REQUIRED
        analysis.review_status = STATUS_REVIEW_REQUIRED
        review = self._record_review(
            db=db,
            action="keep_review_required",
            analysis=analysis,
            reviewer=reviewer,
            justification=justification,
        )
        tool = db.get(MCPTool, tool_id)
        if tool is not None:
            apply_analysis_to_tool(tool, analysis, baseline_for_tool(db, tool_id))
        return review

    def _record_review(
        self,
        *,
        db: Session,
        action: str,
        analysis: ToolAnalysis,
        reviewer: str,
        justification: str,
    ) -> ToolHumanReview:
        review = ToolHumanReview(
            tool_id=analysis.tool_id,
            version_id=analysis.version_id,
            analysis_id=analysis.id,
            action=action,
            fingerprint=analysis.fingerprint,
            reviewer=reviewer,
            justification=justification,
        )
        db.add(review)
        db.add(
            AuditEvent(
                category="tool_analysis_review",
                summary=f"Tool analysis review action: {action}",
                related_event_id=str(analysis.tool_id),
                decision=action,
                evidence={
                    "tool_id": analysis.tool_id,
                    "analysis_id": analysis.id,
                    "fingerprint": analysis.fingerprint,
                    "reviewer": reviewer,
                },
            )
        )
        db.flush()
        return review


def apply_analysis_to_tool(
    tool: MCPTool,
    analysis: ToolAnalysis,
    baseline: ToolApprovedBaseline | None,
    *,
    protocol_approved_match: bool | None = None,
) -> None:
    approved_context_match = (
        baseline is not None
        and baseline.fingerprint == analysis.fingerprint
        and reusable_analysis_context_hash(baseline.analysis_context_hash)
        and baseline.analysis_context_hash == analysis.analysis_context_hash
        and baseline.analyzer_revision == ANALYZER_REVISION
        and analysis.analyzer_revision == ANALYZER_REVISION
        and (protocol_approved_match is not False)
    )
    tool.current_fingerprint = analysis.fingerprint
    tool.approved_fingerprint = baseline.fingerprint if baseline else None
    tool.approved_fingerprint_match = approved_context_match
    tool.analysis_status = analysis.analysis_status
    tool.review_status = analysis.review_status
    tool.risk_score = analysis.risk_score
    tool.risk_level = analysis.risk_level
    tool.semantic_flagged = analysis.semantic_flagged == "true"
    tool.deterministic_critical_finding = (
        analysis.deterministic_critical_finding == "true"
    )
    tool.consistency_status = analysis.consistency_status
    tool.drift_status = analysis.drift_status
    tool.analyzer_revision = analysis.analyzer_revision
    tool.policy_status = analysis.analysis_status
    tool.status = analysis.analysis_status
    semantic_facts = (analysis.semantic_scores or {}).get("facts")
    if isinstance(semantic_facts, dict):
        tool.is_sensitive = semantic_facts.get("is_sensitive") is True
        sensitivity = semantic_facts.get("sensitivity")
        tool.sensitivity = sensitivity if isinstance(sensitivity, str) else "unknown"
    tool.last_analyzed_at = analysis.completed_at or analysis.created_at


def mark_tool_contract_pending_publication(tool: MCPTool) -> None:
    """Keep draft-backed analysis evidence from becoming a runtime admission state."""
    tool.analysis_status = STATUS_QUARANTINED
    tool.review_status = STATUS_REVIEW_REQUIRED
    tool.policy_status = STATUS_QUARANTINED
    tool.status = STATUS_QUARANTINED
    tool.approved_fingerprint_match = False


def _upsert_framework_baseline(
    *,
    db: Session,
    tool_id: int,
    version: ToolObservedVersion,
    analysis: ToolAnalysis,
) -> ToolApprovedBaseline:
    baseline = baseline_for_tool(db, tool_id)
    values = {
        "version_id": version.id,
        "analysis_id": analysis.id,
        "fingerprint": analysis.fingerprint,
        "analysis_context_hash": analysis.analysis_context_hash,
        "approval_source": APPROVAL_SOURCE_FRAMEWORK,
        "reviewer": "framework",
        "justification": "Automatically approved after a clean completed analysis.",
        "analyzer_revision": analysis.analyzer_revision,
        "model_versions": analysis.model_versions,
    }
    if baseline is None:
        baseline = ToolApprovedBaseline(tool_id=tool_id, **values)
        db.add(baseline)
    else:
        for field, value in values.items():
            setattr(baseline, field, value)
        baseline.approved_at = datetime.utcnow()
    db.flush()
    return baseline


def _approval_status_for_baseline(baseline: ToolApprovedBaseline) -> str:
    if baseline.approval_source == APPROVAL_SOURCE_ADMIN:
        return STATUS_ADMIN_ALLOWED
    return STATUS_APPROVED


def tool_snapshot_from_model(tool: MCPTool) -> dict[str, Any]:
    return {
        "name": tool.name,
        "title": tool.title,
        "description": normalize_description(tool.description),
        "input_schema": tool.input_schema or {},
        "output_schema": tool.output_schema or {},
        "annotations": tool.annotations or {},
        "execution": tool.execution or {},
    }


def latest_analysis_for_tool(db: Session, tool_id: int) -> ToolAnalysis | None:
    return db.scalar(
        select(ToolAnalysis)
        .where(ToolAnalysis.tool_id == tool_id)
        .order_by(ToolAnalysis.id.desc())
    )


def baseline_for_tool(db: Session, tool_id: int) -> ToolApprovedBaseline | None:
    return db.scalar(
        select(ToolApprovedBaseline).where(ToolApprovedBaseline.tool_id == tool_id)
    )


def latest_protocol_observation(
    db: Session,
    *,
    tool_id: int,
    upstream_protocol_profile_id: str,
    fingerprint: str | None = None,
) -> ToolProtocolObservation | None:
    query = select(ToolProtocolObservation).where(
        ToolProtocolObservation.tool_id == tool_id,
        ToolProtocolObservation.upstream_protocol_profile_id == upstream_protocol_profile_id,
    )
    if fingerprint is not None:
        query = query.where(ToolProtocolObservation.tool_fingerprint == fingerprint)
    return db.scalar(
        query.order_by(
            ToolProtocolObservation.last_seen_at.desc(),
            ToolProtocolObservation.id.desc(),
        )
    )


def approved_protocol_observation_exists(
    db: Session,
    *,
    tool_id: int,
    upstream_protocol_profile_id: str,
    fingerprint: str,
) -> bool:
    observation = latest_protocol_observation(
        db,
        tool_id=tool_id,
        upstream_protocol_profile_id=upstream_protocol_profile_id,
        fingerprint=fingerprint,
    )
    if observation is None or observation.analysis_id is None:
        return False
    analysis = db.get(ToolAnalysis, observation.analysis_id)
    return (
        analysis is not None
        and analysis.analysis_status in {STATUS_APPROVED, STATUS_ADMIN_ALLOWED}
        and analysis.review_status in {STATUS_APPROVED, STATUS_ADMIN_ALLOWED}
        and observation.analysis_state != STATUS_STALE
    )


def normalize_description(description: str | None) -> str:
    if description is None:
        return ""
    return re.sub(r"\s+", " ", description.strip())


def capabilities_from_text(text: str) -> set[str]:
    facts = extract_tool_semantic_facts(
        {
            "name": "",
            "description": text,
            "input_schema": {},
            "output_schema": {},
            "annotations": {},
            "execution": {},
        }
    )
    capabilities = _capabilities_from_semantic_facts(facts)
    lowered = text.lower()
    for pack in SecurityPackRegistry().packs():
        for capability in pack.capabilities:
            if _contains_capability_keyword(lowered, capability.id):
                capabilities.add(capability.id)
    return capabilities


def capabilities_from_profile(profile: dict[str, Any]) -> set[str]:
    return _capabilities_from_v2_contract(profile)


def _unresolved_semantic_unknown_reasons(
    reasons: tuple[str, ...],
    profile_snapshot: dict[str, Any] | None,
) -> tuple[str, ...]:
    unresolved = list(reasons)
    contract = (profile_snapshot or {}).get("contract")
    effects = contract.get("effects") if isinstance(contract, dict) else None
    has_bound_resource = isinstance(effects, list) and any(
        isinstance(effect, dict)
        and (
            bool(effect.get("resource_bindings"))
            or isinstance(effect.get("fixed_resource"), dict)
        )
        for effect in effects
    )
    if has_bound_resource:
        unresolved = [reason for reason in unresolved if reason != "resource_not_evidenced"]
    return tuple(unresolved)


def capabilities_from_schema(schema: dict[str, Any]) -> set[str]:
    facts = extract_tool_semantic_facts(
        {
            "name": "",
            "description": "",
            "input_schema": schema,
            "output_schema": {},
            "annotations": {},
            "execution": {},
        }
    )
    return _capabilities_from_semantic_facts(facts)


def capabilities_from_execution(execution: dict[str, Any]) -> set[str]:
    facts = extract_tool_semantic_facts(
        {
            "name": "",
            "description": "",
            "input_schema": {},
            "output_schema": {},
            "annotations": {},
            "execution": execution,
        }
    )
    return _capabilities_from_semantic_facts(facts)


def _capabilities_from_semantic_facts(facts: ToolSemanticFacts) -> set[str]:
    actions = facts.values("actions")
    resources = facts.values("resources")
    side_effects = facts.values("side_effects")
    capabilities: set[str] = set()

    read_actions = actions.intersection({"read", "search"})
    write_actions = actions.intersection({"create", "update"})
    if "filesystem" in resources:
        if "list" in actions:
            capabilities.add("filesystem.list")
        if read_actions:
            capabilities.add("filesystem.read")
        if write_actions:
            capabilities.add("filesystem.write")
        if "delete" in actions:
            capabilities.add("filesystem.delete")
    if "database" in resources:
        if read_actions or "list" in actions:
            capabilities.add("database.read")
        if write_actions:
            capabilities.add("database.write")
        if "delete" in actions:
            capabilities.add("database.delete")
    if "message" in resources:
        if read_actions or "list" in actions:
            capabilities.add("message.read")
        if "send" in actions or "communication" in side_effects:
            capabilities.add("message.send")
        if "delete" in actions:
            capabilities.add("message.delete")
    if "calendar" in resources:
        if read_actions or "list" in actions:
            capabilities.add("calendar.read")
        if write_actions:
            capabilities.add("calendar.write")
        if "delete" in actions:
            capabilities.add("calendar.delete")
    if "cloud_storage" in resources:
        if read_actions or "list" in actions:
            capabilities.add("cloud.object.read")
        if write_actions or "send" in actions:
            capabilities.add("cloud.object.write")
        if "delete" in actions:
            capabilities.add("cloud.object.delete")
    if "identity" in resources:
        if read_actions or "list" in actions:
            capabilities.add("identity.read")
        if write_actions or "delete" in actions or "authorize" in actions:
            capabilities.add("identity.manage")
    if "secret_store" in resources and (read_actions or "list" in actions):
        capabilities.add("secret.access")
    if "network_endpoint" in resources:
        if read_actions or "search" in actions:
            capabilities.add("network.request")
        if "send" in actions or "external_transfer" in side_effects:
            capabilities.add("network.send")
    if "process" in resources and "execute" in actions:
        capabilities.add("process.execute")
    if "payment" in resources:
        if read_actions or "list" in actions:
            capabilities.add("payment.read")
        if "transact" in actions:
            capabilities.add("payment.initiate")
    if "health_check" in actions:
        capabilities.add("system.ping")
    return capabilities


def _contains_capability_keyword(lowered_text: str, keyword: str) -> bool:
    lowered_keyword = keyword.lower()
    if not lowered_keyword:
        return False
    if any(not (char.isalnum() or char.isspace()) for char in lowered_keyword):
        return lowered_keyword in lowered_text
    parts = re.findall(r"[a-z0-9]+", lowered_keyword)
    if not parts:
        return False
    pattern = r"(?<![a-z0-9])" + r"[\W_]+".join(map(re.escape, parts)) + r"(?![a-z0-9])"
    return re.search(pattern, lowered_text) is not None


def _schema_field_text(field: dict[str, Any]) -> str:
    values: list[str] = []
    for key in ("title", "description"):
        value = field.get(key)
        if isinstance(value, str):
            values.append(value)
    enum_values = field.get("enum")
    if isinstance(enum_values, list):
        values.extend(str(item) for item in enum_values if isinstance(item, str))
    return " ".join(values).lower()


def _annotation_text(value: Any) -> str:
    fragments: list[str] = []

    def visit(item: Any) -> None:
        if isinstance(item, str):
            fragments.append(item)
        elif isinstance(item, list):
            for child in item:
                visit(child)
        elif isinstance(item, dict):
            for child in item.values():
                visit(child)

    visit(value)
    return " ".join(fragments)


def _capabilities_from_v2_contract(profile: dict[str, Any]) -> set[str]:
    contract = profile.get("contract")
    if not isinstance(contract, dict):
        return set()
    effects = contract.get("effects")
    if not isinstance(effects, list):
        return set()
    capabilities: set[str] = set()
    for effect in effects:
        if not isinstance(effect, dict):
            continue
        capability = effect.get("capability")
        if isinstance(capability, str) and capability:
            capabilities.add(capability)
    return capabilities


def _text_findings(source: str, text: str) -> list[AnalysisFinding]:
    findings: list[AnalysisFinding] = []
    if INVISIBLE_RE.search(text):
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
    if BIDI_RE.search(text):
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
    if re.search(
        r"\b(ask|request|collect|capture|extract|steal)\w*"
        r".{0,60}\b(passwords?|credentials?|api[_ -]?keys?|tokens?|secrets?)\b",
        text,
        re.I,
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
    if re.search(
        r"\b(demande[rz]?|collecte[rz]?|capture[rz]?|récup[ée]re[rz]?|extraire|vole[rz]?)\w*"
        r".{0,60}\b(mots? de passe|identifiants?|clés? api|jetons?|secrets?)\b",
        text,
        re.I,
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
    if re.search(
        r"\b(read|access|collect|capture|include|expose|return|lire|accéder|collecter|inclure|exposer)\w*"
        r".{0,50}\b(\.env|environment variables?|include_env|process\.env|variables? d'environnement)\b",
        text,
        re.I,
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
    if re.search(
        r"\b(ignore|bypass|disable|ignorer?|contourner?|désactiver?)"
        r".{0,40}\b(policy|security|restriction|instruction|politique|sécurité|règle)",
        text,
        re.I,
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


def _schema_findings(
    schema: dict[str, Any],
    source: str,
    profile_capabilities: set[str] | None = None,
    semantic_facts: ToolSemanticFacts | None = None,
) -> list[AnalysisFinding]:
    findings: list[AnalysisFinding] = []
    if schema.get("additionalProperties") is True:
        findings.append(
            _finding(
                "schema_additional_properties_true",
                "schema_permissive",
                source,
                "medium",
                82,
                "additionalProperties is true",
                "Declare explicit properties and reject unexpected inputs.",
                decision=FINDING_DECISION_REVIEW,
            )
        )
    properties = _schema_properties(schema)
    if not properties and schema and not _is_closed_zero_argument_schema(schema):
        findings.append(
            _finding(
                "schema_too_permissive",
                "schema_permissive",
                source,
                "medium",
                70,
                "schema has no declared properties",
                "Declare a narrow input schema.",
                decision=FINDING_DECISION_REVIEW,
            )
        )
    for path, name, field in iter_schema_fields(schema):
        lowered = name.lower()
        field_text = _safe_json(field)
        if lowered in SENSITIVE_PARAMETER_NAMES and not _parameter_expected_by_contract(
            lowered,
            profile_capabilities or set(),
        ):
            process_evidenced = (
                lowered in {"command", "shell", "script"}
                and semantic_facts is not None
                and "code_execution" in semantic_facts.values("side_effects")
            )
            if lowered in {"command", "shell", "script"} and not process_evidenced:
                continue
            severity = "high" if process_evidenced else "medium"
            findings.append(
                _finding(
                    f"sensitive_parameter_{lowered}",
                    "dangerous_parameter",
                    source,
                    severity,
                    90 if process_evidenced else 74,
                    f"parameter '{_safe_excerpt(name)}' at {path}",
                    "Require an explicit security profile and human review for this parameter.",
                    decision=(
                        FINDING_DECISION_BLOCK
                        if process_evidenced
                        else FINDING_DECISION_REVIEW
                    ),
                )
            )
        findings.extend(_text_findings(source, field_text))
    return findings


def _parameter_expected_by_contract(name: str, capabilities: set[str]) -> bool:
    if name in {"command", "shell", "script"}:
        return "process.execute" in capabilities
    if name in {"upload_url", "callback_url", "destination_url"}:
        return bool(capabilities.intersection({"network.request", "network.send"}))
    if name in {"include_env", "credentials", "token"}:
        return bool(
            capabilities.intersection(
                {"secret.read", "secret.access", "identity.manage"}
            )
        )
    if name in {"delete", "overwrite"}:
        return any(
            capability.endswith(".delete")
            or capability in {"filesystem.write", "database.write"}
            for capability in capabilities
        )
    return False


def _is_closed_zero_argument_schema(schema: dict[str, Any]) -> bool:
    return (
        schema.get("type") == "object"
        and schema.get("properties") == {}
        and schema.get("additionalProperties") is False
    )


def _schema_diff(previous: dict[str, Any], current: dict[str, Any]) -> list[dict[str, Any]]:
    changes: list[dict[str, Any]] = []
    previous_props = _schema_properties(previous)
    current_props = _schema_properties(current)
    for name in sorted(set(current_props) - set(previous_props)):
        field_name = _schema_field_name(name)
        field_text = _schema_field_text(current_props[name])
        process_execution = field_name in {"command", "shell", "script"} and bool(
            re.search(
                r"\b(shell|script|process|executable|operating system command).{0,30}\b(execute|run|launch|execution)\b"
                r"|\b(execute|run|launch).{0,30}\b(shell|script|process|executable|operating system command)\b",
                field_text,
                re.IGNORECASE,
            )
        )
        severity = (
            "critical"
            if process_execution
            else "high"
            if field_name in {"upload_url", "callback_url", "destination_url"}
            else "medium"
        )
        changes.append({"type": "parameter_added", "name": name, "severity": severity})
    for name in sorted(set(previous_props) - set(current_props)):
        changes.append({"type": "parameter_removed", "name": name, "severity": "low"})
    for name in sorted(set(previous_props) & set(current_props)):
        if previous_props[name].get("type") != current_props[name].get("type"):
            changes.append({"type": "parameter_type_changed", "name": name, "severity": "high"})
        previous_enum = previous_props[name].get("enum")
        current_enum = current_props[name].get("enum")
        if isinstance(previous_enum, list) and isinstance(current_enum, list):
            if set(map(str, current_enum)) - set(map(str, previous_enum)):
                changes.append({"type": "enum_expanded", "name": name, "severity": "medium"})
    if previous.get("additionalProperties") != current.get("additionalProperties"):
        changes.append({"type": "additional_properties_modified", "severity": "high"})
    previous_required = set(previous.get("required") or [])
    current_required = set(current.get("required") or [])
    for name in sorted(previous_required - current_required):
        changes.append({"type": "field_became_optional", "name": name, "severity": "medium"})
    for name in sorted(current_required - previous_required):
        changes.append({"type": "field_became_required", "name": name, "severity": "low"})
    return changes


def _drift_findings(drift: DriftResult) -> list[AnalysisFinding]:
    findings: list[AnalysisFinding] = []
    for change in drift.changes:
        if change.get("severity") in {"high", "critical"}:
            findings.append(
                _finding(
                    f"drift_{change['type']}",
                    "drift",
                    "schema",
                    str(change["severity"]),
                    84,
                    _safe_json(change),
                    "Review the changed tool version before approval.",
                )
            )
    return findings


def _drift_status(changes: list[dict[str, Any]], similarity: float | None) -> str:
    if not changes:
        return DRIFT_NONE if similarity is None else DRIFT_BENIGN
    severities = {change.get("severity") for change in changes}
    if "critical" in severities:
        return DRIFT_CRITICAL
    if "high" in severities:
        return DRIFT_HIGH
    if "medium" in severities:
        return DRIFT_MEDIUM
    return DRIFT_LOW


def _drift_severity_score(status: str) -> int:
    return {
        DRIFT_NONE: 0,
        DRIFT_BENIGN: 5,
        DRIFT_LOW: 15,
        DRIFT_MEDIUM: 40,
        DRIFT_HIGH: 70,
        DRIFT_CRITICAL: 95,
    }.get(status, 40)


def _risk_score(
    findings: list[AnalysisFinding],
    semantic_result: SemanticResult,
    drift: DriftResult,
) -> int:
    severity_scores = {
        "low": 15,
        "medium": 35,
        "high": 70,
        "critical": 95,
    }
    score = 0
    for finding in findings:
        score = max(score, severity_scores.get(finding.severity, 20))
    if semantic_result.flagged:
        score = max(40, score, int(math.ceil(semantic_result.confidence * 100)))
    score = max(score, _drift_severity_score(drift.status))
    return min(100, score)


def _risk_level(score: int) -> str:
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 15:
        return "low"
    return "info"


def _capability_mismatch_code(capabilities: set[str]) -> str:
    if "process.execute" in capabilities:
        return "unexpected_process_execution"
    if "secret.access" in capabilities:
        return "unexpected_secret_access"
    if "filesystem.delete" in capabilities:
        return "unexpected_destructive_operation"
    if "network.send" in capabilities:
        return "unexpected_network_capability"
    return "schema_profile_mismatch"


def _schema_properties(schema: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        path: value
        for path, _name, value in iter_schema_fields(schema)
    }


def _schema_field_name(path: str) -> str:
    return path.rsplit(".", 1)[-1].lower()


def _semantic_text(tool_snapshot: dict[str, Any]) -> str:
    fragments = [
        str(tool_snapshot.get("name") or ""),
        strip_documentation_examples(
            str(tool_snapshot.get("description") or "")
        )[:3000],
    ]
    for _path, name, field in iter_schema_fields(tool_snapshot.get("input_schema") or {}):
        fragments.append(name)
        fragments.append(_schema_field_text(field)[:240])
    for _path, name, field in iter_schema_fields(tool_snapshot.get("output_schema") or {}):
        fragments.append(name)
        fragments.append(_schema_field_text(field)[:240])
    annotation_text = _annotation_text(tool_snapshot.get("annotations") or {})
    if annotation_text:
        fragments.append(annotation_text[:1000])
    execution_text = _annotation_text(tool_snapshot.get("execution") or {})
    if execution_text:
        fragments.append(execution_text[:1000])
    return normalize_description(" ".join(fragment for fragment in fragments if fragment))[:8000]


def _semantic_categories(profile_snapshot: dict[str, Any] | None) -> list[str]:
    categories = list(SEMANTIC_CATEGORIES)
    pack = (profile_snapshot or {}).get("security_pack")
    declared_categories = pack.get("semantic_categories") if isinstance(pack, dict) else None
    if isinstance(declared_categories, (list, tuple)):
        categories.extend(
            value for value in declared_categories if isinstance(value, str) and value
        )
    pack_id = pack.get("id") if isinstance(pack, dict) else None
    if isinstance(pack_id, str):
        manifest = next(
            (value for value in SecurityPackRegistry().packs() if value.id == pack_id),
            None,
        )
        if manifest is not None:
            categories.extend(manifest.semantic_categories)
    return list(dict.fromkeys(categories))


def _corroborate_semantic_result(
    result: SemanticResult,
    text: str,
    facts: ToolSemanticFacts,
) -> SemanticResult:
    candidates = sorted(
        (
            (category, score)
            for category, score in result.scores.items()
            if category != "normal_tool_description"
        ),
        key=lambda item: item[1],
        reverse=True,
    )
    for category, score in candidates:
        if score < SEMANTIC_REVIEW_THRESHOLD:
            continue
        patterns = SEMANTIC_CORROBORATION_PATTERNS.get(category, ())
        pattern_match = any(
            re.search(pattern, text, re.IGNORECASE)
            for pattern in patterns
        )
        if pattern_match and _semantic_fact_support(category, facts, text):
            return replace(
                result,
                best_category=category,
                confidence=score,
                flagged=True,
            )
    return replace(result, flagged=False)


def _semantic_fact_support(
    category: str,
    facts: ToolSemanticFacts,
    text: str,
) -> bool:
    actions = facts.values("actions")
    resources = facts.values("resources")
    data = facts.values("data_categories")
    side_effects = facts.values("side_effects")
    scopes = facts.values("scopes")
    privileges = facts.values("privileges")
    destinations = facts.values("external_destinations")
    sensitive_transfer_data = data.intersection(
        {"credentials", "personal_data", "financial_data", "source_code", "location"}
    )
    explicit_exfiltration = bool(
        re.search(
            r"\b(exfiltrat\w*|collector|secretly|covertly|without (?:consent|notifying))\b",
            text,
            re.IGNORECASE,
        )
        or any("collector" in destination for destination in destinations)
    )
    requirements = {
        "prompt_injection": True,
        "security_bypass": True,
        "secret_collection": "credentials" in data,
        "data_exfiltration": bool(
            (destinations or "external_transfer" in side_effects)
            and (sensitive_transfer_data or explicit_exfiltration)
        ),
        "hidden_additional_action": bool(side_effects),
        # Execution is a capability, not a security defect by itself. Contract
        # consistency and shell-injection evidence decide whether it is risky.
        "command_execution": False,
        "unauthorized_data_access": bool(resources),
        "user_deception": True,
        "privilege_escalation": bool(privileges) and "authorize" in actions,
        "cross_tenant_access": "cross_tenant" in scopes,
        "unexpected_destructive_operation": "destructive" in side_effects,
        "public_sharing": "public_exposure" in side_effects or "public" in scopes,
        "bulk_messaging": "bulk" in scopes and "message" in resources,
        "server_side_request_forgery": bool(destinations or "network_endpoint" in resources),
        "shell_injection": "process" in resources,
        "unauthorized_financial_transaction": "financial_transaction" in side_effects,
    }
    return requirements.get(category, True)


def _tokens(text: str) -> list[str]:
    return re.findall(r"[a-z0-9._-]+", text.lower())


def _looks_like_encoded_instruction(value: str) -> bool:
    try:
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), validate=False)
    except Exception:
        return False
    if not decoded:
        return False
    text = decoded[:512].decode("utf-8", errors="ignore").lower()
    return any(word in text for word in ("ignore", "secret", "token", "upload", "command"))


def _finding(
    code: str,
    category: str,
    source: str,
    severity: str,
    confidence: int,
    evidence: str,
    recommendation: str,
    *,
    decision: str = FINDING_DECISION_REVIEW,
) -> AnalysisFinding:
    if decision not in {
        FINDING_DECISION_BLOCK,
        FINDING_DECISION_REVIEW,
        FINDING_DECISION_INFO,
    }:
        raise ValueError("invalid finding decision")
    return AnalysisFinding(
        code=code,
        category=category,
        source=source,
        severity=severity,
        confidence=max(0, min(100, int(confidence))),
        evidence={
            "summary": _safe_excerpt(evidence),
            "decision": decision,
        },
        recommendation=recommendation,
    )


def _finding_decision(finding: AnalysisFinding) -> str:
    decision = finding.evidence.get("decision")
    if decision in {
        FINDING_DECISION_BLOCK,
        FINDING_DECISION_REVIEW,
        FINDING_DECISION_INFO,
    }:
        return str(decision)
    if finding.code in CRITICAL_DETERMINISTIC_CODES:
        return FINDING_DECISION_BLOCK
    return FINDING_DECISION_REVIEW


def _deduplicate_findings(
    findings: list[AnalysisFinding],
) -> list[AnalysisFinding]:
    unique: dict[tuple[str, str, str], AnalysisFinding] = {}
    for finding in findings:
        key = (
            finding.code,
            finding.source,
            str(finding.evidence.get("summary") or ""),
        )
        unique.setdefault(key, finding)
    return list(unique.values())


def _safe_excerpt(value: str, limit: int = 160) -> str:
    text = re.sub(r"\s+", " ", str(value)).strip()
    text = re.sub(
        r"(?i)(token|password|secret|api[_ -]?key|credential)=?[A-Za-z0-9._~+/=-]+",
        r"\1=<redacted>",
        text,
    )
    if len(text) > limit:
        return f"{text[:limit]}..."
    return text


def _safe_json(value: Any) -> str:
    try:
        return canonical_json_bytes(value).decode("utf-8")
    except Exception:
        return str(value)


def _json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _json_safe(item)
            for key, item in value.items()
            if key != "findings"
        }
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    return value


def _validate_review(reviewer: str, justification: str) -> None:
    if not reviewer.strip():
        raise ValueError("reviewer is required.")
    if len(justification.strip()) < MIN_REVIEW_JUSTIFICATION_LENGTH:
        raise ValueError("review justification is too short.")


def _validate_approvable_analysis(
    db: Session,
    tool_id: int,
    fingerprint: str,
    analysis: ToolAnalysis,
    version: ToolObservedVersion,
) -> None:
    if analysis.analysis_status in {
        STATUS_ANALYSIS_FAILED,
        STATUS_PENDING_ANALYSIS,
        STATUS_QUARANTINED,
        STATUS_BLOCKED,
        STATUS_STALE,
    }:
        raise ValueError("analysis status cannot be approved.")
    if analysis.completed_at is None:
        raise ValueError("analysis is not complete.")
    if version.fingerprint != fingerprint:
        raise ValueError("observed version fingerprint does not match.")
    if analysis.analyzer_revision != ANALYZER_REVISION:
        raise ValueError("analysis was produced by an outdated analyzer revision.")
    if not reusable_analysis_context_hash(analysis.analysis_context_hash):
        raise ValueError("analysis context hash is missing or invalid.")
    tool = db.get(MCPTool, tool_id)
    if tool is None:
        raise ValueError("tool is missing.")
    if tool.current_fingerprint != fingerprint:
        raise ValueError("fingerprint does not match the current tool version.")
    if not analysis.semantic_scores or not analysis.drift_result or not analysis.model_versions:
        raise ValueError("analysis results are incomplete.")
    if analysis.analysis_status == STATUS_REVIEW_REQUIRED and analysis.review_status not in {
        STATUS_REVIEW_REQUIRED,
        STATUS_APPROVED,
        STATUS_ADMIN_ALLOWED,
    }:
        raise ValueError("review status is not approvable.")


def _model_version_from_config(model: Any, fallback: str) -> str:
    config = getattr(model, "config", None)
    commit_hash = getattr(config, "_commit_hash", None)
    if commit_hash:
        return str(commit_hash)
    name_or_path = getattr(config, "name_or_path", None)
    if name_or_path:
        path = Path(str(name_or_path))
        if path.parent.name == "snapshots":
            return path.name
        return str(name_or_path)
    return fallback


def _sentence_transformer_version(model: Any, fallback: str) -> str:
    for module in model.modules():
        auto_model = getattr(module, "auto_model", None)
        version = _model_version_from_config(auto_model, "")
        if version:
            return version
    return fallback


def _local_snapshot_path(cache_dir: Path, model_name: str) -> Path | None:
    model_dir = cache_dir / f"models--{model_name.replace('/', '--')}"
    refs_main = model_dir / "refs" / "main"
    if refs_main.exists():
        revision = refs_main.read_text(encoding="utf-8").strip()
        snapshot = model_dir / "snapshots" / revision
        if snapshot.exists():
            return snapshot
    snapshots_dir = model_dir / "snapshots"
    if not snapshots_dir.exists():
        return None
    snapshots = sorted(
        (path for path in snapshots_dir.iterdir() if path.is_dir()),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    return snapshots[0] if snapshots else None
