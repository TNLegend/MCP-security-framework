from __future__ import annotations

import base64
from dataclasses import dataclass
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
from proxy.protocol_profiles import LEGACY_PROFILE_ID, ProtocolProfileError, ProtocolProfileRegistry


ANALYZER_REVISION = "tool-description-analyzer-v1"
SEMANTIC_MODEL_NAME = "MoritzLaurer/multilingual-MiniLMv2-L6-mnli-xnli"
EMBEDDING_MODEL_NAME = "intfloat/multilingual-e5-small"
SEMANTIC_MODEL_VERSION = "local-cache"
EMBEDDING_MODEL_VERSION = "local-cache"
SEMANTIC_REVIEW_THRESHOLD = 0.74
MIN_REVIEW_JUSTIFICATION_LENGTH = 8
INVALID_ANALYSIS_CONTEXT_PREFIX = "invalid:"

STATUS_PENDING_ANALYSIS = "PENDING_ANALYSIS"
STATUS_QUARANTINED = "QUARANTINED"
STATUS_REVIEW_REQUIRED = "REVIEW_REQUIRED"
STATUS_APPROVED = "APPROVED"
STATUS_BLOCKED = "BLOCKED"
STATUS_ANALYSIS_FAILED = "ANALYSIS_FAILED"
STATUS_STALE = "STALE"

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
]

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

CAPABILITY_KEYWORDS = {
    "filesystem.read": ("read", "open", "download", "view", "list", "inspect"),
    "filesystem.list": ("list", "enumerate", "directory", "folder"),
    "filesystem.write": ("write", "create", "save", "modify", "update"),
    "filesystem.delete": ("delete", "remove", "erase", "overwrite"),
    "network.send": ("send", "upload", "callback", "webhook", "http", "url"),
    "secret.access": ("secret", "credential", "token", "api key", "env", ".env"),
    "process.execute": ("command", "shell", "script", "execute", "run process"),
    "database.select": ("select", "query", "read database"),
    "database.modify": ("insert", "update", "modify database"),
    "database.delete": ("drop", "delete database", "truncate"),
}

INVISIBLE_RE = re.compile(
    "[\u200b\u200c\u200d\u2060\ufeff\u00ad]",
)
BIDI_RE = re.compile("[\u202a-\u202e\u2066-\u2069]")
HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
URL_RE = re.compile(r"https?://[^\s)>\"]+", re.IGNORECASE)
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
        result = classifier(text, categories, multi_label=True)
        labels = result.get("labels", [])
        scores = result.get("scores", [])
        score_map = {
            str(label): float(score)
            for label, score in zip(labels, scores)
            if str(label) in categories
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
    profile: dict[str, Any] | None,
) -> dict[str, Any]:
    # Profile and registry identity are deliberately separate approval artifacts.
    _ = server_ref, profile
    return {
        "tool_name": tool_name,
        "description": normalize_description(description),
        "input_schema": input_schema or {},
        "output_schema": output_schema or {},
        "annotations": annotations or {},
    }


def compute_tool_fingerprint(payload: dict[str, Any]) -> str:
    return sha256(canonical_json_bytes(payload)).hexdigest()


def analysis_context_payload(profile_snapshot: dict[str, Any] | None) -> dict[str, Any]:
    if profile_snapshot is None:
        return {"schema_version": 0, "profile": None}

    if profile_snapshot.get("schema_version") == 2:
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

    return {
        "schema_version": 1,
        "server_ref": profile_snapshot.get("server_ref"),
        "tool_name": profile_snapshot.get("tool_name"),
        "operation": profile_snapshot.get("operation"),
        "required_capability": profile_snapshot.get("required_capability"),
        "resource": profile_snapshot.get("resource") or {},
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
    findings = deterministic_findings(tool_snapshot, profile_snapshot)
    active_semantic_model = semantic_model or LocalZeroShotSemanticModel()
    active_embedding_model = embedding_model or LocalEmbeddingModel()
    semantic_result = active_semantic_model.classify(
        _semantic_text(tool_snapshot),
        SEMANTIC_CATEGORIES,
    )
    consistency = consistency_result(tool_snapshot, profile_snapshot)
    drift = drift_result(
        baseline_snapshot,
        tool_snapshot,
        active_embedding_model,
    )
    findings.extend(consistency["findings"])
    findings.extend(_drift_findings(drift))

    deterministic_critical = any(
        finding.severity == "critical" or finding.code in CRITICAL_DETERMINISTIC_CODES
        for finding in findings
    )
    risk_score = _risk_score(findings, semantic_result, drift)
    risk_level = _risk_level(risk_score)
    if deterministic_critical:
        status = STATUS_BLOCKED
        review_status = STATUS_BLOCKED
    elif semantic_result.flagged:
        status = STATUS_REVIEW_REQUIRED
        review_status = STATUS_REVIEW_REQUIRED
    else:
        status = STATUS_REVIEW_REQUIRED
        review_status = STATUS_REVIEW_REQUIRED

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
) -> list[AnalysisFinding]:
    findings: list[AnalysisFinding] = []
    text_sources = {
        "description": tool_snapshot.get("description") or "",
        "annotation": _safe_json(tool_snapshot.get("annotations") or {}),
    }
    for source, text in text_sources.items():
        findings.extend(_text_findings(source, text))

    schema = tool_snapshot.get("input_schema") or {}
    output_schema = tool_snapshot.get("output_schema") or {}
    findings.extend(_schema_findings(schema, "schema"))
    findings.extend(_schema_findings(output_schema, "schema"))

    profile_text = _safe_json(profile_snapshot or {})
    if "secret" in profile_text.lower():
        findings.append(
            _finding(
                "profile_secret_capability",
                "capability",
                "profile",
                "medium",
                80,
                "profile mentions secret access",
                "Confirm that secret access is explicitly intended.",
            )
        )
    return findings


def consistency_result(
    tool_snapshot: dict[str, Any],
    profile_snapshot: dict[str, Any] | None,
) -> dict[str, Any]:
    description_caps = capabilities_from_text(
        f"{tool_snapshot.get('name', '')} {tool_snapshot.get('description') or ''}"
    )
    schema_caps = capabilities_from_schema(tool_snapshot.get("input_schema") or {})
    annotation_caps = capabilities_from_text(_safe_json(tool_snapshot.get("annotations") or {}))
    profile_caps = capabilities_from_profile(profile_snapshot or {})
    findings: list[AnalysisFinding] = []

    technical_caps = schema_caps | annotation_caps
    extra_schema_caps = technical_caps - profile_caps
    extra_description_caps = description_caps - profile_caps

    if extra_schema_caps:
        code = _capability_mismatch_code(extra_schema_caps)
        findings.append(
            _finding(
                code,
                "consistency",
                "schema",
                "critical" if code in CRITICAL_DETERMINISTIC_CODES else "high",
                88,
                f"schema capabilities exceed profile: {', '.join(sorted(extra_schema_caps))}",
                "Narrow the schema or update the official Tool Security Profile.",
            )
        )
    if extra_description_caps:
        findings.append(
            _finding(
                "schema_profile_mismatch",
                "consistency",
                "description",
                "medium",
                78,
                f"description capabilities exceed profile: {', '.join(sorted(extra_description_caps))}",
                "Review whether the profile authorizes the described behavior.",
            )
        )
    if "filesystem.delete" in technical_caps and "read" in (tool_snapshot.get("description") or "").lower():
        findings.append(
            _finding(
                "unexpected_destructive_operation",
                "consistency",
                "schema",
                "critical",
                92,
                "delete-like parameter appears in read-only description",
                "Remove destructive parameters from read-only tools.",
            )
        )
    if "network.send" in technical_caps and profile_caps <= {"filesystem.read", "filesystem.list"}:
        findings.append(
            _finding(
                "unexpected_network_capability",
                "consistency",
                "schema",
                "high",
                90,
                "network destination appears for local filesystem profile",
                "Separate network sending into an explicitly profiled tool.",
            )
        )
    status = "consistent" if not findings else "mismatch"
    return {
        "status": status,
        "description_capabilities": sorted(description_caps),
        "schema_capabilities": sorted(schema_caps),
        "annotation_capabilities": sorted(annotation_caps),
        "profile_capabilities": sorted(profile_caps),
        "findings": findings,
    }


def drift_result(
    baseline_snapshot: dict[str, Any] | None,
    current_snapshot: dict[str, Any],
    embedding_model: EmbeddingModel,
) -> DriftResult:
    if baseline_snapshot is None:
        return DriftResult(status=DRIFT_NONE, changes=[], similarity=None)

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
        self.semantic_model = semantic_model
        self.embedding_model = embedding_model

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
        tool.analysis_status = STATUS_APPROVED if approved_match else STATUS_QUARANTINED
        tool.review_status = STATUS_APPROVED if approved_match else STATUS_REVIEW_REQUIRED
        tool.status = STATUS_APPROVED if approved_match else STATUS_QUARANTINED
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

        apply_analysis_to_tool(tool, analysis, baseline)
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
        analysis = ToolAnalysis(
            tool_id=tool.id,
            version_id=version.id,
            fingerprint=version.fingerprint,
            analysis_context_hash=analysis_context_hash,
            analysis_status=STATUS_APPROVED,
            risk_score=tool.risk_score,
            risk_level=tool.risk_level,
            semantic_flagged="false",
            deterministic_critical_finding="false",
            consistency_status=tool.consistency_status,
            drift_status=DRIFT_NONE,
            review_status=STATUS_APPROVED,
            semantic_scores=None,
            consistency_result=None,
            drift_result={"status": DRIFT_NONE, "changes": [], "similarity": None},
            model_versions=baseline.model_versions,
            analyzer_revision=baseline.analyzer_revision,
            created_at=now,
            completed_at=now,
        )
        db.add(analysis)
        db.flush()
        apply_analysis_to_tool(tool, analysis, baseline)
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
            baseline.reviewer = reviewer
            baseline.justification = justification
            baseline.analyzer_revision = analysis.analyzer_revision
            baseline.model_versions = analysis.model_versions
            baseline.approved_at = datetime.utcnow()
        analysis.analysis_status = STATUS_APPROVED
        analysis.review_status = STATUS_APPROVED
        self._record_review(
            db=db,
            action="approve",
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
            apply_analysis_to_tool(tool, analysis, baseline_for_tool(db, tool_id))
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
) -> None:
    approved_context_match = (
        baseline is not None
        and baseline.fingerprint == analysis.fingerprint
        and reusable_analysis_context_hash(baseline.analysis_context_hash)
        and baseline.analysis_context_hash == analysis.analysis_context_hash
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
    tool.last_analyzed_at = analysis.completed_at or analysis.created_at


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


def normalize_description(description: str | None) -> str:
    if description is None:
        return ""
    return re.sub(r"\s+", " ", description.strip())


def capabilities_from_text(text: str) -> set[str]:
    lowered = text.lower()
    capabilities: set[str] = set()
    for capability, keywords in CAPABILITY_KEYWORDS.items():
        if any(keyword in lowered for keyword in keywords):
            capabilities.add(capability)
    return capabilities


def capabilities_from_profile(profile: dict[str, Any]) -> set[str]:
    required = profile.get("required_capability")
    capabilities = {required} if isinstance(required, str) and required else set()
    operation = profile.get("operation")
    if operation == "read":
        capabilities.add("filesystem.read")
    if operation == "list":
        capabilities.add("filesystem.list")
    return capabilities


def capabilities_from_schema(schema: dict[str, Any]) -> set[str]:
    text = _safe_json(schema)
    capabilities = capabilities_from_text(text)
    for name, field in _schema_properties(schema).items():
        lowered_name = name.lower()
        field_text = _safe_json(field).lower()
        if lowered_name in {"upload_url", "callback_url", "destination_url"}:
            capabilities.add("network.send")
        if lowered_name in {"command", "shell", "script"}:
            capabilities.add("process.execute")
        if lowered_name in {"credentials", "token", "include_env"}:
            capabilities.add("secret.access")
        if lowered_name in {"delete", "overwrite"}:
            capabilities.add("filesystem.delete")
        if "delete" in field_text or "overwrite" in field_text:
            capabilities.add("filesystem.delete")
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
            )
        )
    for url in URL_RE.findall(text):
        findings.append(
            _finding(
                "external_url_reference",
                "network",
                source,
                "medium",
                75,
                _safe_excerpt(url),
                "Review whether external network destinations are expected.",
            )
        )
    if re.search(r"\b(passwords?|credentials?|api[_ -]?keys?|tokens?)\b", text, re.I):
        findings.append(
            _finding(
                "credential_request",
                "secret_collection",
                source,
                "critical",
                88,
                "credential-like request found",
                "Do not collect credentials through tool descriptions or schemas.",
            )
        )
    if re.search(r"\b(\.env|environment variables?|include_env|process\.env)\b", text, re.I):
        findings.append(
            _finding(
                "environment_secret_access",
                "secret_collection",
                source,
                "critical",
                90,
                "environment secret access requested",
                "Remove environment secret access from the tool contract.",
            )
        )
    if re.search(r"\b(ignore|bypass|disable).{0,40}\b(policy|security|restriction|instruction)", text, re.I):
        findings.append(
            _finding(
                "ignore_security_restrictions",
                "prompt_injection",
                source,
                "critical",
                91,
                "instruction to bypass security restrictions detected",
                "Remove prompt-injection instructions from the tool metadata.",
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
                )
            )
            break
    return findings


def _schema_findings(schema: dict[str, Any], source: str) -> list[AnalysisFinding]:
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
            )
        )
    properties = _schema_properties(schema)
    if not properties and schema:
        findings.append(
            _finding(
                "schema_too_permissive",
                "schema_permissive",
                source,
                "medium",
                70,
                "schema has no declared properties",
                "Declare a narrow input schema.",
            )
        )
    for name, field in properties.items():
        lowered = name.lower()
        field_text = _safe_json(field)
        if lowered in SENSITIVE_PARAMETER_NAMES:
            severity = "critical" if lowered in {"command", "shell", "script", "include_env", "credentials", "token", "delete"} else "high"
            findings.append(
                _finding(
                    f"sensitive_parameter_{lowered}",
                    "dangerous_parameter",
                    source,
                    severity,
                    85,
                    f"parameter '{_safe_excerpt(name)}'",
                    "Require an explicit security profile and human review for this parameter.",
                )
            )
        findings.extend(_text_findings(source, field_text))
    return findings


def _schema_diff(previous: dict[str, Any], current: dict[str, Any]) -> list[dict[str, Any]]:
    changes: list[dict[str, Any]] = []
    previous_props = _schema_properties(previous)
    current_props = _schema_properties(current)
    for name in sorted(set(current_props) - set(previous_props)):
        severity = "critical" if name.lower() in {"command", "shell", "script", "delete"} else "high" if name.lower() in {"upload_url", "callback_url", "destination_url"} else "medium"
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
        score = max(score, int(math.ceil(semantic_result.confidence * 100)))
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
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        return {}
    return {
        str(name): value
        for name, value in properties.items()
        if isinstance(value, dict)
    }


def _semantic_text(tool_snapshot: dict[str, Any]) -> str:
    return " ".join(
        [
            str(tool_snapshot.get("name") or ""),
            str(tool_snapshot.get("description") or ""),
            _safe_json(tool_snapshot.get("annotations") or {}),
            _safe_json(tool_snapshot.get("input_schema") or {}),
            _safe_json(tool_snapshot.get("output_schema") or {}),
        ]
    )


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
) -> AnalysisFinding:
    return AnalysisFinding(
        code=code,
        category=category,
        source=source,
        severity=severity,
        confidence=max(0, min(100, int(confidence))),
        evidence={"summary": _safe_excerpt(evidence)},
        recommendation=recommendation,
    )


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
