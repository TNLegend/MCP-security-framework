"""Frozen analysis evidence, independent of mutable governance decisions.

Checksums bind reuse within the trusted database; they do not defend against a
DB administrator who can rewrite evidence and its digest. No permissions here.
"""

from copy import deepcopy
from hashlib import sha256
import json
from sqlalchemy import select

KEY = "frozen_analysis_evidence_v1"
LINEAGE = "approval_reuse_v1"


def digest(value):
    return sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode()
    ).hexdigest()


def findings(db, analysis_id):
    from app.models.tool_analysis import ToolAnalysisFinding

    rows = db.scalars(
        select(ToolAnalysisFinding)
        .where(ToolAnalysisFinding.analysis_id == analysis_id)
        .order_by(ToolAnalysisFinding.id)
    ).all()
    return [
        deepcopy(
            {
                k: getattr(r, k)
                for k in (
                    "code",
                    "category",
                    "source",
                    "severity",
                    "confidence",
                    "evidence",
                    "recommendation",
                )
            }
        )
        for r in rows
    ]


def projection(db, analysis):
    return deepcopy(
        {
            "source_analysis_id": analysis.id,
            "fingerprint": analysis.fingerprint,
            "analysis_context_hash": analysis.analysis_context_hash,
            "analyzer_revision": analysis.analyzer_revision,
            "model_versions": analysis.model_versions,
            "analysis_status": analysis.analysis_status,
            "review_status": analysis.review_status,
            "risk_score": analysis.risk_score,
            "risk_level": analysis.risk_level,
            "semantic_flagged": analysis.semantic_flagged,
            "deterministic_critical_finding": analysis.deterministic_critical_finding,
            "consistency_status": analysis.consistency_status,
            "drift_status": analysis.drift_status,
            "semantic_scores": {
                k: v
                for k, v in (analysis.semantic_scores or {}).items()
                if k not in (KEY, LINEAGE)
            },
            "consistency_result": analysis.consistency_result,
            "drift_result": analysis.drift_result,
            "findings": findings(db, analysis.id),
        }
    )


def freeze_before_review(db, analysis):
    if analysis.analysis_status == "ADMIN_ALLOWED" and KEY not in (
        analysis.semantic_scores or {}
    ):
        raise ValueError("legacy_review_evidence_not_frozen")
    prior = (analysis.semantic_scores or {}).get(KEY)
    if prior:
        validate_frozen(db, analysis, prior)
        return
    payload = projection(db, analysis)
    analysis.semantic_scores = {
        **(analysis.semantic_scores or {}),
        KEY: {"sha256": digest(payload), "payload": payload},
    }


def validate_frozen(db, source, record):
    if (
        not isinstance(record, dict)
        or not isinstance(record.get("payload"), dict)
        or digest(record["payload"]) != record.get("sha256")
    ):
        raise ValueError("frozen_evidence_digest_mismatch")
    frozen = record["payload"]
    current = projection(db, source)
    if current["source_analysis_id"] != frozen["source_analysis_id"]:
        lineage = (source.semantic_scores or {}).get(LINEAGE, {})
        original_id = lineage.get(
            "original_evidence_analysis_id", lineage.get("source_analysis_id")
        )
        if (
            lineage.get("source_evidence_sha256") != record["sha256"]
            or original_id != frozen["source_analysis_id"]
            or lineage.get("new_semantic_inference") is not False
        ):
            raise ValueError("invalid_reused_evidence_lineage")
        current["source_analysis_id"] = frozen["source_analysis_id"]
    for name in current:
        if (
            name not in ("analysis_status", "review_status")
            and current[name] != frozen[name]
        ):
            raise ValueError("source_evidence_changed:" + name)
    return frozen


def has_frozen_evidence(analysis):
    return analysis is not None and KEY in (analysis.semantic_scores or {})


def evidence_provenance(analysis):
    """Small consumer view; full evidence remains in the signed bundle."""
    scores = analysis.semantic_scores or {}
    record = scores.get(KEY)
    lineage = scores.get(LINEAGE)
    if not record:
        return {"state": "LEGACY_UNFROZEN", "new_semantic_inference": None}
    return {
        "state": "REUSED" if lineage else "FROZEN",
        "source_analysis_id": record["payload"]["source_analysis_id"],
        "source_evidence_sha256": record["sha256"],
        "raw_analysis_status": record["payload"]["analysis_status"],
        "raw_review_status": record["payload"]["review_status"],
        "new_semantic_inference": False if lineage else True,
        "lineage": deepcopy(lineage),
    }
