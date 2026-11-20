"""Append-only Deploy governance decisions and ADMIN exception lifecycle.

Exceptions annotate findings. They NEVER change stored CloudFinding,
signed mappings, AWS policies, or authoritative Runtime allow/deny.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from hashlib import sha256
import json
from pathlib import Path
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.cloud_security import (
    CloudDeployExceptionEvent, CloudDeployGovernanceDecision, CloudFinding,
    CloudScan,
)


class DeployHistoryError(ValueError):
    pass


def _hash(data: object) -> str:
    return sha256(json.dumps(
        data, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        default=str,
    ).encode()).hexdigest()


def local_policy_sha256() -> str:
    """Hash pinned local two-policy manifest, NOT a remote OPA attestation."""
    folder = Path(__file__).resolve().parents[3] / "policies/opa"
    manifest = json.loads((folder / "deploy_bundle_manifest.json").read_text(
        encoding="utf-8"
    ))
    pinned = manifest.get("policy_sha256")
    if (manifest.get("format") != "deploy-opa-local-bundle-v1"
            or manifest.get("policy_revision") != "opa-deploy-security-advisory-v1"
            or not isinstance(pinned, dict)
            or set(pinned) != {"deploy_security.rego", "runtime_policy.rego"}):
        raise DeployHistoryError("DEPLOY_POLICY_MANIFEST_UNSUPPORTED")
    for name, expected in pinned.items():
        if sha256((folder/name).read_bytes()).hexdigest() != expected:
            raise DeployHistoryError("DEPLOY_POLICY_MANIFEST_DRIFT")
    return _hash(manifest)


def _decision_entry(row: CloudDeployGovernanceDecision) -> str:
    return _hash({
        "id": row.id, "scan": row.scan_id, "actor": row.actor_user_id,
        "classification": row.classification, "revision": row.policy_revision,
        "local_policy_sha256": row.policy_bundle_sha256,
        "input_sha256": row.input_sha256, "output_sha256": row.output_sha256,
        "result": row.result, "previous": row.previous_entry_sha256,
        "created_at": row.created_at.isoformat(),
    })


def record_deploy_decision(db: Session, scan_id: str, actor_id: str,
                           source: dict, decision: dict):
    # Serialize concurrent evaluations of the same scan.
    scan = db.scalar(select(CloudScan).where(
        CloudScan.id == scan_id).with_for_update())
    if scan is None:
        raise DeployHistoryError("DEPLOY_SCAN_NOT_FOUND")
    prior = db.scalar(select(CloudDeployGovernanceDecision).where(
        CloudDeployGovernanceDecision.scan_id == scan_id
    ).order_by(CloudDeployGovernanceDecision.created_at.desc(),
               CloudDeployGovernanceDecision.id.desc()).limit(1))
    if prior and prior.entry_sha256 != _decision_entry(prior):
        raise DeployHistoryError("DEPLOY_DECISION_CHAIN_INVALID")
    now = datetime.utcnow()
    row = CloudDeployGovernanceDecision(
        id=str(uuid4()), scan_id=scan_id, actor_user_id=actor_id,
        classification=decision["classification"],
        policy_revision=decision["policy_revision"],
        policy_bundle_sha256=local_policy_sha256(),
        input_sha256=_hash(source), output_sha256=_hash(decision),
        result=decision, previous_entry_sha256=prior.entry_sha256 if prior else None,
        created_at=now,
        entry_sha256="0" * 64,
    )
    row.entry_sha256 = _decision_entry(row)
    db.add(row)
    db.flush()
    return row


def list_deploy_decisions(db: Session, scan_id: str) -> list[dict]:
    rows = db.scalars(select(CloudDeployGovernanceDecision).where(
        CloudDeployGovernanceDecision.scan_id == scan_id
    ).order_by(CloudDeployGovernanceDecision.created_at,
               CloudDeployGovernanceDecision.id).limit(1001)).all()
    if len(rows) > 1000:
        raise DeployHistoryError("DEPLOY_DECISION_HISTORY_LIMIT")
    output = []
    previous = None
    for row in rows:
        if (row.previous_entry_sha256 != previous
                or row.entry_sha256 != _decision_entry(row)
                or row.input_sha256 is None
                or row.output_sha256 != _hash(row.result)):
            raise DeployHistoryError("DEPLOY_DECISION_CHAIN_INVALID")
        previous = row.entry_sha256
        output.append({
            "id": row.id, "scan_id": row.scan_id,
            "created_at": row.created_at.isoformat(),
            "classification": row.classification,
            "policy_revision": row.policy_revision,
            "local_policy_sha256": row.policy_bundle_sha256,
            "input_sha256": row.input_sha256,
            "output_sha256": row.output_sha256,
            "entry_sha256": row.entry_sha256,
            "result": row.result,
        })
    return output


def _exception_entry(row: CloudDeployExceptionEvent) -> str:
    return _hash({
        "id": row.id, "exception": row.exception_id,
        "scan": row.scan_id, "finding": row.finding_id, "actor": row.actor_user_id,
        "operation": row.operation, "reason": row.reason,
        "expires_at": row.expires_at.isoformat() if row.expires_at else None,
        "previous": row.previous_entry_sha256,
        "created_at": row.created_at.isoformat(),
    })


def _load_exception_events(db: Session, scan_id: str, exception_id: str | None = None):
    query = select(CloudDeployExceptionEvent).where(
        CloudDeployExceptionEvent.scan_id == scan_id)
    if exception_id is not None:
        query = query.where(CloudDeployExceptionEvent.exception_id == exception_id)
    rows = db.scalars(query.order_by(
        CloudDeployExceptionEvent.created_at,
        CloudDeployExceptionEvent.id).limit(1001)).all()
    if len(rows) > 1000:
        raise DeployHistoryError("DEPLOY_EXCEPTION_HISTORY_LIMIT")
    return rows


def _verify_exception_trace(rows: list[CloudDeployExceptionEvent]):
    streams: dict[str, str | None] = {}
    for row in rows:
        expected_previous = streams.get(row.exception_id)
        if (row.previous_entry_sha256 != expected_previous
                or row.entry_sha256 != _exception_entry(row)):
            raise DeployHistoryError("DEPLOY_EXCEPTION_CHAIN_INVALID")
        streams[row.exception_id] = row.entry_sha256


def _exception_state(rows: list[CloudDeployExceptionEvent]) -> str:
    if not rows:
        return "NONE"
    latest = rows[-1]
    if latest.operation == "APPROVE" and latest.expires_at and latest.expires_at <= datetime.utcnow():
        return "EXPIRED"
    return {"REQUEST": "REQUESTED", "APPROVE": "APPROVED",
            "REJECT": "REJECTED", "REVOKE": "REVOKED"}[latest.operation]


def record_exception_event(
    db: Session, scan_id: str, actor_id: str, operation: str,
    reason: str, *, exception_id: str | None = None,
    finding_id: str | None = None, expires_days: int | None = None,
) -> dict:
    if operation not in {"REQUEST", "APPROVE", "REJECT", "REVOKE"}:
        raise DeployHistoryError("DEPLOY_EXCEPTION_OPERATION_INVALID")
    if not isinstance(reason, str) or not 20 <= len(reason.strip()) <= 1000:
        raise DeployHistoryError("DEPLOY_EXCEPTION_REASON_REQUIRED")
    scan = db.scalar(select(CloudScan).where(
        CloudScan.id == scan_id).with_for_update())
    if scan is None or scan.status not in ("PARTIAL", "COMPLETED"):
        raise DeployHistoryError("DEPLOY_EXCEPTION_SCAN_NOT_FINAL")
    now = datetime.utcnow()
    if operation == "REQUEST":
        if exception_id is not None or not finding_id or expires_days is not None:
            raise DeployHistoryError("DEPLOY_EXCEPTION_REQUEST_INVALID")
        finding = db.get(CloudFinding, finding_id)
        if not finding or finding.scan_id != scan_id:
            raise DeployHistoryError("DEPLOY_EXCEPTION_FINDING_NOT_IN_SCAN")
        exception_id = str(uuid4())
        events = []
    else:
        if not exception_id or finding_id is not None:
            raise DeployHistoryError("DEPLOY_EXCEPTION_ID_REQUIRED")
        events = _load_exception_events(db, scan_id, exception_id)
        _verify_exception_trace(events)
        if not events:
            raise DeployHistoryError("DEPLOY_EXCEPTION_NOT_FOUND")
        finding_id = events[0].finding_id
        state = _exception_state(events)
        if operation in {"APPROVE", "REJECT"} and state != "REQUESTED":
            raise DeployHistoryError("DEPLOY_EXCEPTION_NOT_PENDING")
        if operation == "REVOKE" and state not in ("APPROVED", "EXPIRED"):
            raise DeployHistoryError("DEPLOY_EXCEPTION_NOT_APPROVED")
    if operation == "APPROVE":
        if not isinstance(expires_days, int) or not 1 <= expires_days <= 90:
            raise DeployHistoryError("DEPLOY_EXCEPTION_EXPIRY_REQUIRED")
        expires_at = now + timedelta(days=expires_days)
    else:
        if expires_days is not None:
            raise DeployHistoryError("DEPLOY_EXCEPTION_EXPIRY_NOT_ALLOWED")
        expires_at = None
    event = CloudDeployExceptionEvent(
        id=str(uuid4()), exception_id=exception_id,
        scan_id=scan_id, finding_id=finding_id, actor_user_id=actor_id,
        operation=operation, reason=reason.strip(),
        expires_at=expires_at,
        previous_entry_sha256=events[-1].entry_sha256 if events else None,
        entry_sha256="0" * 64, created_at=now,
    )
    event.entry_sha256 = _exception_entry(event)
    db.add(event)
    db.flush()
    return {
        "exception_id": event.exception_id, "event_id": event.id,
        "scan_id": scan_id, "finding_id": finding_id,
        "operation": event.operation,
        "state": _exception_state([event]),
        "expires_at": expires_at.isoformat() if expires_at else None,
        "entry_sha256": event.entry_sha256,
    }


def list_exception_history(db: Session, scan_id: str) -> list[dict]:
    rows = _load_exception_events(db, scan_id)
    _verify_exception_trace(rows)
    by_exception: dict[str, list] = {}
    for event in rows:
        by_exception.setdefault(event.exception_id, []).append(event)
    output = []
    for exception_id, events in by_exception.items():
        latest = events[-1]
        output.append({
            "exception_id": exception_id,
            "finding_id": latest.finding_id,
            "state": _exception_state(events),
            "expires_at": latest.expires_at.isoformat() if latest.expires_at else None,
            "events": [{
                "id": event.id, "operation": event.operation,
                "reason": event.reason, "created_at": event.created_at.isoformat(),
                "expires_at": event.expires_at.isoformat() if event.expires_at else None,
                "entry_sha256": event.entry_sha256,
            } for event in events],
        })
    return output
