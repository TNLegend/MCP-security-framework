"""F11: ordered, durable MCP discovery generations for the admin API.

The reservation commits *before* external discovery. Publication must be in
one transaction with inventory import. Only PostgreSQL is authoritative:
non-PG sessions are explicitly unsupported for this distributed guarantee.

All publication paths (admin and signed import) must use the same
PostgreSQL generation fence. Background recovery never replays an untrusted
remote operation or publishes a cached response by itself.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from hashlib import sha256
import json
import re
from typing import Callable, TypeVar

from sqlalchemy import func, select, text
from sqlalchemy.orm import aliased
from sqlalchemy.orm import Session

from app.models.discovery_generation import MCPDiscoveryGeneration, MCPDiscoveryHead


DISCOVERY_GENERATION_LOCK_KEY = 807018009
# PostgreSQL two-integer advisory locks occupy a separate namespace from
# the single-bigint global maintenance gate. Scope hash collisions only
# serialize otherwise independent catalogs, never broaden authority.
DISCOVERY_GENERATION_SCOPE_NAMESPACE = 807018010
MAX_GENERATION_AGE = timedelta(minutes=30)
T = TypeVar("T")


class DiscoveryGenerationError(RuntimeError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def discovery_context_digest(
    *, auth_mode: str, credential_ref: str | None,
    protocol_version: str | None, profile_id: str | None,
    oauth_config: dict | None = None,
    credential_material_hash: str | None = None,
) -> str:
    """Fingerprint trusted discovery configuration, never persist secrets.

    The digest includes a reviewed OAuth config snapshot when available,
    but credentials stored outside the database require a versioned
    credential authority for guaranteed rotation detection (still F13).
    """
    payload = {
        "auth_mode": auth_mode, "credential_ref": credential_ref,
        "protocol_version": protocol_version, "profile_id": profile_id,
        "oauth_config": oauth_config,
        "credential_material_hash": credential_material_hash,
    }
    try:
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True, allow_nan=False).encode("utf-8")
    except (ValueError, TypeError) as exc:
        raise DiscoveryGenerationError("discovery_context_invalid") from exc
    return sha256(encoded).hexdigest()


def trusted_discovery_context_digest(
    *, auth_mode: str, credential_ref: str | None,
    protocol_version: str | None, profile_id: str | None,
    oauth_config: dict | None = None,
) -> str:
    """Bind BEARER discovery to its *actual* secret version, not only its ref.

    Reading from the trusted local credential store is required both at
    reservation and publication. Only a digest of its bearer material is
    incorporated into the persisted context hash; tokens are never placed
    in the generation table or logged. For OAuth, the stable connection
    generation is carried by the reviewed oauth_config rather than the
    refreshable access token. Cross-host replicas without shared versioned
    credentials must not claim coherent authorization.
    """
    from common.upstream_auth import (
        AUTH_MODE_BEARER, UpstreamAuthError, read_upstream_secret,
        validate_upstream_auth_config,
    )

    try:
        mode, reference = validate_upstream_auth_config(
            auth_mode, credential_ref
        )
        material_hash = None
        if mode == AUTH_MODE_BEARER:
            assert reference is not None
            token = read_upstream_secret(reference, token_only=True)
            material_hash = sha256(token.encode("utf-8")).hexdigest()
    except UpstreamAuthError as exc:
        raise DiscoveryGenerationError(
            "discovery_credential_version_unavailable"
        ) from exc
    return discovery_context_digest(
        auth_mode=mode, credential_ref=reference,
        protocol_version=protocol_version, profile_id=profile_id,
        oauth_config=oauth_config, credential_material_hash=material_hash,
    )


def discovery_scope_key(*, transport: str, endpoint: str) -> str:
    if not transport or not endpoint:
        raise DiscoveryGenerationError("discovery_scope_invalid")
    return sha256(f"{transport}\x00{endpoint}".encode("utf-8")).hexdigest()


def _lock_generation_authority(db: Session, *, scope_key: str | None = None, wait: bool = True) -> None:
    """Single global maintenance fence, plus a transaction-scoped catalog lock.

    All scoped writers take a SHARED lock on the maintenance gate and then
    an exclusive two-int lock for their exact catalog scope. Maintenance
    (recovery/pruning across scopes) takes the EXCLUSIVE global gate.
    This preserves cleanup/publication ordering, without making catalog A's
    slow Analyzer block unrelated catalog B's publication.
    Lock order is ALWAYS global gate, then scope; never reverse it.
    """
    if db.get_bind().dialect.name != "postgresql":
        raise DiscoveryGenerationError("discovery_postgresql_required")
    if scope_key is None:
        db.execute(
            text("SELECT pg_advisory_xact_lock(:k)"),
            {"k": DISCOVERY_GENERATION_LOCK_KEY},
        )
        return
    if not isinstance(scope_key, str) or not re.fullmatch(r"[0-9a-f]{64}", scope_key):
        raise DiscoveryGenerationError("discovery_scope_invalid")
    if wait:
        db.execute(text("SELECT pg_advisory_xact_lock_shared(:k)"),
                   {"k": DISCOVERY_GENERATION_LOCK_KEY})
    elif not db.scalar(text("SELECT pg_try_advisory_xact_lock_shared(:k)"),
                       {"k": DISCOVERY_GENERATION_LOCK_KEY}):
        raise DiscoveryGenerationError("catalog_busy_retry_transaction")
    # Collision here can only reduce parallelism. Scope identity remains
    # authoritative in the locked database rows and generation/context CAS.
    hash32 = int.from_bytes(bytes.fromhex(scope_key)[:4], "big", signed=True)
    params = {"namespace": DISCOVERY_GENERATION_SCOPE_NAMESPACE, "scope": hash32}
    if wait:
        db.execute(text("SELECT pg_advisory_xact_lock(:namespace, :scope)"), params)
    elif not db.scalar(text("SELECT pg_try_advisory_xact_lock(:namespace, :scope)"), params):
        raise DiscoveryGenerationError("catalog_busy_retry_transaction")




def higher_authority_lock_held(db: Session) -> bool:
    """Read actual PG locks, including callers using the lock without RLock."""
    if db.get_bind().dialect.name != "postgresql":
        return False
    return bool(db.scalar(text("""
        SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=pg_backend_pid()
          AND locktype='advisory' AND granted AND objsubid=1
          AND classid=0 AND objid IN (807018002,807018003))
    """)))


def lock_review_catalog_scope(db: Session, *, tool_id: int) -> None:
    """Serialize a human review with F11 publication of THIS catalog.

    Ordering: F11 maintenance shared -> catalog scope exclusive -> Runtime
    dispatch advisory authority. F11 import already owns the catalog lock
    before touching mutable tool/observation rows and later acquires the
    Runtime authority when analysis is persisted. A review that grabs Runtime
    first can otherwise deadlock against this publication's tool row lock.

    Do NOT take the global Runtime lock while waiting on a slow catalog:
    unrelated existing MCP dispatches must remain responsive. This helper
    intentionally does nothing for SQLite-only standalone unit fixtures;
    actual durable cross-worker ordering is supported on PostgreSQL.
    """
    if db.get_bind().dialect.name != "postgresql":
        return
    from app.models.mcp_server import MCPServer
    from app.models.mcp_tool import MCPTool

    def tool_scope():
        return db.execute(
            select(MCPServer.transport, MCPServer.endpoint)
            .select_from(MCPTool)
            .join(MCPServer, MCPServer.id == MCPTool.server_id)
            .where(MCPTool.id == tool_id)
        ).one_or_none()

    scope = tool_scope()
    if scope is None:
        raise ValueError("tool_review_tool_missing")
    key = discovery_scope_key(transport=scope.transport, endpoint=scope.endpoint)
    _lock_generation_authority(db, scope_key=key, wait=not higher_authority_lock_held(db))
    refreshed = tool_scope()
    if (
        refreshed is None
        or discovery_scope_key(
            transport=refreshed.transport, endpoint=refreshed.endpoint,
        ) != key
    ):
        raise DiscoveryGenerationError("discovery_review_catalog_scope_changed")



def reserve_discovery_generation(
    db: Session, *, transport: str, endpoint: str,
    context_hash: str | None = None,
) -> MCPDiscoveryGeneration:
    """Call db.commit immediately after return, before contacting upstream."""
    scope = discovery_scope_key(transport=transport, endpoint=endpoint)
    if context_hash is not None and not re.fullmatch(r"[0-9a-f]{64}", context_hash):
        raise DiscoveryGenerationError("discovery_context_invalid")
    _lock_generation_authority(db, scope_key=scope)
    head = db.scalar(
        select(MCPDiscoveryHead)
        .where(MCPDiscoveryHead.scope_key == scope)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if head is None:
        head = MCPDiscoveryHead(scope_key=scope, latest_generation=0)
        db.add(head)
        db.flush()
    else:
        for previous in db.scalars(
            select(MCPDiscoveryGeneration).where(
                MCPDiscoveryGeneration.scope_key == scope,
                MCPDiscoveryGeneration.status == "RUNNING",
            )
        ).all():
            previous.status = "SUPERSEDED"
            previous.completed_at = datetime.utcnow()
    head.latest_generation += 1
    head.updated_at = datetime.utcnow()
    run = MCPDiscoveryGeneration(
        scope_key=scope, generation=head.latest_generation,
        context_hash=context_hash, status="RUNNING"
    )
    db.add(run)
    db.flush()
    return run


def publish_discovery_generation(
    db: Session, *, generation_id: str, expected_scope_key: str,
    import_callback: Callable[[], T],
    expected_context_hash: str | None = None,
    validate_before_publish: Callable[[], None] | None = None,
) -> T:
    """Import and mark PUBLISHED in the caller's *single* DB transaction.

    No inventory writes happen if the reservation has been superseded.
    Caller must commit once after any associated audit is recorded.
    """
    # A read-only scope lookup precedes the scoped advisory lock; a
    # concurrent prune must take the exclusive maintenance gate. Re-read
    # under the scope lock and revalidate all generation/context predicates.
    scope = db.scalar(
        select(MCPDiscoveryGeneration.scope_key)
        .where(MCPDiscoveryGeneration.id == generation_id)
    )
    if scope is None:
        raise DiscoveryGenerationError("discovery_generation_unknown")
    _lock_generation_authority(db, scope_key=scope)
    run = db.scalar(
        select(MCPDiscoveryGeneration)
        .where(MCPDiscoveryGeneration.id == generation_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if run is None:
        raise DiscoveryGenerationError("discovery_generation_unknown")
    if run.scope_key != scope:
        raise DiscoveryGenerationError("discovery_generation_scope_mismatch")
    head = db.scalar(
        select(MCPDiscoveryHead)
        .where(MCPDiscoveryHead.scope_key == run.scope_key)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if run.scope_key != expected_scope_key:
        raise DiscoveryGenerationError("discovery_generation_scope_mismatch")
    if run.context_hash != expected_context_hash:
        raise DiscoveryGenerationError("discovery_context_changed")
    if run.status == "RUNNING" and datetime.utcnow() - run.started_at > MAX_GENERATION_AGE:
        raise DiscoveryGenerationError("discovery_generation_expired")
    if (
        head is None or run.status != "RUNNING"
        or head.latest_generation != run.generation
    ):
        raise DiscoveryGenerationError("discovery_generation_superseded")
    result = import_callback()
    # Inventory import or Analyzer may take seconds. Recheck the current
    # credential/policy context just before marking the same SQL transaction
    # PUBLISHED. A changed credential must roll back imported tools as well.
    if validate_before_publish is not None:
        validate_before_publish()
    run.status = "PUBLISHED"
    run.completed_at = datetime.utcnow()
    db.flush()
    return result




def get_discovery_generation_status(
    db: Session, *, generation_id: str,
) -> dict[str, str | int | bool]:
    """Read only the *committed* lifecycle status after uncertain HTTP I/O.

    This does not renew leases, retry remote discovery, mark a generation
    published or authorize import. Avoid returning context hashes, scope
    identifiers or credential details to an internal client.
    """
    from uuid import UUID

    try:
        normalized = str(UUID(generation_id))
    except (ValueError, TypeError, AttributeError) as exc:
        raise DiscoveryGenerationError("discovery_generation_id_invalid") from exc
    if db.get_bind().dialect.name != "postgresql":
        raise DiscoveryGenerationError("discovery_postgresql_required")
    record = db.scalar(
        select(MCPDiscoveryGeneration)
        .where(MCPDiscoveryGeneration.id == normalized)
    )
    if record is None:
        raise DiscoveryGenerationError("discovery_generation_unknown")
    return {
        "generation_id": record.id,
        "generation": record.generation,
        "status": record.status,
        "terminal": record.status in ("FAILED", "SUPERSEDED", "PUBLISHED"),
        # A PUBLISHED status means commit succeeded, but not that replay is
        # safe; all follow-up imports require a new reservation.
        "may_retry_import": False,
    }


def recover_expired_discovery_generations(
    db: Session, *, scope_key: str | None = None,
    max_recover: int = 100, now: datetime | None = None,
) -> int:
    """Turn expired RUNNING jobs into durable FAILED without replaying MCP.

    Requires the SAME PostgreSQL transaction advisory lock as reserve/publish.
    Caller must commit. No remote calls, no inventory mutation, and no
    reactivation of an older generation. A newer reserve creates a fresh run.
    """
    if not isinstance(max_recover, int) or isinstance(max_recover, bool) or not 1 <= max_recover <= 1000:
        raise DiscoveryGenerationError("discovery_recovery_limit_invalid")
    _lock_generation_authority(db)
    checked_at = now or datetime.utcnow()
    query = (
        select(MCPDiscoveryGeneration)
        .where(
            MCPDiscoveryGeneration.status == "RUNNING",
            MCPDiscoveryGeneration.started_at <= checked_at - MAX_GENERATION_AGE,
        )
        .order_by(MCPDiscoveryGeneration.started_at, MCPDiscoveryGeneration.id)
        .limit(max_recover)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if scope_key is not None:
        query = query.where(MCPDiscoveryGeneration.scope_key == scope_key)
    orphaned = db.scalars(query).all()
    for run in orphaned:
        run.status = "FAILED"
        run.error_code = "discovery_worker_lease_expired"
        run.completed_at = checked_at
    db.flush()
    return len(orphaned)


def prune_terminal_discovery_generations(
    db: Session, *, older_than: datetime,
    scope_key: str | None = None, max_delete: int = 100,
) -> int:
    """Bounded retention under the publication fence; never reuse counters.

    Preserve the newest reservation of every scope and the newest PUBLISHED
    generation for audit/recovery. Earlier completed rows older than the
    retention threshold are eligible. No head is deleted.
    """
    if not isinstance(max_delete, int) or isinstance(max_delete, bool) or not 1 <= max_delete <= 1000:
        raise DiscoveryGenerationError("discovery_retention_limit_invalid")
    _lock_generation_authority(db)
    latest_published = aliased(MCPDiscoveryGeneration)
    published_number = (
        select(func.max(latest_published.generation))
        .where(
            latest_published.scope_key == MCPDiscoveryGeneration.scope_key,
            latest_published.status == "PUBLISHED",
        )
        .correlate(MCPDiscoveryGeneration)
        .scalar_subquery()
    )
    candidates = (
        select(MCPDiscoveryGeneration)
        .join(
            MCPDiscoveryHead,
            MCPDiscoveryHead.scope_key == MCPDiscoveryGeneration.scope_key,
        )
        .where(
            MCPDiscoveryGeneration.status.in_(("FAILED", "SUPERSEDED", "PUBLISHED")),
            MCPDiscoveryGeneration.completed_at < older_than,
            MCPDiscoveryGeneration.generation != MCPDiscoveryHead.latest_generation,
            MCPDiscoveryGeneration.generation != func.coalesce(published_number, -1),
        )
        .order_by(MCPDiscoveryGeneration.completed_at, MCPDiscoveryGeneration.id)
        .limit(max_delete)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if scope_key is not None:
        candidates = candidates.where(MCPDiscoveryGeneration.scope_key == scope_key)
    to_remove = db.scalars(candidates).all()
    for run in to_remove:
        db.delete(run)
    db.flush()
    return len(to_remove)

def fail_discovery_generation(
    db: Session, *, generation_id: str, error_code: str,
) -> None:
    """Idempotent terminal failure, preserving superseding generations."""
    # A read-only scope lookup precedes the scoped advisory lock; a
    # concurrent prune must take the exclusive maintenance gate. Re-read
    # under the scope lock and revalidate all generation/context predicates.
    scope = db.scalar(
        select(MCPDiscoveryGeneration.scope_key)
        .where(MCPDiscoveryGeneration.id == generation_id)
    )
    if scope is None:
        raise DiscoveryGenerationError("discovery_generation_unknown")
    _lock_generation_authority(db, scope_key=scope)
    run = db.scalar(
        select(MCPDiscoveryGeneration)
        .where(MCPDiscoveryGeneration.id == generation_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if run is None:
        raise DiscoveryGenerationError("discovery_generation_unknown")
    if run.status == "RUNNING":
        run.status = "FAILED"
        run.error_code = error_code[:128]
        run.completed_at = datetime.utcnow()
    db.flush()
