"""Opt-in F11 PostgreSQL discovery generation reconciler.

Default invocation is READ ONLY. Destructive maintenance requires an explicit
exact database-name guard and confirmation, including during QA. Never
contacts an MCP, retries tools/call, or changes published inventory.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta
from pathlib import Path

from sqlalchemy import func, select, text

ROOT = Path(__file__).resolve().parents[1]
for candidate in (ROOT, ROOT / "backend"):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

from app.db.database import SessionLocal  # noqa: E402
from app.models.discovery_generation import MCPDiscoveryGeneration  # noqa: E402
from app.services.discovery_generation import (  # noqa: E402
    MAX_GENERATION_AGE,
    prune_terminal_discovery_generations,
    recover_expired_discovery_generations,
)


def reconcile(*, apply: bool, expected_database: str | None = None,
              confirm_apply: bool = False, scope_key: str | None = None,
              max_batch: int = 100, retain_days: int = 30) -> dict:
    if (
        not isinstance(max_batch, int) or isinstance(max_batch, bool)
        or not 1 <= max_batch <= 1000
        or not isinstance(retain_days, int) or isinstance(retain_days, bool)
        or not 7 <= retain_days <= 365
        or (
            scope_key is not None and (
                len(scope_key) != 64
                or any(char not in "0123456789abcdef" for char in scope_key)
            )
        )
    ):
        raise ValueError("discovery_maintenance_argument_invalid")
    if apply and (not confirm_apply or not expected_database):
        raise ValueError("discovery_maintenance_confirmation_required")
    with SessionLocal() as db:
        if db.get_bind().dialect.name != "postgresql":
            raise RuntimeError("discovery_postgresql_required")
        actual = db.scalar(text("SELECT current_database()"))
        if expected_database is not None and actual != expected_database:
            raise RuntimeError("discovery_database_name_mismatch")
        if not apply:
            query = select(func.count(MCPDiscoveryGeneration.id)).where(
                MCPDiscoveryGeneration.status == "RUNNING",
                MCPDiscoveryGeneration.started_at
                <= datetime.utcnow() - MAX_GENERATION_AGE,
            )
            if scope_key:
                query = query.where(MCPDiscoveryGeneration.scope_key == scope_key)
            pending = db.scalar(query)
            db.rollback()
            return {
                "mode": "preview", "database": actual,
                "expired_running_candidates": int(pending or 0),
                "note": "No mutations. Retention eligibility is evaluated only under apply lock.",
            }
        expired = recover_expired_discovery_generations(
            db, scope_key=scope_key, max_recover=max_batch,
        )
        pruned = prune_terminal_discovery_generations(
            db, scope_key=scope_key, max_delete=max_batch,
            older_than=datetime.utcnow() - timedelta(days=retain_days),
        )
        db.commit()
        return {
            "mode": "applied", "database": actual,
            "failed_expired_generations": expired,
            "deleted_historical_terminal_generations": pruned,
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="Mutate only after explicit confirmation")
    parser.add_argument("--confirm-apply", action="store_true")
    parser.add_argument("--expected-db", help="Exact PostgreSQL database name guard")
    parser.add_argument("--scope-key", help="Optional SHA-256 scope identifier")
    parser.add_argument("--max-batch", type=int, default=100)
    parser.add_argument("--retain-days", type=int, default=30)
    options = parser.parse_args(argv)
    try:
        result = reconcile(
            apply=options.apply,
            expected_database=options.expected_db,
            confirm_apply=options.confirm_apply,
            scope_key=options.scope_key,
            max_batch=options.max_batch,
            retain_days=options.retain_days,
        )
    except (ValueError, RuntimeError) as exc:
        print("discovery maintenance refused: " + str(exc), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
