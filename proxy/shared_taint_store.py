"""Durable same-host Result Guard taint state for cooperating proxy workers.

The storage contains only SHA-256 fingerprints and SHA-256 session IDs, never
upstream tool result bodies, credentials or agent-supplied session names.

Only a shared *trusted local volume* is supported. This is NOT a claim of
cross-host coherence or atomicity with a separate MCP dispatch admission.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sqlite3
from time import sleep, time
from typing import Callable


class SharedTaintStoreError(RuntimeError):
    pass


class SharedTaintSQLiteStore:
    def __init__(
        self,
        path: str | Path,
        *,
        clock: Callable[[], float] = time,
        ttl_seconds: int = 900,
        max_sessions: int = 1024,
        max_fingerprints: int = 2048,
    ) -> None:
        self.path = Path(path)
        if (
            not self.path.is_absolute()
            or self.path.is_symlink()
            or self.path.parent.is_symlink()
            or not self.path.parent.is_dir()
            or not (1 <= ttl_seconds <= 86400)
            or not (1 <= max_sessions <= 100000)
            or not (1 <= max_fingerprints <= 8192)
        ):
            raise SharedTaintStoreError("taint_store_configuration_invalid")
        self.clock = clock
        self.ttl_seconds = ttl_seconds
        self.max_sessions = max_sessions
        self.max_fingerprints = max_fingerprints
        # WAL mode is a persistent *database-level* setting. Setting it on
        # every new connection races with other readers/writers, including
        # concurrent worker startup, and can fail with SQLITE_BUSY despite
        # SQLite's ordinary write-transaction busy timeout.
        # Configure it once at initialization with a bounded retry; normal
        # read/write connections must never attempt to change journal mode.
        for attempt in range(5):
            db = None
            try:
                db = self._connect()
                mode = db.execute("PRAGMA journal_mode").fetchone()
                if not mode:
                    raise SharedTaintStoreError("taint_store_journal_mode_missing")
                if str(mode[0]).lower() != "wal":
                    changed = db.execute("PRAGMA journal_mode=WAL").fetchone()
                    if not changed or str(changed[0]).lower() != "wal":
                        raise SharedTaintStoreError("taint_store_wal_required")
                db.execute("""
                    CREATE TABLE IF NOT EXISTS session_taint (
                      session_sha256 TEXT PRIMARY KEY,
                      expires_at REAL NOT NULL,
                      fingerprints TEXT NOT NULL,
                      incomplete INTEGER NOT NULL
                    )""")
                db.execute("""
                    CREATE TABLE IF NOT EXISTS taint_watermark (
                      singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                      unknown_until REAL NOT NULL
                    )""")
                db.execute("INSERT OR IGNORE INTO taint_watermark VALUES (1, 0)")
                break
            except sqlite3.OperationalError as exc:
                if (
                    attempt == 4
                    or not any(word in str(exc).lower() for word in ("locked", "busy"))
                ):
                    raise SharedTaintStoreError("taint_store_unavailable") from exc
                sleep(0.02 * (attempt + 1))
            except (sqlite3.Error, OSError) as exc:
                raise SharedTaintStoreError("taint_store_unavailable") from exc
            finally:
                if db is not None:
                    db.close()

    def _connect(self) -> sqlite3.Connection:
        # A configured store must reside in a trusted local directory. Reject
        # replacement with an obvious symlink; active hostile local filesystem
        # attacks require OS ACLs and are outside the SQLite-level guarantee.
        if self.path.is_symlink() or self.path.parent.is_symlink():
            raise SharedTaintStoreError("taint_store_path_untrusted")
        try:
            db = sqlite3.connect(str(self.path), timeout=5.0, isolation_level=None)
            try:
                db.execute("PRAGMA busy_timeout=5000")
                db.execute("PRAGMA synchronous=FULL")
                return db
            except BaseException:
                db.close()
                raise
        except (sqlite3.Error, OSError) as exc:
            raise SharedTaintStoreError("taint_store_unavailable") from exc

    @staticmethod
    def _session_key(reference: str) -> str:
        return hashlib.sha256(reference.encode("utf-8")).hexdigest()

    @staticmethod
    def _valid_hashes(fingerprints: frozenset[str]) -> bool:
        return all(
            isinstance(value, str)
            and len(value) == 64
            and all(c in "0123456789abcdef" for c in value)
            for value in fingerprints
        )

    def _prune(self, db: sqlite3.Connection, now: float) -> None:
        db.execute("DELETE FROM session_taint WHERE expires_at <= ?", (now,))
        db.execute(
            "UPDATE taint_watermark SET unknown_until=0 "
            "WHERE singleton=1 AND unknown_until <= ?", (now,)
        )

    def merge(
        self, session_reference: str, fingerprints: frozenset[str], complete: bool
    ) -> None:
        if not session_reference or (not fingerprints and complete):
            return
        if not self._valid_hashes(fingerprints):
            raise SharedTaintStoreError("taint_store_invalid_fingerprints")
        now = float(self.clock())
        sid = self._session_key(session_reference)
        try:
            db = self._connect()
            try:
                db.execute("BEGIN IMMEDIATE")
                self._prune(db, now)
                old = db.execute(
                    "SELECT expires_at, fingerprints, incomplete FROM session_taint "
                    "WHERE session_sha256=?", (sid,)
                ).fetchone()
                merged = set(fingerprints)
                if old:
                    merged.update(json.loads(old[1]))
                incomplete = not complete or bool(old and old[2])
                if len(merged) > self.max_fingerprints:
                    incomplete = True
                bounded = sorted(merged)[: self.max_fingerprints]
                db.execute(
                    "INSERT OR REPLACE INTO session_taint "
                    "(session_sha256, expires_at, fingerprints, incomplete) "
                    "VALUES (?, ?, ?, ?)",
                    (sid, now + self.ttl_seconds,
                     json.dumps(bounded, separators=(",", ":")), int(incomplete))
                )
                count = db.execute("SELECT COUNT(*) FROM session_taint").fetchone()[0]
                if count > self.max_sessions:
                    victims = db.execute(
                        "SELECT session_sha256, expires_at FROM session_taint "
                        "ORDER BY expires_at ASC, session_sha256 ASC LIMIT ?",
                        (count - self.max_sessions,)
                    ).fetchall()
                    unknown_until = max(expires for _, expires in victims)
                    db.executemany(
                        "DELETE FROM session_taint WHERE session_sha256=?",
                        ((victim,) for victim, _ in victims)
                    )
                    db.execute(
                        "UPDATE taint_watermark "
                        "SET unknown_until=MAX(unknown_until, ?) "
                        "WHERE singleton=1", (unknown_until,)
                    )
                db.commit()
            except Exception:
                db.rollback()
                raise
            finally:
                db.close()
        except (sqlite3.Error, OSError, ValueError, TypeError) as exc:
            raise SharedTaintStoreError("taint_store_write_failed") from exc

    def read(
        self, session_reference: str
    ) -> tuple[frozenset[str], bool, bool]:
        now = float(self.clock())
        sid = self._session_key(session_reference)
        try:
            db = self._connect()
            try:
                db.execute("BEGIN IMMEDIATE")
                self._prune(db, now)
                watermark = db.execute(
                    "SELECT unknown_until FROM taint_watermark WHERE singleton=1"
                ).fetchone()
                if watermark is None:
                    raise SharedTaintStoreError("taint_store_state_missing")
                entry = db.execute(
                    "SELECT fingerprints, incomplete FROM session_taint "
                    "WHERE session_sha256=?", (sid,)
                ).fetchone()
                db.commit()
            except Exception:
                db.rollback()
                raise
            finally:
                db.close()
            if entry is None:
                return frozenset(), False, watermark[0] > now
            hashes = json.loads(entry[0])
            if (
                not isinstance(hashes, list)
                or len(hashes) > self.max_fingerprints
                or not self._valid_hashes(frozenset(hashes))
            ):
                raise SharedTaintStoreError("taint_store_corrupt")
            return frozenset(hashes), bool(entry[1]), watermark[0] > now
        except (sqlite3.Error, OSError, ValueError, TypeError) as exc:
            raise SharedTaintStoreError("taint_store_read_failed") from exc
