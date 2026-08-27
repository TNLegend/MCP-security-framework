from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import secrets
import threading
from typing import Any, Callable


@dataclass
class LegacyClientSession:
    session_id: str
    server_id: int
    initialized: bool
    expires_at: datetime
    protocol_version: str
    profile_id: str
    transport_kind: str


@dataclass
class LegacyUpstreamSession:
    client: Any
    expires_at: datetime
    framework_session_id: str


class LegacyClientSessionStore:
    def __init__(
        self,
        ttl_seconds: int = 900,
        max_sessions: int = 1_000,
        max_sessions_per_server: int = 200,
    ) -> None:
        self.ttl = timedelta(seconds=ttl_seconds)
        self.max_sessions = max_sessions
        self.max_sessions_per_server = max_sessions_per_server
        self._sessions: dict[str, LegacyClientSession] = {}
        self._lock = threading.RLock()

    def create(
        self,
        server_id: int,
        *,
        protocol_version: str = "2025-11-25",
        profile_id: str = "mcp-legacy-2025-11-25-restricted-v1",
        transport_kind: str = "legacy_streamable_http",
    ) -> LegacyClientSession:
        now = datetime.now(timezone.utc)
        session = LegacyClientSession(
            session_id=secrets.token_urlsafe(32),
            server_id=server_id,
            initialized=False,
            expires_at=now + self.ttl,
            protocol_version=protocol_version,
            profile_id=profile_id,
            transport_kind=transport_kind,
        )
        with self._lock:
            self._cleanup_expired_locked(now)
            if len(self._sessions) >= self.max_sessions:
                raise ValueError("legacy_protocol_session_capacity_exceeded")
            server_count = sum(
                1 for item in self._sessions.values() if item.server_id == server_id
            )
            if server_count >= self.max_sessions_per_server:
                raise ValueError("legacy_protocol_server_session_capacity_exceeded")
            self._sessions[session.session_id] = session
        return session

    def get(self, session_id: str, server_id: int) -> LegacyClientSession:
        with self._lock:
            session = self._sessions.get(session_id)
            if (
                session is None
                or session.server_id != server_id
                or session.expires_at <= datetime.now(timezone.utc)
            ):
                self._sessions.pop(session_id, None)
                raise ValueError("legacy_protocol_session_invalid")
            return session

    def mark_initialized(self, session_id: str, server_id: int) -> None:
        session = self.get(session_id, server_id)
        session.initialized = True

    def _cleanup_expired_locked(self, now: datetime) -> None:
        expired = [
            session_id
            for session_id, session in self._sessions.items()
            if session.expires_at <= now
        ]
        for session_id in expired:
            self._sessions.pop(session_id, None)


class LegacyUpstreamSessionPool:
    """Isolates stateful upstream sessions by trusted framework session and server."""

    def __init__(
        self,
        ttl_seconds: int = 900,
        max_clients: int = 1_000,
        max_clients_per_framework_session: int = 50,
    ) -> None:
        self.ttl = timedelta(seconds=ttl_seconds)
        self.max_clients = max_clients
        self.max_clients_per_framework_session = max_clients_per_framework_session
        self._clients: dict[tuple[str, int, str, str], LegacyUpstreamSession] = {}
        self._lock = threading.RLock()

    def get_or_create(
        self,
        *,
        framework_session_id: str,
        server_id: int,
        profile_id: str,
        connection_context_hash: str = "default",
        factory: Callable[[], Any],
    ) -> Any:
        key = (framework_session_id, server_id, profile_id, connection_context_hash)
        now = datetime.now(timezone.utc)
        with self._lock:
            self._cleanup_expired_locked(now)
            session = self._clients.get(key)
            if session is None:
                if len(self._clients) >= self.max_clients:
                    raise RuntimeError("legacy_upstream_session_capacity_exceeded")
                per_session_count = sum(
                    1
                    for item in self._clients.values()
                    if item.framework_session_id == framework_session_id
                )
                if per_session_count >= self.max_clients_per_framework_session:
                    raise RuntimeError(
                        "legacy_upstream_framework_session_capacity_exceeded"
                    )
                client = factory()
                self._clients[key] = LegacyUpstreamSession(
                    client=client,
                    expires_at=now + self.ttl,
                    framework_session_id=framework_session_id,
                )
                return client
            return session.client

    def close_framework_session(self, framework_session_id: str) -> int:
        with self._lock:
            keys = [
                key
                for key, session in self._clients.items()
                if session.framework_session_id == framework_session_id
            ]
            for key in keys:
                session = self._clients.pop(key)
                _close_client(session.client)
            return len(keys)

    def close_all(self) -> int:
        with self._lock:
            sessions = list(self._clients.values())
            self._clients.clear()
        for session in sessions:
            _close_client(session.client)
        return len(sessions)

    def _cleanup_expired_locked(self, now: datetime) -> None:
        expired = [
            key for key, session in self._clients.items() if session.expires_at <= now
        ]
        for key in expired:
            session = self._clients.pop(key)
            _close_client(session.client)


def _close_client(client: Any) -> None:
    close = getattr(client, "close", None)
    if callable(close):
        try:
            close()
        except Exception:
            return
