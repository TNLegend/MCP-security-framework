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


class LegacyClientSessionStore:
    def __init__(self, ttl_seconds: int = 900) -> None:
        self.ttl = timedelta(seconds=ttl_seconds)
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


class LegacyUpstreamSessionPool:
    """Isolates stateful upstream sessions by trusted framework session and server."""

    def __init__(self) -> None:
        self._clients: dict[tuple[str, int, str, str], Any] = {}
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
        with self._lock:
            client = self._clients.get(key)
            if client is None:
                client = factory()
                self._clients[key] = client
            return client
