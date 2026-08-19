from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable
from urllib.parse import urlparse


class MCPOriginError(Exception):
    """Raised when an inbound MCP HTTP Origin is malformed or untrusted."""


@dataclass(frozen=True)
class NormalizedOrigin:
    scheme: str
    host: str
    port: int


class MCPOriginValidator:
    def __init__(self, allowed_origins: Iterable[str] = ()) -> None:
        self._allowed = frozenset(
            _parse_origin(value, allow_trailing_slash=True)
            for value in allowed_origins
            if value and value.strip()
        )

    @classmethod
    def from_csv(cls, allowed_origins: str | None) -> "MCPOriginValidator":
        if not allowed_origins:
            return cls(())
        return cls(part.strip() for part in allowed_origins.split(","))

    def validate_headers(self, headers: dict[str, str]) -> None:
        origin = headers.get("origin")
        if origin is None:
            return
        normalized = _parse_origin(origin, allow_trailing_slash=False)
        if normalized not in self._allowed:
            raise MCPOriginError("mcp_origin_forbidden")


def _parse_origin(value: str, *, allow_trailing_slash: bool) -> NormalizedOrigin:
    raw = value.strip()
    if raw != value or not raw or raw == "null" or "," in raw:
        raise MCPOriginError("mcp_origin_malformed")
    parsed = urlparse(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise MCPOriginError("mcp_origin_malformed")
    if parsed.username or parsed.password or parsed.params or parsed.query or parsed.fragment:
        raise MCPOriginError("mcp_origin_malformed")
    if parsed.path and not (allow_trailing_slash and parsed.path == "/"):
        raise MCPOriginError("mcp_origin_malformed")
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        raise MCPOriginError("mcp_origin_malformed") from exc
    return NormalizedOrigin(
        scheme=parsed.scheme,
        host=parsed.hostname.lower(),
        port=port,
    )
