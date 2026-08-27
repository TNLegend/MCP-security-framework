from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import socket
from typing import Any, Callable, Iterable
from urllib.parse import SplitResult, parse_qsl, urlsplit


ALLOWED_MCP_SCHEMES = frozenset({"http", "https"})
LOCAL_LAB_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
LOCAL_LAB_TRUST_HOST = "127.0.0.1"
LOCAL_LAB_PORT = 9000
LOCAL_LAB_PATH = "/mcp"
BLOCKED_METADATA_HOSTS = frozenset(
    {
        "instance-data.ec2.internal",
        "metadata.aws.internal",
        "metadata.google.internal",
    }
)
BLOCKED_METADATA_ADDRESSES = frozenset(
    {
        ipaddress.ip_address("100.100.100.200"),
        ipaddress.ip_address("169.254.169.254"),
        ipaddress.ip_address("169.254.170.2"),
        ipaddress.ip_address("fd00:ec2::254"),
    }
)
SENSITIVE_QUERY_PARAMETER_NAMES = frozenset(
    {
        "access_token",
        "api_key",
        "authorization",
        "credential",
        "password",
        "secret",
        "token",
    }
)


class MCPEndpointValidationError(ValueError):
    """Raised when an Inventory-owned MCP endpoint is unsafe or malformed."""


@dataclass(frozen=True)
class ParsedMCPEndpoint:
    value: str
    parsed: SplitResult
    hostname: str
    port: int


AddressResolver = Callable[..., Iterable[tuple]]


def server_ref_for_server(server: dict[str, Any]) -> str:
    explicit = server.get("server_ref")
    if isinstance(explicit, str) and explicit.strip():
        return explicit
    transport = str(server.get("transport") or "streamable_http")
    endpoint = str(server.get("endpoint") or "")
    return f"{transport}:{endpoint}"


def parse_mcp_endpoint(endpoint: str) -> ParsedMCPEndpoint:
    if not isinstance(endpoint, str):
        raise MCPEndpointValidationError("endpoint_invalid")
    normalized = endpoint.strip()
    if not normalized or normalized != endpoint or "\\" in normalized:
        raise MCPEndpointValidationError("endpoint_invalid")
    if any(character.isspace() or ord(character) < 32 for character in normalized):
        raise MCPEndpointValidationError("endpoint_invalid")
    try:
        parsed = urlsplit(normalized)
        hostname = (parsed.hostname or "").rstrip(".").lower()
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    except ValueError as exc:
        raise MCPEndpointValidationError("endpoint_invalid") from exc
    if parsed.scheme.lower() not in ALLOWED_MCP_SCHEMES:
        raise MCPEndpointValidationError("unsupported_endpoint_scheme")
    if not parsed.netloc or not hostname:
        raise MCPEndpointValidationError("endpoint_authority_invalid")
    if parsed.username is not None or parsed.password is not None:
        raise MCPEndpointValidationError("endpoint_userinfo_unsupported")
    if parsed.fragment:
        raise MCPEndpointValidationError("endpoint_fragment_unsupported")
    if any(
        name.lower() in SENSITIVE_QUERY_PARAMETER_NAMES
        for name, _value in parse_qsl(parsed.query, keep_blank_values=True)
    ):
        raise MCPEndpointValidationError("endpoint_sensitive_query_unsupported")
    if "%" in hostname or port < 1 or port > 65535:
        raise MCPEndpointValidationError("endpoint_authority_invalid")
    return ParsedMCPEndpoint(
        value=normalized,
        parsed=parsed,
        hostname=hostname,
        port=port,
    )


def validate_mcp_endpoint(
    endpoint: str,
    *,
    resolve_dns: bool = True,
    resolver: AddressResolver | None = None,
) -> ParsedMCPEndpoint:
    parsed = parse_mcp_endpoint(endpoint)
    if parsed.hostname in BLOCKED_METADATA_HOSTS:
        raise MCPEndpointValidationError("endpoint_metadata_target_blocked")

    literal = _ip_address(parsed.hostname)
    if literal is not None:
        _reject_blocked_address(literal)
        return parsed
    if not resolve_dns:
        return parsed

    resolve = resolver or socket.getaddrinfo
    try:
        answers = resolve(
            parsed.hostname,
            parsed.port,
            type=socket.SOCK_STREAM,
        )
    except (OSError, socket.gaierror) as exc:
        raise MCPEndpointValidationError("endpoint_host_resolution_failed") from exc
    addresses = {
        address
        for answer in answers
        if len(answer) >= 5
        for address in [_ip_address(str(answer[4][0]))]
        if address is not None
    }
    if not addresses:
        raise MCPEndpointValidationError("endpoint_host_resolution_failed")
    for address in addresses:
        _reject_blocked_address(address)
    return parsed


def is_exact_local_lab_endpoint(endpoint: str) -> bool:
    try:
        parsed = parse_mcp_endpoint(endpoint)
    except MCPEndpointValidationError:
        return False
    return (
        parsed.parsed.scheme.lower() == "http"
        and parsed.hostname == LOCAL_LAB_TRUST_HOST
        and parsed.port == LOCAL_LAB_PORT
        and parsed.parsed.path == LOCAL_LAB_PATH
        and not parsed.parsed.query
    )


def _ip_address(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _reject_blocked_address(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> None:
    comparable = address.ipv4_mapped if isinstance(address, ipaddress.IPv6Address) else None
    effective = comparable or address
    if (
        address in BLOCKED_METADATA_ADDRESSES
        or effective in BLOCKED_METADATA_ADDRESSES
        or effective.is_link_local
        or effective.is_unspecified
        or effective.is_multicast
        or effective.is_reserved
    ):
        raise MCPEndpointValidationError("endpoint_special_address_blocked")
