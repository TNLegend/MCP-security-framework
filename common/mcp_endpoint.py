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

# RFC 6052's well-known NAT64 prefix embeds one IPv4 address in the
# low 32 bits. Accept only its globally routable IPv4 translations.
# This is not a blanket exception for reserved IPv6 addresses.
NAT64_WELL_KNOWN_PREFIX = ipaddress.IPv6Network("64:ff9b::/96")


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
        # Only the explicit 'localhost' lab name may resolve to loopback.
        # A remote DNS hostname advertising 127.0.0.1/::1 is not a lab.
        if parsed.hostname == "localhost" and not address.is_loopback:
            raise MCPEndpointValidationError("endpoint_localhost_resolution_invalid")
        _reject_blocked_address(
            address, allow_loopback=parsed.hostname == "localhost"
        )
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
    *, allow_loopback: bool = True,
) -> None:
    if isinstance(address, ipaddress.IPv6Address) and address in NAT64_WELL_KNOWN_PREFIX:
        # NAT64 AAAA records can accompany ordinary public A records.
        # Python labels 64:ff9b::/96 reserved: inspect the embedded IPv4
        # rather than approving arbitrary IPv6 reserved blocks.
        translated = ipaddress.IPv4Address(int(address) & 0xFFFFFFFF)
        if (
            not translated.is_global
            or translated.is_multicast
            or translated.is_reserved
            or translated in BLOCKED_METADATA_ADDRESSES
        ):
            raise MCPEndpointValidationError("endpoint_special_address_blocked")
        return
    comparable = address.ipv4_mapped if isinstance(address, ipaddress.IPv6Address) else None
    effective = comparable or address
    # Loopback MCPs are deliberately supported for local labs on both
    # address families. IPv6 ::1 is marked "reserved" by ipaddress.
    if (
        allow_loopback
        and effective.is_loopback
        and address not in BLOCKED_METADATA_ADDRESSES
    ):
        return
    if (
        address in BLOCKED_METADATA_ADDRESSES
        or effective in BLOCKED_METADATA_ADDRESSES
        # RFC1918 and CGNAT IPv4 space is not classified as 'reserved' by
        # ipaddress. Require globally routable addresses instead of only
        # banning a few special flags; explicit loopback labs are handled
        # above. Also protects a hostname with mixed public/private answers.
        or not effective.is_global
        or effective.is_link_local
        or effective.is_unspecified
        or effective.is_multicast
        or effective.is_reserved
        or (
            isinstance(effective, ipaddress.IPv6Address)
            and effective.is_private
        )
    ):
        raise MCPEndpointValidationError("endpoint_special_address_blocked")

def format_http_authority(hostname: str, port: int | None, scheme: str) -> str:
    """Provider-neutral RFC 3986 bracketed IPv6 serialization."""
    host = f"[{hostname}]" if ":" in hostname and not hostname.startswith("[") else hostname
    default_port = 443 if scheme.lower() == "https" else 80
    return host if port in (None, default_port) else f"{host}:{port}"
