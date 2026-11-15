"""Provider-neutral DNS-pinned urllib transport for untrusted MCP/OAuth endpoints.

DNS is resolved exactly once for each connection. Every answer is verified
before socket creation; the connection is made to the numeric sockaddr from
that verified set. The original hostname is retained for Host, TLS SNI, and
certificate hostname validation. No environment proxy or HTTP redirect is
permitted, including on credential-bearing OAuth calls.
"""
from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
from urllib.error import URLError
from urllib.request import (
    HTTPHandler, HTTPSHandler, HTTPRedirectHandler, ProxyHandler, Request,
    build_opener,
)

from common.mcp_endpoint import (
    MCPEndpointValidationError, format_http_authority, validate_mcp_endpoint,
)


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: N802
        return None


def _verified_socket(
    host: str, port: int, timeout: float | object,
    source_address: tuple[str, int] | None, *, scheme: str,
) -> socket.socket:
    """Resolve and validate ALL answers, then connect only by numeric IP."""
    try:
        # No caller-controlled redirects/proxies can change this hostname.
        address = f"{scheme}://{format_http_authority(host, port, scheme)}/"
        answers = list(socket.getaddrinfo(
            host, port, type=socket.SOCK_STREAM,
        ))
        # Resolve into the exact answers used for the socket, not a second
        # DNS lookup via validation; fail closed if any answer is unsafe.
        validate_mcp_endpoint(
            address,
            resolver=lambda *_args, **_kwargs: answers,
        )
        try:
            literal = ipaddress.ip_address(host)
        except ValueError:
            literal = None
        candidates = []
        for family, socktype, proto, _canon, sockaddr in answers:
            if family not in {socket.AF_INET, socket.AF_INET6}:
                continue
            if socktype != socket.SOCK_STREAM or not sockaddr:
                continue
            peer = ipaddress.ip_address(sockaddr[0])
            # A numeric endpoint must never connect to a different IP even
            # if a faulty/custom resolver supplies an inconsistent result.
            if literal is not None and peer != literal:
                raise MCPEndpointValidationError("endpoint_dns_pin_mismatch")
            if sockaddr[1] != port:
                raise MCPEndpointValidationError("endpoint_dns_pin_mismatch")
            candidates.append((family, socktype, proto, sockaddr))
        if not candidates:
            raise MCPEndpointValidationError("endpoint_host_resolution_failed")
    except (OSError, ValueError) as exc:
        if isinstance(exc, MCPEndpointValidationError):
            raise
        raise MCPEndpointValidationError("endpoint_host_resolution_failed") from exc

    last_error: OSError | None = None
    for family, socktype, proto, sockaddr in candidates:
        sock = socket.socket(family, socktype, proto)
        try:
            if timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:  # noqa: SLF001
                sock.settimeout(timeout)
            if source_address:
                sock.bind(source_address)
            # Numeric sockaddr connects directly: no name resolution between
            # the security check and the actual peer chosen for this socket.
            sock.connect(sockaddr)
            return sock
        except OSError as exc:
            last_error = exc
            sock.close()
    if last_error is not None:
        raise last_error
    raise MCPEndpointValidationError("endpoint_host_resolution_failed")


class _PinnedConnection:
    _pinned_scheme: str

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # http.client sets an instance-level _create_connection to the
        # ordinary, DNS-resolving socket.create_connection in __init__.
        # Replace that per instance, preserving HTTPSConnection.connect's
        # use of the original host for SNI/certificate verification.
        self._create_connection = self._create_pinned_connection

    def _create_pinned_connection(self, address, timeout, source_address):
        return _verified_socket(
            address[0], address[1], timeout, source_address,
            scheme=self._pinned_scheme,
        )


class _PinnedHTTPConnection(_PinnedConnection, http.client.HTTPConnection):
    _pinned_scheme = "http"


class _PinnedHTTPSConnection(_PinnedConnection, http.client.HTTPSConnection):
    _pinned_scheme = "https"


class _PinnedHTTPHandler(HTTPHandler):
    def http_open(self, req):
        if req.has_proxy():
            raise URLError("endpoint_proxy_unsupported")
        return self.do_open(_PinnedHTTPConnection, req)


class _PinnedHTTPSHandler(HTTPSHandler):
    def https_open(self, req):
        # urllib uses _tunnel_host rather than has_proxy() for HTTPS CONNECT.
        if req.has_proxy() or getattr(req, "_tunnel_host", None):
            raise URLError("endpoint_proxy_unsupported")
        # Python 3.13 HTTPSHandler only stores _context; certificate hostname
        # checking is governed by that strict SSLContext and remains enabled.
        return self.do_open(_PinnedHTTPSConnection, req, context=self._context)


def build_pinned_opener():
    """One security boundary for MCP HTTP/SSE, Discovery and upstream OAuth."""
    return build_opener(
        ProxyHandler({}),  # Never delegate credentials or DNS to env proxies.
        _NoRedirect(),
        _PinnedHTTPHandler(),
        _PinnedHTTPSHandler(context=ssl.create_default_context()),
    )


def pinned_urlopen(request: Request, *, timeout: float = 10):
    return build_pinned_opener().open(request, timeout=timeout)
