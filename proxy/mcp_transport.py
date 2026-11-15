from __future__ import annotations

from dataclasses import dataclass
from http.client import IncompleteRead
import socket
import queue
import threading
from time import monotonic
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen
from common.pinned_http import pinned_urlopen

from common.canonical_json import canonical_json_bytes
from proxy.strict_json import (
    MAX_JSON_BYTES,
    MAX_UPSTREAM_RESPONSE_JSON_BYTES,
    MAX_UPSTREAM_RESPONSE_STRING_LENGTH,
    StrictJSONError,
    parse_strict_json,
)


# An upstream SSE event includes framing in addition to the bounded JSON.
MAX_SSE_EVENT_BYTES = MAX_UPSTREAM_RESPONSE_JSON_BYTES + 4_096
MAX_SSE_EVENTS_PER_RESPONSE = 256
MAX_LEGACY_PENDING_REQUESTS = 32


class TransportHTTPError(Exception):
    """Raised when an MCP transport HTTP operation fails."""


class TransportProtocolError(Exception):
    """Raised when an MCP transport violates the selected MCP wire contract."""


@dataclass(frozen=True)
class SSEEvent:
    event: str
    data: str
    event_id: str | None = None


def _iter_sse_raw_lines(
    response: Any, *, max_line_bytes: int, deadline_monotonic: float | None,
):
    """Stream lines without letting a slow, unterminated line reset a deadline."""
    if deadline_monotonic is None:
        # Preserve the historical stream contract for endpoint discovery and
        # callers that do not supply an absolute request deadline.
        while True:
            try:
                line = response.readline(max_line_bytes + 1)
            except TimeoutError as exc:
                raise TransportProtocolError("sse_read_timeout") from exc
            except OSError as exc:
                raise TransportProtocolError("sse_read_failed") from exc
            yield line
            if not line:
                return

    # read1 returns available bytes rather than waiting for a whole line or
    # requested byte count. The fallback reads a single byte, never a full
    # newline-delimited line, on custom streams without read1/read.
    # Inspect methods declared by the concrete stream type. Generic Mock
    # objects dynamically fabricate any attribute (including read1/read),
    # even when only readline was actually configured by a caller.
    if callable(getattr(type(response), "read1", None)):
        reader = response.read1
    elif callable(getattr(type(response), "read", None)):
        reader = response.read
    else:
        reader = lambda _size: response.readline(1)
    pending = bytearray()
    # A byte-drip inside http.client's chunk-size reader can block even
    # read1() across repeated short socket.recv calls. A per-recv timeout
    # does not impose an absolute end-to-end deadline. Abort the underlying
    # socket at the deadline, independently of Python's framing parser.
    raw_socket = getattr(
        getattr(getattr(response, "fp", None), "raw", None), "_sock", None,
    )
    deadline_watchdog = None
    watchdog_expired = threading.Event()
    if raw_socket is not None:
        def _expire_socket(socket_to_abort=raw_socket):
            # The close may interrupt a Windows socket read before the
            # reader observes the next monotonic tick. Record *who*
            # interrupted it so we do not misclassify the deadline as a
            # generic read failure.
            watchdog_expired.set()
            try:
                socket_to_abort.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

        deadline_watchdog = threading.Timer(
            max(0.001, deadline_monotonic - monotonic()), _expire_socket,
        )
        deadline_watchdog.daemon = True
        deadline_watchdog.start()
    try:
        while True:
            remaining = deadline_monotonic - monotonic()
            if remaining <= 0:
                raise TransportProtocolError("mcp_sse_response_deadline_exceeded")
            try:
                if raw_socket is not None:
                    fileno = getattr(raw_socket, "fileno", None)
                    descriptor = fileno() if callable(fileno) else None
                    if isinstance(descriptor, int) and descriptor < 0:
                        # HTTPResponse closes its raw socket once a finite
                        # Content-Length has been consumed. Still ask its
                        # reader for EOF and drain/validate buffered frames.
                        raw_socket = None
                    else:
                        raw_socket.settimeout(max(0.001, remaining))
                chunk = reader(min(8192, max_line_bytes + 1))
            except (TimeoutError, OSError, IncompleteRead) as exc:
                if watchdog_expired.is_set() or monotonic() >= deadline_monotonic:
                    raise TransportProtocolError(
                        "mcp_sse_response_deadline_exceeded"
                    ) from exc
                if isinstance(exc, TimeoutError):
                    raise TransportProtocolError("sse_read_timeout") from exc
                raise TransportProtocolError("sse_read_failed") from exc
            if monotonic() >= deadline_monotonic:
                raise TransportProtocolError("mcp_sse_response_deadline_exceeded")
            if not isinstance(chunk, bytes):
                raise TransportProtocolError("sse_read_invalid_bytes")
            if not chunk:
                remaining_body = getattr(response, "length", None)
                if isinstance(remaining_body, int) and remaining_body > 0:
                    raise TransportProtocolError("mcp_sse_response_incomplete_body")
                if pending:
                    yield bytes(pending)
                yield b""
                return
            pending.extend(chunk)
            while True:
                end = pending.find(b"\n")
                if end < 0:
                    break
                if end + 1 > max_line_bytes + 1:
                    raise TransportProtocolError("sse_event_too_large")
                line = bytes(pending[:end + 1])
                del pending[:end + 1]
                yield line
            if len(pending) > max_line_bytes:
                raise TransportProtocolError("sse_event_too_large")
    finally:
        if deadline_watchdog is not None:
            deadline_watchdog.cancel()

def iter_sse_events(
    response: Any, *,
    max_event_bytes: int = MAX_SSE_EVENT_BYTES,
    deadline_monotonic: float | None = None,
):
    event_name = "message"
    event_id: str | None = None
    data_parts: list[str] = []
    bytes_seen = 0
    saw_field = False

    for raw_line in _iter_sse_raw_lines(
        response,
        max_line_bytes=max_event_bytes,
        deadline_monotonic=deadline_monotonic,
    ):
        if deadline_monotonic is not None and monotonic() >= deadline_monotonic:
            raise TransportProtocolError("mcp_sse_response_deadline_exceeded")
        if raw_line == b"":
            if saw_field or data_parts:
                raise TransportProtocolError("sse_stream_closed_mid_event")
            return
        bytes_seen += len(raw_line)
        if bytes_seen > max_event_bytes:
            raise TransportProtocolError("sse_event_too_large")
        try:
            line = raw_line.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise TransportProtocolError("sse_line_invalid_utf8") from exc
        line = line.rstrip("\r\n")
        if line == "":
            if data_parts:
                yield SSEEvent(event=event_name or "message", data="\n".join(data_parts), event_id=event_id)
            event_name = "message"
            event_id = None
            data_parts = []
            bytes_seen = 0
            saw_field = False
            continue
        saw_field = True
        if line.startswith(":"):
            continue
        field, separator, value = line.partition(":")
        if separator and value.startswith(" "):
            value = value[1:]
        if field == "event":
            event_name = value
        elif field == "data":
            data_parts.append(value)
        elif field == "id":
            event_id = value
        elif field == "retry":
            continue


def read_endpoint_event(response: Any) -> str:
    for index, event in enumerate(iter_sse_events(response)):
        if index >= MAX_SSE_EVENTS_PER_RESPONSE:
            raise TransportProtocolError("legacy_sse_endpoint_event_missing")
        if event.event != "endpoint":
            if event.data:
                raise TransportProtocolError("legacy_sse_endpoint_unexpected_event")
            continue
        endpoint = event.data.strip()
        if not endpoint:
            raise TransportProtocolError("legacy_sse_endpoint_empty")
        return endpoint
    raise TransportProtocolError("legacy_sse_endpoint_event_missing")


def resolve_same_origin_endpoint(base_endpoint: str, event_endpoint: str) -> str:
    base = urlparse(base_endpoint)
    if base.scheme not in {"http", "https"} or not base.netloc:
        raise TransportProtocolError("legacy_sse_base_endpoint_invalid")
    resolved = urlparse(urljoin(base_endpoint, event_endpoint))
    if resolved.scheme not in {"http", "https"}:
        raise TransportProtocolError("legacy_sse_endpoint_scheme_invalid")
    if resolved.username or resolved.password or resolved.fragment:
        raise TransportProtocolError("legacy_sse_endpoint_authority_invalid")
    if (
        resolved.scheme != base.scheme
        or (resolved.hostname or "").lower() != (base.hostname or "").lower()
        or _effective_port(resolved) != _effective_port(base)
    ):
        raise TransportProtocolError("legacy_sse_endpoint_cross_origin")
    if not resolved.path.startswith("/"):
        raise TransportProtocolError("legacy_sse_endpoint_path_invalid")
    return resolved.geturl()


def _effective_port(parsed: Any) -> int | None:
    if parsed.port is not None:
        return parsed.port
    if parsed.scheme == "http":
        return 80
    if parsed.scheme == "https":
        return 443
    return None


class StreamableHTTPResponseDecoder:
    def __init__(
        self,
        *,
        expected_request_id: Any,
        max_response_bytes: int = MAX_UPSTREAM_RESPONSE_JSON_BYTES,
        max_sse_event_bytes: int = MAX_SSE_EVENT_BYTES,
        deadline_monotonic: float | None = None,
    ) -> None:
        self.deadline_monotonic = deadline_monotonic
        self.expected_request_id = expected_request_id
        self.max_response_bytes = max_response_bytes
        self.max_sse_event_bytes = max_sse_event_bytes

    def decode(self, response: Any) -> dict[str, Any]:
        status_code = response.getcode()
        if status_code != 200:
            raise TransportProtocolError(f"unexpected_mcp_response_status:{status_code}")
        content_type = response.headers.get_content_type()
        if content_type == "application/json":
            return self._decode_json_response(response)
        if content_type == "text/event-stream":
            return self._decode_sse_response(response)
        raise TransportProtocolError("mcp_response_content_type_unsupported")

    def _decode_json_response(self, response: Any) -> dict[str, Any]:
        # read(n) may wait for n bytes even as a server slowly drips chunks;
        # read1 (when available) returns the next available buffered chunk.
        # Recheck the absolute deadline after every chunk, not just SSE.
        chunks: list[bytes] = []
        size = 0
        read_next = getattr(response, "read1", None) or response.read
        while True:
            if self.deadline_monotonic is not None and monotonic() >= self.deadline_monotonic:
                raise TransportProtocolError("mcp_jsonrpc_response_deadline_exceeded")
            try:
                if self.deadline_monotonic is not None:
                    # urllib's HTTPResponse is backed by a buffered socket.
                    # Clamp each individual blocking read to the remaining
                    # end-to-end budget, not the original socket idle timeout.
                    raw_socket = getattr(
                        getattr(getattr(response, "fp", None), "raw", None),
                        "_sock", None,
                    )
                    if raw_socket is not None:
                        remaining = self.deadline_monotonic - monotonic()
                        if remaining <= 0:
                            raise TransportProtocolError(
                                "mcp_jsonrpc_response_deadline_exceeded"
                            )
                        raw_socket.settimeout(max(0.001, remaining))
                chunk = read_next(min(8192, self.max_response_bytes + 1 - size))
            except TimeoutError as exc:
                raise TransportProtocolError("mcp_response_timeout") from exc
            except OSError as exc:
                raise TransportProtocolError("mcp_response_read_failed") from exc
            if self.deadline_monotonic is not None and monotonic() >= self.deadline_monotonic:
                raise TransportProtocolError("mcp_jsonrpc_response_deadline_exceeded")
            if not chunk:
                break
            size += len(chunk)
            if size > self.max_response_bytes:
                raise TransportProtocolError("mcp_jsonrpc_response_too_large")
            chunks.append(chunk)
        body = b"".join(chunks)
        if not body:
            raise TransportProtocolError("mcp_jsonrpc_response_empty")
        try:
            message = parse_strict_json(
                body,
                max_bytes=min(self.max_response_bytes, MAX_UPSTREAM_RESPONSE_JSON_BYTES),
                max_string_length=MAX_UPSTREAM_RESPONSE_STRING_LENGTH,
            )
        except StrictJSONError as exc:
            raise TransportProtocolError("mcp_jsonrpc_response_invalid_json") from exc
        return self._validate_response_message(message)

    def _decode_sse_response(self, response: Any) -> dict[str, Any]:
        final_response: dict[str, Any] | None = None
        # Chunked SSE streams may remain open after the final JSON-RPC event.
        # Finite, close-delimited streams are drained to detect extra replies.
        transfer_encodings = (response.headers.get("Transfer-Encoding", "") or "").lower()
        persistent_chunked_stream = "chunked" in {
            encoding.strip() for encoding in transfer_encodings.split(",")
        }
        for index, event in enumerate(
            iter_sse_events(
                response, max_event_bytes=self.max_sse_event_bytes,
                deadline_monotonic=self.deadline_monotonic,
            )
        ):
            if index >= MAX_SSE_EVENTS_PER_RESPONSE:
                raise TransportProtocolError("mcp_sse_response_event_limit_exceeded")
            if not event.data:
                continue
            if event.event != "message":
                raise TransportProtocolError("mcp_sse_response_unexpected_event")
            try:
                parsed = parse_strict_json(
                    event.data.encode("utf-8"),
                    max_bytes=MAX_UPSTREAM_RESPONSE_JSON_BYTES,
                    max_string_length=MAX_UPSTREAM_RESPONSE_STRING_LENGTH,
                )
            except StrictJSONError as exc:
                raise TransportProtocolError("mcp_sse_response_invalid_json") from exc
            for message in _jsonrpc_messages(parsed):
                response_message = self._classify_stream_message(message)
                if response_message is not None:
                    if final_response is not None:
                        raise TransportProtocolError("mcp_sse_duplicate_final_response")
                    final_response = response_message
            # On a persistent chunked SSE stream there is no required EOF.
            # A complete, validated final event is sufficient to finish the call.
            if final_response is not None and persistent_chunked_stream:
                return final_response
        if final_response is None:
            raise TransportProtocolError("mcp_sse_response_missing_final_response")
        return final_response

    def _classify_stream_message(self, message: dict[str, Any]) -> dict[str, Any] | None:
        if "method" in message:
            if "id" in message:
                raise TransportProtocolError("mcp_sse_server_request_unsupported")
            method = message.get("method")
            if method not in {"notifications/progress", "notifications/message"}:
                raise TransportProtocolError("mcp_sse_notification_unsupported")
            return None
        return self._validate_response_message(message)

    def _validate_response_message(self, message: Any) -> dict[str, Any]:
        if not isinstance(message, dict):
            raise TransportProtocolError("mcp_jsonrpc_response_not_object")
        if message.get("jsonrpc") != "2.0":
            raise TransportProtocolError("mcp_jsonrpc_response_version_invalid")
        if message.get("id") != self.expected_request_id:
            raise TransportProtocolError("mcp_jsonrpc_response_id_mismatch")
        if ("result" in message) == ("error" in message):
            raise TransportProtocolError("mcp_jsonrpc_response_result_error_invalid")
        return message


def _jsonrpc_messages(parsed: Any) -> list[dict[str, Any]]:
    if isinstance(parsed, dict):
        return [parsed]
    if isinstance(parsed, list) and 0 < len(parsed) <= 16 and all(
        isinstance(item, dict) for item in parsed
    ):
        return list(parsed)
    raise TransportProtocolError("mcp_sse_jsonrpc_batch_invalid")


class LegacyHTTPSSETransport:
    def __init__(
        self,
        *,
        sse_endpoint: str,
        timeout_seconds: float,
        opener: Any | None = None,
        connection_headers: dict[str, str] | None = None,
    ) -> None:
        self.sse_endpoint = sse_endpoint
        self.timeout_seconds = timeout_seconds
        self.post_endpoint: str | None = None
        self._opener = opener
        self._connection_headers = dict(connection_headers or {})
        self._response: Any | None = None
        self._reader: threading.Thread | None = None
        self._endpoint_ready = threading.Event()
        self._lock = threading.RLock()
        self._pending: dict[Any, queue.Queue[dict[str, Any] | Exception]] = {}
        self._closed = False
        self._error: Exception | None = None

    def open(self) -> None:
        with self._lock:
            if self.post_endpoint is not None and self._error is None:
                return
            self._closed = False
            self._error = None
            self._endpoint_ready.clear()
        request = Request(
            self.sse_endpoint,
            headers={"Accept": "text/event-stream", **self._connection_headers},
            method="GET",
        )
        try:
            response = self._open_url(request)
        except HTTPError as exc:
            raise TransportHTTPError(f"legacy_sse_http_{exc.code}") from exc
        except TimeoutError as exc:
            raise TransportHTTPError("legacy_sse_timeout") from exc
        except URLError as exc:
            raise TransportHTTPError(f"legacy_sse_network_error:{exc.reason}") from exc
        if response.headers.get_content_type() != "text/event-stream":
            response.close()
            raise TransportProtocolError("legacy_sse_content_type_invalid")
        self._response = response
        self._reader = threading.Thread(
            target=self._reader_loop,
            name="mcp-legacy-http-sse-reader",
            daemon=True,
        )
        self._reader.start()
        if not self._endpoint_ready.wait(self.timeout_seconds):
            self.close()
            raise TransportProtocolError("legacy_sse_endpoint_timeout")
        if self._error is not None:
            self.close()
            raise TransportProtocolError(str(self._error)) from self._error
        if not self.post_endpoint:
            self.close()
            raise TransportProtocolError("legacy_sse_post_endpoint_missing")

    def post_json(
        self,
        payload: dict[str, Any],
        *,
        headers: dict[str, str],
        notification: bool = False,
    ) -> dict[str, Any]:
        self.open()
        request_id = payload.get("id")
        waiter: queue.Queue[dict[str, Any] | Exception] | None = None
        if not notification:
            waiter = queue.Queue(maxsize=1)
            with self._lock:
                if self._error is not None:
                    raise TransportProtocolError(str(self._error))
                if len(self._pending) >= MAX_LEGACY_PENDING_REQUESTS:
                    raise TransportProtocolError("legacy_sse_pending_limit_exceeded")
                self._pending[request_id] = waiter
        try:
            self._post_message(payload, headers=headers)
            if notification:
                return {}
            assert waiter is not None
            try:
                result = waiter.get(timeout=self.timeout_seconds)
            except queue.Empty as exc:
                raise TransportProtocolError("legacy_sse_response_timeout") from exc
            if isinstance(result, Exception):
                raise TransportProtocolError(str(result)) from result
            return result
        finally:
            if not notification:
                with self._lock:
                    self._pending.pop(request_id, None)

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            response = self._response
            self._response = None
            self._fail_pending_locked(TransportProtocolError("legacy_sse_connection_closed"))
        if response is not None:
            try:
                response.close()
            except OSError:
                pass

    def _open_url(self, request: Request) -> Any:
        if self._opener is not None:
            return self._opener.open(request, timeout=self.timeout_seconds)
        return pinned_urlopen(request, timeout=self.timeout_seconds)

    def _post_message(self, payload: dict[str, Any], *, headers: dict[str, str]) -> None:
        if not self.post_endpoint:
            raise TransportProtocolError("legacy_sse_post_endpoint_missing")
        body = canonical_json_bytes(payload)
        request = Request(
            self.post_endpoint,
            data=body,
            headers=headers,
            method="POST",
        )
        try:
            with self._open_url(request) as response:
                status_code = response.getcode()
                if status_code not in {200, 202, 204}:
                    raise TransportProtocolError(f"legacy_sse_post_status_invalid:{status_code}")
                response.read(MAX_JSON_BYTES + 1)
        except HTTPError as exc:
            exc.read(MAX_JSON_BYTES + 1)
            raise TransportHTTPError(f"legacy_sse_post_http_{exc.code}") from exc
        except TimeoutError as exc:
            raise TransportHTTPError("legacy_sse_post_timeout") from exc
        except URLError as exc:
            raise TransportHTTPError(f"legacy_sse_post_network_error:{exc.reason}") from exc

    def _reader_loop(self) -> None:
        try:
            response = self._response
            if response is None:
                raise TransportProtocolError("legacy_sse_response_missing")
            endpoint = read_endpoint_event(response)
            self.post_endpoint = resolve_same_origin_endpoint(self.sse_endpoint, endpoint)
            self._endpoint_ready.set()
            for event in iter_sse_events(response):
                if self._closed:
                    return
                if event.event != "message" or not event.data:
                    raise TransportProtocolError("legacy_sse_unexpected_event")
                try:
                    parsed = parse_strict_json(
                    event.data.encode("utf-8"),
                    max_bytes=MAX_UPSTREAM_RESPONSE_JSON_BYTES,
                    max_string_length=MAX_UPSTREAM_RESPONSE_STRING_LENGTH,
                )
                except StrictJSONError as exc:
                    raise TransportProtocolError("legacy_sse_message_invalid_json") from exc
                for message in _jsonrpc_messages(parsed):
                    self._deliver_message(message)
            raise TransportProtocolError("legacy_sse_connection_disconnected")
        except Exception as exc:
            self._record_error(exc)

    def _deliver_message(self, message: dict[str, Any]) -> None:
        if message.get("jsonrpc") != "2.0":
            raise TransportProtocolError("legacy_sse_jsonrpc_version_invalid")
        if "method" in message:
            if "id" in message:
                raise TransportProtocolError("legacy_sse_server_request_unsupported")
            if message.get("method") not in {"notifications/progress", "notifications/message"}:
                raise TransportProtocolError("legacy_sse_notification_unsupported")
            return
        request_id = message.get("id")
        if ("result" in message) == ("error" in message):
            raise TransportProtocolError("legacy_sse_response_result_error_invalid")
        with self._lock:
            waiter = self._pending.pop(request_id, None)
        if waiter is None:
            raise TransportProtocolError("legacy_sse_unknown_response_id")
        waiter.put_nowait(message)

    def _record_error(self, exc: Exception) -> None:
        with self._lock:
            if self._closed:
                return
            self._error = exc
            self._endpoint_ready.set()
            self._fail_pending_locked(exc)

    def _fail_pending_locked(self, exc: Exception) -> None:
        for waiter in self._pending.values():
            try:
                waiter.put_nowait(exc)
            except queue.Full:
                pass
        self._pending.clear()
