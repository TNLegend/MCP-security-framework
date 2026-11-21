from __future__ import annotations
from common.tool_projection import render_tool_definition

import asyncio
from dataclasses import dataclass
from functools import partial
from datetime import datetime, timedelta, timezone
from pathlib import Path
import queue
import secrets
import sys
import threading
from typing import Any

backend_path = Path(__file__).resolve().parents[1] / "backend"
if str(backend_path) not in sys.path:
    sys.path.insert(0, str(backend_path))

from anyio import CapacityLimiter, to_thread
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

from app.core.config import settings
from app.services.published_configuration import (
    PublishedConfigurationError,
    PublishedConfigurationSnapshotResolver,
)
from proxy.backend_client import BackendClient, BackendClientError
from proxy.mcp_origin import MCPOriginError, MCPOriginValidator
from proxy.mcp_proxy import MCPProxy, protocol_verdict_expired
from proxy.runtime_logger import safe_runtime_error_code
from proxy.protocol_profiles import (
    LEGACY_PROFILE_ID,
    LEGACY_PROTOCOL_VERSIONS,
    MODERN_META_PROTOCOL_VERSION,
    MODERN_DISCOVER_CACHE_SCOPE,
    MODERN_PROTOCOL_VERSIONS,
    MODERN_TOOLS_LIST_CACHE_SCOPE,
    ProtocolProfileError,
    ProtocolProfileRegistry,
    modern_cache_fields,
    modern_result_meta,
)
from proxy.protocol_revisions import ProtocolEra, TransportKind
from proxy.protocol_sessions import LegacyClientSessionStore
from proxy.observation_admission import live_review_admissible
from proxy.strict_json import MAX_JSON_BYTES, StrictJSONError, parse_strict_json


class EraResolver:
    def __init__(self) -> None:
        self.registry = ProtocolProfileRegistry()

    def resolve(
        self,
        payload: dict[str, Any],
        headers: dict[str, str],
    ) -> str:
        header_version = headers.get("mcp-protocol-version")
        params = payload.get("params")
        meta = params.get("_meta") if isinstance(params, dict) else None
        meta_version = (
            meta.get(MODERN_META_PROTOCOL_VERSION) if isinstance(meta, dict) else None
        )
        legacy_body_version = (
            params.get("protocolVersion") if isinstance(params, dict) else None
        )
        candidates = {
            value
            for value in (header_version, meta_version, legacy_body_version)
            if isinstance(value, str) and value
        }
        if len(candidates) > 1:
            raise ProtocolProfileError("conflicting_protocol_era_signals")
        if not candidates:
            raise ProtocolProfileError("unsupported_or_missing_protocol_era")
        version = next(iter(candidates))
        try:
            profile = self.registry.get_by_version(version)
        except ProtocolProfileError as exc:
            raise ProtocolProfileError("unsupported_or_missing_protocol_era") from exc
        if version in MODERN_PROTOCOL_VERSIONS or version in LEGACY_PROTOCOL_VERSIONS:
            return profile.profile_id
        raise ProtocolProfileError("unsupported_or_missing_protocol_era")


@dataclass
class LegacyHTTPSSEConnection:
    connection_id: str
    server_id: int
    expires_at: datetime
    messages: queue.Queue[str | None]
    initialized: bool = False
    protocol_version: str | None = None
    profile_id: str | None = None


class LegacyHTTPSSEConnectionStore:
    def __init__(
        self,
        ttl_seconds: int = 900,
        queue_size: int = 64,
        max_connections: int = 1_000,
        max_connections_per_server: int = 200,
    ) -> None:
        self.ttl = timedelta(seconds=ttl_seconds)
        self.queue_size = queue_size
        self.max_connections = max_connections
        self.max_connections_per_server = max_connections_per_server
        self._connections: dict[str, LegacyHTTPSSEConnection] = {}
        self._lock = threading.RLock()

    def create(self, server_id: int) -> LegacyHTTPSSEConnection:
        now = datetime.now(timezone.utc)
        connection = LegacyHTTPSSEConnection(
            connection_id=secrets.token_urlsafe(32),
            server_id=server_id,
            expires_at=now + self.ttl,
            messages=queue.Queue(maxsize=self.queue_size),
        )
        with self._lock:
            self._cleanup_expired_locked(now)
            if len(self._connections) >= self.max_connections:
                raise ProtocolProfileError("legacy_http_sse_connection_capacity_exceeded")
            server_count = sum(
                1 for item in self._connections.values() if item.server_id == server_id
            )
            if server_count >= self.max_connections_per_server:
                raise ProtocolProfileError(
                    "legacy_http_sse_server_connection_capacity_exceeded"
                )
            self._connections[connection.connection_id] = connection
        return connection

    def get(self, connection_id: str, server_id: int) -> LegacyHTTPSSEConnection:
        with self._lock:
            connection = self._connections.get(connection_id)
            if (
                connection is None
                or connection.server_id != server_id
                or connection.expires_at <= datetime.now(timezone.utc)
            ):
                self._connections.pop(connection_id, None)
                raise ValueError("legacy_http_sse_connection_invalid")
            return connection

    def set_profile(
        self,
        connection_id: str,
        server_id: int,
        *,
        protocol_version: str,
        profile_id: str,
    ) -> None:
        connection = self.get(connection_id, server_id)
        connection.protocol_version = protocol_version
        connection.profile_id = profile_id

    def mark_initialized(self, connection_id: str, server_id: int) -> None:
        self.get(connection_id, server_id).initialized = True

    def enqueue_response(self, connection: LegacyHTTPSSEConnection, response: Response) -> None:
        body = getattr(response, "body", b"")
        if not isinstance(body, bytes):
            body = bytes(body)
        self._enqueue(connection, body.decode("utf-8"))

    def enqueue_jsonrpc(self, connection: LegacyHTTPSSEConnection, payload: dict[str, Any]) -> None:
        import json

        self._enqueue(connection, json.dumps(payload, separators=(",", ":")))

    def stream(self, connection: LegacyHTTPSSEConnection):
        endpoint = f"/mcp/{connection.server_id}?sse_connection_id={connection.connection_id}"
        yield f"event: endpoint\ndata: {endpoint}\n\n".encode("utf-8")
        try:
            while True:
                try:
                    message = connection.messages.get(timeout=30)
                except queue.Empty:
                    yield b": keepalive\n\n"
                    continue
                if message is None:
                    return
                yield f"event: message\ndata: {message}\n\n".encode("utf-8")
        finally:
            with self._lock:
                self._connections.pop(connection.connection_id, None)

    def _enqueue(self, connection: LegacyHTTPSSEConnection, message: str) -> None:
        try:
            connection.messages.put_nowait(message)
        except queue.Full as exc:
            raise ProtocolProfileError("legacy_http_sse_response_queue_full") from exc

    def _cleanup_expired_locked(self, now: datetime) -> None:
        expired = [
            connection_id
            for connection_id, connection in self._connections.items()
            if connection.expires_at <= now
        ]
        for connection_id in expired:
            self._connections.pop(connection_id, None)


class MCPGateway:
    def __init__(
        self,
        *,
        proxy: MCPProxy | None = None,
        backend_client: BackendClient | None = None,
        snapshot_resolver: PublishedConfigurationSnapshotResolver | None = None,
        legacy_sessions: LegacyClientSessionStore | None = None,
        legacy_http_sse_connections: LegacyHTTPSSEConnectionStore | None = None,
        allowed_origins: tuple[str, ...] | None = None,
    ) -> None:
        self.backend_client = backend_client or BackendClient()
        self.proxy = proxy or MCPProxy(backend_client=self.backend_client)
        self.snapshot_resolver = snapshot_resolver or PublishedConfigurationSnapshotResolver()
        self.legacy_sessions = legacy_sessions or LegacyClientSessionStore()
        self.legacy_http_sse_connections = (
            legacy_http_sse_connections or LegacyHTTPSSEConnectionStore()
        )
        self.profiles = ProtocolProfileRegistry()
        self.era_resolver = EraResolver()
        # Bound synchronous control-plane/policy/upstream work off the
        # ASGI event loop. One gateway instance owns one concurrency limit.
        self._dispatch_limiter = CapacityLimiter(8)
        # Bound admitted work (active + waiting), not just worker threads.
        self._dispatch_admission = asyncio.Semaphore(16)
        self.origin_validator = (
            MCPOriginValidator(allowed_origins)
            if allowed_origins is not None
            else MCPOriginValidator.from_csv(settings.mcp_gateway_allowed_origins)
        )

    def create_app(self) -> FastAPI:
        app = FastAPI(title="MCP Security Gateway", docs_url=None, redoc_url=None)

        @app.get("/health")
        async def gateway_health() -> dict[str, str]:
            return {"status": "ok", "service": "mcp-security-gateway"}

        @app.post("/mcp/{server_id}")
        async def mcp_endpoint(server_id: int, request: Request) -> Response:
            try:
                headers = _strict_request_headers(request)
                self.origin_validator.validate_headers(headers)
                content_type = headers.get("content-type", "").split(";", 1)[0].lower()
                if content_type != "application/json":
                    return _jsonrpc_error(None, -32600, "unsupported_content_type", 415)
                payload = parse_strict_json(await _read_bounded_json_body(request))
                _validate_jsonrpc_envelope(payload)
                try:
                    await asyncio.wait_for(self._dispatch_admission.acquire(), timeout=0.05)
                except asyncio.TimeoutError:
                    return _jsonrpc_error(
                        payload.get("id"), -32000, "gateway_overloaded", 503
                    )
                try:
                    sse_connection_id = request.query_params.get("sse_connection_id")
                    if sse_connection_id:
                        profile_id = await to_thread.run_sync(
                            partial(
                                self._resolve_legacy_http_sse_profile_id,
                                server_id, sse_connection_id, payload, headers,
                            ),
                            limiter=self._dispatch_limiter,
                        )
                    else:
                        profile_id = await to_thread.run_sync(
                            partial(self._resolve_profile_id, server_id, payload, headers),
                            limiter=self._dispatch_limiter,
                        )
                    profile = self.profiles.get(profile_id)
                    profile.validate_inbound_request(payload, headers=headers)
                    if sse_connection_id:
                        return await to_thread.run_sync(
                            partial(
                                self._dispatch_legacy_http_sse_post,
                                server_id=server_id, connection_id=sse_connection_id,
                                payload=payload, headers=headers, profile_id=profile_id,
                            ),
                            limiter=self._dispatch_limiter,
                        )
                    return await to_thread.run_sync(
                        partial(
                            self._dispatch,
                            server_id=server_id, payload=payload, headers=headers,
                            profile_id=profile_id,
                        ),
                        limiter=self._dispatch_limiter,
                    )
                finally:
                    self._dispatch_admission.release()
            except MCPOriginError as exc:
                return _jsonrpc_error(None, -32000, str(exc), 403)
            except (StrictJSONError, ProtocolProfileError, ValueError) as exc:
                return _jsonrpc_error(payload.get("id") if "payload" in locals() else None, -32600, str(exc), 400)
            except (BackendClientError, PublishedConfigurationError):
                return _jsonrpc_error(payload.get("id") if "payload" in locals() else None, -32000, "gateway_dependency_unavailable", 503)
            except Exception:
                return _jsonrpc_error(payload.get("id") if "payload" in locals() else None, -32603, "gateway_fail_closed", 500)

        @app.get("/mcp/{server_id}")
        async def mcp_get_endpoint(server_id: int, request: Request) -> Response:
            try:
                headers = _strict_request_headers(request)
                self.origin_validator.validate_headers(headers)
                profile_id = self._resolve_get_profile_id(server_id, headers)
                profile = self.profiles.get(profile_id)
                if profile.transport_kind != TransportKind.LEGACY_HTTP_SSE:
                    return Response(status_code=405, headers={"Allow": "POST"})
                connection = self.legacy_http_sse_connections.create(server_id)
                return StreamingResponse(
                    self.legacy_http_sse_connections.stream(connection),
                    media_type="text/event-stream",
                    headers={"Cache-Control": "no-cache"},
                )
            except MCPOriginError as exc:
                return _jsonrpc_error(None, -32000, str(exc), 403)
            except (ProtocolProfileError, ValueError) as exc:
                return _jsonrpc_error(None, -32600, str(exc), 400)

        return app

    def _resolve_profile_id(
        self,
        server_id: int,
        payload: dict[str, Any],
        headers: dict[str, str],
    ) -> str:
        method = payload.get("method")
        session_id = headers.get("mcp-session-id")
        if isinstance(session_id, str) and session_id and method != "initialize":
            session = self.legacy_sessions.get(session_id, server_id)
            header_version = headers.get("mcp-protocol-version")
            if header_version and header_version != session.protocol_version:
                raise ProtocolProfileError("legacy_protocol_session_revision_mismatch")
            return session.profile_id
        return self.era_resolver.resolve(payload, headers)

    def _resolve_get_profile_id(self, server_id: int, headers: dict[str, str]) -> str:
        session_id = headers.get("mcp-session-id")
        header_version = headers.get("mcp-protocol-version")
        if isinstance(session_id, str) and session_id:
            session = self.legacy_sessions.get(session_id, server_id)
            if header_version and header_version != session.protocol_version:
                raise ProtocolProfileError("legacy_protocol_session_revision_mismatch")
            return session.profile_id
        if isinstance(header_version, str) and header_version:
            return self.profiles.get_by_version(header_version).profile_id
        return self.profiles.get_by_version("2024-11-05").profile_id

    def _resolve_legacy_http_sse_profile_id(
        self,
        server_id: int,
        connection_id: str,
        payload: dict[str, Any],
        headers: dict[str, str],
    ) -> str:
        connection = self.legacy_http_sse_connections.get(connection_id, server_id)
        method = payload.get("method")
        if method == "initialize":
            profile_id = self.era_resolver.resolve(payload, headers)
            profile = self.profiles.get(profile_id)
            if profile.transport_kind != TransportKind.LEGACY_HTTP_SSE:
                raise ProtocolProfileError("legacy_http_sse_revision_required")
            return profile_id
        if connection.profile_id is None:
            raise ProtocolProfileError("legacy_http_sse_connection_not_initialized")
        if headers.get("mcp-session-id"):
            raise ProtocolProfileError("legacy_http_sse_mcp_session_id_unsupported")
        return connection.profile_id

    def _dispatch(
        self,
        *,
        server_id: int,
        payload: dict[str, Any],
        headers: dict[str, str],
        profile_id: str,
    ) -> Response:
        method = payload["method"]
        request_id = payload.get("id")
        profile = self.profiles.get(profile_id)
        if profile.protocol_era == ProtocolEra.LEGACY:
            return self._dispatch_legacy(server_id, payload, headers, profile_id)
        if method == "server/discover":
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "resultType": "complete",
                        "supportedVersions": list(MODERN_PROTOCOL_VERSIONS),
                        "capabilities": {"tools": {}},
                        **modern_cache_fields(MODERN_DISCOVER_CACHE_SCOPE),
                        "_meta": modern_result_meta(),
                    },
                }
            )
        if method == "tools/list":
            metadata_identity, auth_error = self._authenticate_tool_metadata_access(
                headers,
                request_id,
            )
            if auth_error is not None:
                return auth_error
            return self._tools_list_response(
                server_id,
                request_id,
                profile_id,
                metadata_identity.agent_id,
            )
        if method == "tools/call":
            return self._tool_call_response(server_id, payload, headers, profile_id)
        raise ProtocolProfileError("unsupported_mcp_method")

    def _dispatch_legacy_http_sse_post(
        self,
        *,
        server_id: int,
        connection_id: str,
        payload: dict[str, Any],
        headers: dict[str, str],
        profile_id: str,
    ) -> Response:
        connection = self.legacy_http_sse_connections.get(connection_id, server_id)
        method = payload["method"]
        request_id = payload.get("id")
        profile = self.profiles.get(profile_id)
        if profile.transport_kind != TransportKind.LEGACY_HTTP_SSE:
            raise ProtocolProfileError("legacy_http_sse_revision_required")
        if method == "initialize":
            params = payload.get("params") or {}
            if (
                params.get("protocolVersion") != profile.protocol_version
                or not isinstance(params.get("capabilities"), dict)
                or not isinstance(params.get("clientInfo"), dict)
            ):
                raise ProtocolProfileError("legacy_initialize_invalid")
            self.legacy_http_sse_connections.set_profile(
                connection_id,
                server_id,
                protocol_version=profile.protocol_version,
                profile_id=profile.profile_id,
            )
            self.legacy_http_sse_connections.enqueue_jsonrpc(
                connection,
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "protocolVersion": profile.protocol_version,
                        "capabilities": {"tools": {"listChanged": False}},
                        "serverInfo": {
                            "name": "mcp-security-framework-proxy",
                            "version": "0.1.0",
                        },
                    },
                },
            )
            return Response(status_code=202)
        if method == "notifications/initialized":
            self.legacy_http_sse_connections.mark_initialized(connection_id, server_id)
            return Response(status_code=202)
        if not connection.initialized:
            raise ProtocolProfileError("legacy_protocol_session_not_initialized")
        if method == "tools/list":
            metadata_identity, auth_error = self._authenticate_tool_metadata_access(
                headers,
                request_id,
            )
            if auth_error is not None:
                self.legacy_http_sse_connections.enqueue_response(connection, auth_error)
                return Response(status_code=202)
            self.legacy_http_sse_connections.enqueue_response(
                connection,
                self._tools_list_response(
                    server_id,
                    request_id,
                    profile_id,
                    metadata_identity.agent_id,
                ),
            )
            return Response(status_code=202)
        if method == "tools/call":
            self.legacy_http_sse_connections.enqueue_response(
                connection,
                self._tool_call_response(server_id, payload, headers, profile_id),
            )
            return Response(status_code=202)
        raise ProtocolProfileError("unsupported_mcp_method")

    def _dispatch_legacy(
        self,
        server_id: int,
        payload: dict[str, Any],
        headers: dict[str, str],
        profile_id: str,
    ) -> Response:
        method = payload["method"]
        request_id = payload.get("id")
        profile = self.profiles.get(profile_id)
        if profile.transport_kind == TransportKind.LEGACY_HTTP_SSE:
            raise ProtocolProfileError("legacy_http_sse_requires_sse_connection")
        if method == "initialize":
            params = payload.get("params") or {}
            if (
                params.get("protocolVersion") != profile.protocol_version
                or not isinstance(params.get("capabilities"), dict)
                or not isinstance(params.get("clientInfo"), dict)
            ):
                raise ProtocolProfileError("legacy_initialize_invalid")
            session = self.legacy_sessions.create(
                server_id,
                protocol_version=profile.protocol_version,
                profile_id=profile.profile_id,
                transport_kind=profile.transport_kind.value,
            )
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "protocolVersion": profile.protocol_version,
                        "capabilities": {"tools": {"listChanged": False}},
                        "serverInfo": {
                            "name": "mcp-security-framework-proxy",
                            "version": "0.1.0",
                        },
                    },
                },
                headers={"Mcp-Session-Id": session.session_id},
            )

        session_id = headers.get("mcp-session-id")
        if not isinstance(session_id, str) or not session_id:
            raise ProtocolProfileError("legacy_protocol_session_missing")
        session = self.legacy_sessions.get(session_id, server_id)
        if method == "notifications/initialized":
            self.legacy_sessions.mark_initialized(session_id, server_id)
            return Response(status_code=202)
        if not session.initialized:
            raise ProtocolProfileError("legacy_protocol_session_not_initialized")
        if method == "tools/list":
            metadata_identity, auth_error = self._authenticate_tool_metadata_access(
                headers,
                request_id,
            )
            if auth_error is not None:
                return auth_error
            return self._tools_list_response(
                server_id,
                request_id,
                session.profile_id,
                metadata_identity.agent_id,
            )
        if method == "tools/call":
            return self._tool_call_response(server_id, payload, headers, session.profile_id)
        raise ProtocolProfileError("unsupported_mcp_method")

    def _authenticate_tool_metadata_access(
        self,
        headers: dict[str, str],
        request_id: Any,
    ) -> tuple[Any | None, Response | None]:
        authorization = headers.get("authorization", "")
        access_token = authorization[7:] if authorization.lower().startswith("bearer ") else None
        session_token = headers.get("x-mcp-framework-session")
        if not access_token and not session_token:
            return None, _framework_identity_error(request_id)
        try:
            identity = self.proxy.authenticate_framework_identity(
                {
                    "access_token": access_token,
                    "session_token": session_token,
                }
            )
        except Exception:
            return None, _framework_identity_error(request_id)
        return identity, None

    def _approved_tools(
        self,
        server_id: int,
        profile_id: str,
        authenticated_agent_id: str,
    ) -> list[dict[str, Any]]:
        server = self.backend_client.find_server(server_id=server_id)
        if server is None:
            raise BackendClientError("registered_server_missing")
        if protocol_verdict_expired(server):
            return []
        upstream_profile = (
            server.get("preferred_upstream_profile")
            or server.get("preferred_protocol_profile")
            or LEGACY_PROFILE_ID
        )
        snapshot = self.snapshot_resolver.load_active_snapshot()
        authorization = snapshot.get_agent_authorization(authenticated_agent_id)
        granted_capabilities = {
            grant.capability for grant in authorization.grants
        }
        result: list[dict[str, Any]] = []
        for tool in self.backend_client.list_tools():
            if tool.get("server_id") != server_id:
                continue
            profile_tool = self.backend_client.find_tool(
                server_id,
                str(tool.get("name") or ""),
                str(upstream_profile),
            )
            if profile_tool is None:
                continue
            tool = profile_tool
            fingerprint = tool.get("current_fingerprint")
            if not isinstance(fingerprint, str):
                continue
            if not live_review_admissible(tool):
                continue
            try:
                contract = snapshot.get_tool_security_contract(
                    server_ref=server.get("server_ref")
                    or f"{server.get('transport') or 'streamable_http'}:{server.get('endpoint')}",
                    tool_name=str(tool.get("name") or ""),
                )
                required_capabilities = {effect.capability for effect in contract.effects}
                if not required_capabilities <= granted_capabilities:
                    continue
                approval = snapshot.get_tool_observation_approval(
                    server_ref=server.get("server_ref")
                    or f"{server.get('transport') or 'streamable_http'}:{server.get('endpoint')}",
                    upstream_protocol_profile_id=str(upstream_profile),
                    tool_fingerprint=fingerprint,
                )
                if approval.contract_hash != contract.contract_hash:
                    continue
            except PublishedConfigurationError:
                continue
            result.append(tool)
        return result

    def _tools_list_response(
        self,
        server_id: int,
        request_id: Any,
        profile_id: str,
        authenticated_agent_id: str,
    ) -> Response:
        tools = [
            render_tool_definition(tool)
            for tool in self._approved_tools(
                server_id,
                profile_id,
                authenticated_agent_id,
            )
        ]
        result: dict[str, Any] = {"tools": tools}
        if self.profiles.get(profile_id).protocol_era == ProtocolEra.MODERN:
            result["resultType"] = "complete"
            result.update(modern_cache_fields(MODERN_TOOLS_LIST_CACHE_SCOPE))
        return JSONResponse({"jsonrpc": "2.0", "id": request_id, "result": result})

    def _tool_call_response(
        self,
        server_id: int,
        payload: dict[str, Any],
        headers: dict[str, str],
        profile_id: str,
    ) -> Response:
        params = payload.get("params") or {}
        authorization = headers.get("authorization", "")
        access_token = authorization[7:] if authorization.lower().startswith("bearer ") else None
        session_token = headers.get("x-mcp-framework-session")
        if not access_token and not session_token:
            return _jsonrpc_error(payload.get("id"), -32001, "framework_identity_required", 401)
        proxy_result = self.proxy.handle_tool_call(
            {
                "server_id": server_id,
                "tool_name": params.get("name"),
                "arguments": params.get("arguments", {}),
                "access_token": access_token,
                "session_token": session_token,
                "client_protocol_profile_id": profile_id,
            }
        )
        # Decide JSON-RPC success from the full proxy status, never only
        # from executed: remote effects can precede result or audit failures.
        proxy_status = proxy_result.get("status")
        effect_possible = bool(proxy_result.get("mcp_called"))
        # RT-10: give the agent a stable, non-sensitive correlation reference
        # the operator can search in Tool activity. Never echo remote text.
        runtime_log_payload = proxy_result.get("runtime_log")
        operation_id = (
            runtime_log_payload.get("operation_id")
            if isinstance(runtime_log_payload, dict) else None
        )
        reference = {
            "operation_id": operation_id if isinstance(operation_id, str) else None,
            "runtime_log_id": proxy_result.get("runtime_log_id"),
        }
        if proxy_status == "error":
            error_message = (
                "audit_completion_failed"
                if proxy_result.get("execution_status") == "audit_completion_failed"
                else "upstream_execution_failed"
            )
            return _jsonrpc_error(
                payload.get("id"),
                -32004,
                error_message,
                502,
                data={
                    "execution_status": proxy_result.get("execution_status"),
                    "rule_id": proxy_result.get("rule_id"),
                    "effect_possible": effect_possible,
                    "retry_unsafe": effect_possible,
                    **reference,
                },
            )
        if proxy_status == "blocked":
            # A result guard can withhold the response of a call that DID
            # reach the MCP server. Never present that as "not executed".
            withheld = proxy_result.get("execution_status") == "result_blocked"
            return _jsonrpc_error(
                payload.get("id"),
                -32003,
                "tool_result_withheld" if withheld else "tool_call_blocked",
                403,
                data={
                    "rule_id": proxy_result.get("rule_id"),
                    "skip_reason": proxy_result.get("skip_reason"),
                    "reason_code": safe_runtime_error_code(
                        proxy_result.get("skip_reason") or proxy_result.get("rule_id")
                    ),
                    "effect_possible": effect_possible,
                    "retry_unsafe": effect_possible,
                    **reference,
                },
            )
        if proxy_status == "approval_required":
            # RT-07: a deferred (legacy ASK_APPROVAL) decision is never
            # dispatched and there is no runtime approval queue to wait for.
            return _jsonrpc_error(
                payload.get("id"),
                -32003,
                "tool_call_not_dispatched_policy_deferred",
                403,
                data={
                    "rule_id": proxy_result.get("rule_id"),
                    "reason_code": "policy_deferred",
                    "runtime_approval_workflow": False,
                    "effect_possible": effect_possible,
                    "retry_unsafe": effect_possible,
                    **reference,
                },
            )
        if (
            proxy_status != "allowed"
            or not proxy_result.get("executed")
            or not isinstance(proxy_result.get("tool_result"), dict)
        ):
            return _jsonrpc_error(
                payload.get("id"),
                -32004,
                "proxy_result_state_invalid",
                502,
                data={"effect_possible": effect_possible},
            )
        result = dict(proxy_result.get("tool_result") or {})
        if self.profiles.get(profile_id).protocol_era == ProtocolEra.MODERN:
            result["resultType"] = "complete"
        else:
            result.pop("resultType", None)
        return JSONResponse({"jsonrpc": "2.0", "id": payload.get("id"), "result": result})


def create_gateway_app(**kwargs: Any) -> FastAPI:
    return MCPGateway(**kwargs).create_app()


def _validate_jsonrpc_envelope(payload: dict[str, Any]) -> None:
    if payload.get("jsonrpc") != "2.0":
        raise ProtocolProfileError("jsonrpc_version_invalid")
    method = payload.get("method")
    if not isinstance(method, str) or not method:
        raise ProtocolProfileError("jsonrpc_method_invalid")
    if method != "notifications/initialized" and "id" not in payload:
        raise ProtocolProfileError("jsonrpc_id_missing")
    if set(payload) - {"jsonrpc", "id", "method", "params"}:
        raise ProtocolProfileError("jsonrpc_unknown_top_level_field")


def _strict_request_headers(request: Request) -> dict[str, str]:
    protected = {
        "content-type",
        "authorization",
        "mcp-protocol-version",
        "mcp-method",
        "mcp-name",
        "mcp-session-id",
        "origin",
        "x-mcp-framework-session",
    }
    headers: dict[str, str] = {}
    counts: dict[str, int] = {}
    for raw_name, raw_value in request.scope.get("headers", ()):
        try:
            name = raw_name.decode("ascii").lower()
            value = raw_value.decode("latin-1")
        except UnicodeDecodeError as exc:
            raise ProtocolProfileError("request_header_encoding_invalid") from exc
        counts[name] = counts.get(name, 0) + 1
        if name in protected and counts[name] > 1:
            raise ProtocolProfileError("duplicate_protected_header")
        headers[name] = value
    return headers


async def _read_bounded_json_body(request: Request) -> bytes:
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            length = int(content_length)
        except ValueError as exc:
            raise StrictJSONError("json_content_length_invalid") from exc
        if length > MAX_JSON_BYTES:
            raise StrictJSONError("json_body_empty_or_too_large")

    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        if not chunk:
            continue
        total += len(chunk)
        if total > MAX_JSON_BYTES:
            raise StrictJSONError("json_body_empty_or_too_large")
        chunks.append(chunk)
    return b"".join(chunks)


def _jsonrpc_error(
    request_id: Any,
    code: int,
    message: str,
    status_code: int,
    *,
    data: dict[str, Any] | None = None,
) -> JSONResponse:
    error: dict[str, Any] = {"code": code, "message": message}
    if data:
        error["data"] = data
    return JSONResponse(
        {"jsonrpc": "2.0", "id": request_id, "error": error},
        status_code=status_code,
    )


def _framework_identity_error(request_id: Any) -> JSONResponse:
    return _jsonrpc_error(request_id, -32001, "framework_identity_required", 401)
