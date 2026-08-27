from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from common.canonical_json import canonical_json_bytes
from common.mcp_endpoint import MCPEndpointValidationError, validate_mcp_endpoint
from proxy.mcp_transport import (
    LegacyHTTPSSETransport,
    StreamableHTTPResponseDecoder,
    TransportHTTPError,
    TransportProtocolError,
)
from proxy.protocol_profiles import (
    LEGACY_PROFILE_ID,
    LEGACY_PROTOCOL_VERSION,
    MODERN_PROFILE_ID,
    MODERN_PROTOCOL_VERSION,
    ProtocolProfileError,
    ProtocolProfileRegistry,
)
from proxy.protocol_revisions import (
    ProtocolEra,
    ProtocolRevisionRegistry,
    TransportKind,
    recognized_modern_error,
    supported_versions_from_modern_error,
)
from proxy.strict_json import StrictJSONError, parse_strict_json


MAX_PROBE_RESPONSE_BYTES = 262_144
DEFAULT_PROBE_TIMEOUT_SECONDS = 3.0
DEFAULT_REDISCOVERY_INTERVAL_SECONDS = 900
MCP_ACCEPT_HEADER = "application/json, text/event-stream"
MCP_CLIENT_USER_AGENT = "MCP-Security-Framework/1.0"


class ProtocolNegotiationError(Exception):
    """Raised when an MCP endpoint cannot be safely probed."""


@dataclass(frozen=True)
class ProtocolNegotiationResult:
    supported_protocol_profiles: tuple[str, ...]
    preferred_upstream_profile: str
    protocol_version: str
    probe_status: str
    probe_error: str | None
    last_probe_at: datetime
    supported_protocol_versions: tuple[str, ...] = ()
    preferred_protocol_version: str | None = None
    negotiated_protocol_version: str | None = None
    transport_kind: str | None = None
    detected_era: str | None = None
    protocol_verdict_expires_at: datetime | None = None


@dataclass(frozen=True)
class _Probe:
    profile_id: str | None = None
    version: str | None = None
    transport_kind: TransportKind | None = None
    supported_versions: tuple[str, ...] = ()
    error: str | None = None
    terminal: bool = False
    sse_post_endpoint: str | None = None

    @property
    def success(self) -> bool:
        return self.profile_id is not None and self.version is not None


class NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: N802
        return None


class ProtocolNegotiator:
    def __init__(
        self,
        *,
        timeout_seconds: float = DEFAULT_PROBE_TIMEOUT_SECONDS,
        max_response_bytes: int = MAX_PROBE_RESPONSE_BYTES,
        allow_local_lab: bool = True,
        bearer_token: str | None = None,
    ) -> None:
        self.timeout_seconds = timeout_seconds
        self.max_response_bytes = max_response_bytes
        self.allow_local_lab = allow_local_lab
        self._upstream_headers = {"User-Agent": MCP_CLIENT_USER_AGENT}
        if bearer_token:
            self._upstream_headers["Authorization"] = f"Bearer {bearer_token}"
        self._opener = build_opener(NoRedirectHandler)
        self.revision_registry = ProtocolRevisionRegistry()
        self.profile_registry = ProtocolProfileRegistry()

    def negotiate(self, *, endpoint: str, registered_endpoint: str) -> ProtocolNegotiationResult:
        if endpoint != registered_endpoint:
            raise ProtocolNegotiationError("endpoint_not_registered")
        self._validate_endpoint(endpoint)
        now = datetime.now(timezone.utc)

        modern = self._probe_modern(endpoint)
        if modern.terminal and not modern.success:
            raise ProtocolNegotiationError(f"modern_probe_failed_closed:{modern.error}")

        legacy_streamable_probes, legacy_streamable_error, legacy_streamable_terminal = (
            self._probe_legacy_streamable(endpoint)
        )
        if legacy_streamable_terminal and not legacy_streamable_probes and not modern.success:
            raise ProtocolNegotiationError(
                f"legacy_streamable_probe_failed_closed:{legacy_streamable_error}"
            )

        legacy_sse = _Probe(error="legacy_sse_not_probed")
        if not legacy_streamable_probes:
            legacy_sse = self._probe_legacy_http_sse(endpoint)
            if legacy_sse.terminal and not legacy_sse.success and not modern.success:
                raise ProtocolNegotiationError(f"legacy_sse_probe_failed_closed:{legacy_sse.error}")

        probes = [probe for probe in (modern, *legacy_streamable_probes, legacy_sse) if probe.success]
        if not probes:
            raise ProtocolNegotiationError(
                "unsupported_mcp_protocol: "
                f"modern={modern.error}; "
                f"legacy_streamable={legacy_streamable_error}; "
                f"legacy_sse={legacy_sse.error}"
            )
        probes = self._dedupe_probes(probes)

        modern_profiles = [probe for probe in probes if self._profile_era(probe) == ProtocolEra.MODERN]
        legacy_profiles = [probe for probe in probes if self._profile_era(probe) == ProtocolEra.LEGACY]
        preferred = modern_profiles[0] if modern_profiles else legacy_profiles[0]
        supported_profiles = tuple(probe.profile_id for probe in probes if probe.profile_id)
        supported_versions = tuple(probe.version for probe in probes if probe.version)
        status = (
            "dual_supported"
            if modern_profiles and legacy_profiles
            else "modern_supported"
            if modern_profiles
            else "legacy_supported"
        )
        return ProtocolNegotiationResult(
            supported_protocol_profiles=supported_profiles,
            preferred_upstream_profile=str(preferred.profile_id),
            protocol_version=str(preferred.version),
            probe_status=status,
            probe_error=None,
            last_probe_at=now,
            supported_protocol_versions=supported_versions,
            preferred_protocol_version=str(preferred.version),
            negotiated_protocol_version=str(preferred.version),
            transport_kind=preferred.transport_kind.value if preferred.transport_kind else None,
            detected_era=self._profile_era(preferred).value,
            protocol_verdict_expires_at=now
            + timedelta(seconds=DEFAULT_REDISCOVERY_INTERVAL_SECONDS),
        )

    def _profile_era(self, probe: _Probe) -> ProtocolEra:
        if not probe.profile_id:
            raise ProtocolNegotiationError("probe_profile_missing")
        return self.profile_registry.get(probe.profile_id).protocol_era

    def _validate_endpoint(self, endpoint: str) -> None:
        try:
            validate_mcp_endpoint(endpoint)
        except MCPEndpointValidationError as exc:
            raise ProtocolNegotiationError(str(exc)) from exc

    def _probe_modern(self, endpoint: str) -> _Probe:
        version = self.revision_registry.modern_versions_preference_order()[0]
        profile = self.profile_registry.get_by_version(version)
        payload, profile_headers = profile.serialize_request(
            request_id=1,
            method="server/discover",
            params={},
        )
        result, error, message = self._probe_json(endpoint, payload, profile_headers)
        if error is not None:
            if message is not None and recognized_modern_error(message):
                supported = tuple(supported_versions_from_modern_error(message))
                return _Probe(
                    error="recognized_modern_protocol_error",
                    supported_versions=supported,
                    terminal=True,
                )
            return _Probe(error=error, terminal=self._probe_error_is_terminal(error))
        assert result is not None
        supported_versions = tuple(
            value for value in result.get("supportedVersions", ()) if isinstance(value, str)
        )
        negotiated = self.revision_registry.mutually_supported_modern_version(
            list(supported_versions)
        )
        if negotiated is None:
            return _Probe(
                error="no_mutual_modern_revision",
                supported_versions=supported_versions,
                terminal=True,
            )
        negotiated_profile = self.profile_registry.get_by_version(negotiated)
        try:
            negotiated_profile.validate_discover_result(result)
        except ProtocolProfileError:
            return _Probe(
                error="modern_discover_result_invalid",
                supported_versions=supported_versions,
                terminal=True,
            )
        return _Probe(
            profile_id=negotiated_profile.profile_id,
            version=negotiated,
            transport_kind=TransportKind.MODERN_STREAMABLE_HTTP,
            supported_versions=supported_versions,
        )

    def _probe_legacy_streamable(self, endpoint: str) -> tuple[tuple[_Probe, ...], str, bool]:
        last_error = "legacy_streamable_not_supported"
        probes: list[_Probe] = []
        for version in self.revision_registry.legacy_versions_preference_order():
            descriptor = self.revision_registry.get(version)
            if TransportKind.LEGACY_STREAMABLE_HTTP not in descriptor.supported_transport_kinds:
                continue
            payload = self._legacy_initialize_payload(version)
            result, error, _message = self._probe_json(endpoint, payload, {})
            if error is not None:
                last_error = error
                if self._probe_error_is_terminal(error):
                    return tuple(probes), error, True
                continue
            assert result is not None
            negotiated = result.get("protocolVersion") or version
            if not isinstance(negotiated, str):
                return tuple(probes), "legacy_protocol_version_missing", True
            if not self.revision_registry.is_framework_supported(negotiated):
                return tuple(probes), "unsupported_legacy_counter_offer", True
            negotiated_descriptor = self.revision_registry.get(negotiated)
            if (
                negotiated_descriptor.era != ProtocolEra.LEGACY
                or TransportKind.LEGACY_STREAMABLE_HTTP
                not in negotiated_descriptor.supported_transport_kinds
            ):
                return tuple(probes), "legacy_transport_revision_mismatch", True
            profile = self.profile_registry.get_by_version(negotiated)
            try:
                profile.validate_initialize_result(result)
            except ProtocolProfileError:
                return tuple(probes), "legacy_initialize_result_invalid", True
            probes.append(
                _Probe(
                    profile_id=profile.profile_id,
                    version=negotiated,
                    transport_kind=TransportKind.LEGACY_STREAMABLE_HTTP,
                    supported_versions=(negotiated,),
                )
            )
        return tuple(self._dedupe_probes(probes)), last_error, False

    def _probe_legacy_http_sse(self, endpoint: str) -> _Probe:
        descriptor = self.revision_registry.get("2024-11-05")
        payload = self._legacy_initialize_payload(descriptor.version)
        transport = LegacyHTTPSSETransport(
            sse_endpoint=endpoint,
            timeout_seconds=self.timeout_seconds,
            opener=self._opener,
            connection_headers=self._upstream_headers,
        )
        try:
            message = transport.post_json(
                payload,
                headers={"Accept": MCP_ACCEPT_HEADER, "Content-Type": "application/json"},
            )
        except (TransportHTTPError, TransportProtocolError) as exc:
            return _Probe(error=str(exc), terminal=self._probe_error_is_terminal(str(exc)))
        finally:
            transport.close()
        if message.get("error"):
            return _Probe(error="legacy_sse_jsonrpc_error", terminal=True)
        result = message.get("result")
        if not isinstance(result, dict):
            return _Probe(error="legacy_sse_result_missing", terminal=True)
        negotiated = result.get("protocolVersion") or descriptor.version
        if negotiated != descriptor.version:
            return _Probe(error="legacy_sse_protocol_version_mismatch", terminal=True)
        profile = self.profile_registry.get_by_version(descriptor.version)
        try:
            profile.validate_initialize_result(result)
        except ProtocolProfileError:
            return _Probe(error="legacy_sse_initialize_result_invalid", terminal=True)
        return _Probe(
            profile_id=profile.profile_id,
            version=descriptor.version,
            transport_kind=TransportKind.LEGACY_HTTP_SSE,
            supported_versions=(descriptor.version,),
            sse_post_endpoint=transport.post_endpoint,
        )

    def _legacy_initialize_payload(self, version: str) -> dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": version,
                "capabilities": {},
                "clientInfo": {
                    "name": "mcp-security-framework-probe",
                    "version": "0.1.0",
                },
            },
        }

    def _probe_json(
        self,
        endpoint: str,
        payload: dict[str, Any],
        headers: dict[str, str],
    ) -> tuple[dict[str, Any] | None, str | None, dict[str, Any] | None]:
        request_headers = {
            "Accept": MCP_ACCEPT_HEADER,
            "Content-Type": "application/json",
            **headers,
            **self._upstream_headers,
        }
        body = canonical_json_bytes(payload)
        request = Request(endpoint, data=body, headers=request_headers, method="POST")
        try:
            with self._opener.open(request, timeout=self.timeout_seconds) as response:
                decoder = StreamableHTTPResponseDecoder(
                    expected_request_id=payload.get("id"),
                    max_response_bytes=self.max_response_bytes,
                )
                message = decoder.decode(response)
        except HTTPError as exc:
            content = exc.read(self.max_response_bytes + 1)
            message = self._parse_optional_json_message(content)
            return None, f"http_{exc.code}", message
        except TimeoutError:
            return None, "probe_timeout", None
        except TransportProtocolError as exc:
            return None, str(exc), None
        except URLError as exc:
            reason = getattr(exc, "reason", None)
            if isinstance(reason, TimeoutError):
                return None, "probe_timeout", None
            return None, "probe_network_error", None
        except OSError:
            return None, "probe_network_error", None
        if message.get("error"):
            return None, "probe_jsonrpc_error", message
        result = message.get("result")
        if not isinstance(result, dict):
            return None, "probe_result_missing", message
        return result, None, message

    def _parse_optional_json_message(self, content: bytes) -> dict[str, Any] | None:
        if not content or len(content) > self.max_response_bytes:
            return None
        try:
            message = parse_strict_json(content)
        except StrictJSONError:
            return None
        return message if isinstance(message, dict) else None

    def _dedupe_probes(self, probes: list[_Probe] | tuple[_Probe, ...]) -> tuple[_Probe, ...]:
        seen: set[str] = set()
        deduped: list[_Probe] = []
        for probe in probes:
            if not probe.profile_id or probe.profile_id in seen:
                continue
            seen.add(probe.profile_id)
            deduped.append(probe)
        return tuple(deduped)

    def _probe_error_is_terminal(self, error: str) -> bool:
        if error == "probe_timeout":
            return True
        if error in {"http_401", "http_403"}:
            return True
        if error.startswith("http_5"):
            return True
        if error in {
            "probe_response_too_large",
            "probe_response_invalid_json",
            "probe_result_missing",
        }:
            return True
        return False


def protocol_rediscovery_due(
    last_probe_at: datetime | None,
    *,
    interval_seconds: int = DEFAULT_REDISCOVERY_INTERVAL_SECONDS,
    now: datetime | None = None,
) -> bool:
    if interval_seconds <= 0:
        raise ValueError("rediscovery_interval_invalid")
    if last_probe_at is None:
        return True
    current = now or (
        datetime.now(last_probe_at.tzinfo)
        if last_probe_at.tzinfo is not None
        else datetime.utcnow()
    )
    return current >= last_probe_at + timedelta(seconds=interval_seconds)
