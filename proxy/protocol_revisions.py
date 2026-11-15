from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Mapping

from mcp_types import methods as mcp_methods
from mcp_types.version import (
    HANDSHAKE_PROTOCOL_VERSIONS as OFFICIAL_HANDSHAKE_PROTOCOL_VERSIONS,
    KNOWN_PROTOCOL_VERSIONS as OFFICIAL_KNOWN_PROTOCOL_VERSIONS,
    MODERN_PROTOCOL_VERSIONS as OFFICIAL_MODERN_PROTOCOL_VERSIONS,
)


class ProtocolRevisionError(Exception):
    """Raised when protocol revision validation cannot proceed safely."""


class ProtocolEra(str, Enum):
    LEGACY = "legacy"
    MODERN = "modern"


class TransportKind(str, Enum):
    LEGACY_HTTP_SSE = "legacy_http_sse"
    LEGACY_STREAMABLE_HTTP = "legacy_streamable_http"
    MODERN_STREAMABLE_HTTP = "modern_streamable_http"


class LifecycleKind(str, Enum):
    INITIALIZE = "initialize"
    PER_REQUEST = "per_request"


def restricted_profile_id(era: ProtocolEra, version: str) -> str:
    return f"mcp-{era.value}-{version}-restricted-v1"


@dataclass(frozen=True)
class ProtocolRevisionDescriptor:
    version: str
    era: ProtocolEra
    schema_family: str
    lifecycle_kind: LifecycleKind
    supported_transport_kinds: tuple[TransportKind, ...]
    framework_enabled: bool
    framework_profile_id: str
    introduced_features: tuple[str, ...] = ()
    notes: str = ""

    @property
    def default_transport_kind(self) -> TransportKind:
        return self.supported_transport_kinds[0]


FRAMEWORK_REVISION_DESCRIPTORS: tuple[ProtocolRevisionDescriptor, ...] = (
    ProtocolRevisionDescriptor(
        version="2024-11-05",
        era=ProtocolEra.LEGACY,
        schema_family="2025-11-25",
        lifecycle_kind=LifecycleKind.INITIALIZE,
        supported_transport_kinds=(TransportKind.LEGACY_HTTP_SSE,),
        framework_enabled=True,
        framework_profile_id=restricted_profile_id(ProtocolEra.LEGACY, "2024-11-05"),
        notes="Legacy initialize era over the deprecated HTTP+SSE transport.",
    ),
    ProtocolRevisionDescriptor(
        version="2025-03-26",
        era=ProtocolEra.LEGACY,
        schema_family="2025-11-25",
        lifecycle_kind=LifecycleKind.INITIALIZE,
        supported_transport_kinds=(TransportKind.LEGACY_STREAMABLE_HTTP,),
        framework_enabled=True,
        framework_profile_id=restricted_profile_id(ProtocolEra.LEGACY, "2025-03-26"),
        notes="Legacy initialize era over Streamable HTTP.",
    ),
    ProtocolRevisionDescriptor(
        version="2025-06-18",
        era=ProtocolEra.LEGACY,
        schema_family="2025-11-25",
        lifecycle_kind=LifecycleKind.INITIALIZE,
        supported_transport_kinds=(TransportKind.LEGACY_STREAMABLE_HTTP,),
        framework_enabled=True,
        framework_profile_id=restricted_profile_id(ProtocolEra.LEGACY, "2025-06-18"),
        introduced_features=("elicitation",),
        notes="Legacy initialize era over Streamable HTTP.",
    ),
    ProtocolRevisionDescriptor(
        version="2025-11-25",
        era=ProtocolEra.LEGACY,
        schema_family="2025-11-25",
        lifecycle_kind=LifecycleKind.INITIALIZE,
        supported_transport_kinds=(TransportKind.LEGACY_STREAMABLE_HTTP,),
        framework_enabled=True,
        framework_profile_id=restricted_profile_id(ProtocolEra.LEGACY, "2025-11-25"),
        introduced_features=("tasks_extension_surface",),
        notes="Newest initialize-handshake revision currently enabled.",
    ),
    ProtocolRevisionDescriptor(
        version="2026-07-28",
        era=ProtocolEra.MODERN,
        schema_family="2026-07-28",
        lifecycle_kind=LifecycleKind.PER_REQUEST,
        supported_transport_kinds=(TransportKind.MODERN_STREAMABLE_HTTP,),
        framework_enabled=True,
        framework_profile_id=restricted_profile_id(ProtocolEra.MODERN, "2026-07-28"),
        introduced_features=("server/discover", "per_request_metadata", "mrtr"),
        notes="Modern stateless per-request revision.",
    ),
)

KNOWN_HISTORICAL_UNSUPPORTED_REVISIONS = frozenset({"2024-10-07"})
FRAMEWORK_SUPPORTED_VERSIONS = tuple(
    descriptor.version
    for descriptor in FRAMEWORK_REVISION_DESCRIPTORS
    if descriptor.framework_enabled
)
LEGACY_FRAMEWORK_SUPPORTED_VERSIONS = tuple(
    descriptor.version
    for descriptor in FRAMEWORK_REVISION_DESCRIPTORS
    if descriptor.framework_enabled and descriptor.era == ProtocolEra.LEGACY
)
MODERN_FRAMEWORK_SUPPORTED_VERSIONS = tuple(
    descriptor.version
    for descriptor in FRAMEWORK_REVISION_DESCRIPTORS
    if descriptor.framework_enabled and descriptor.era == ProtocolEra.MODERN
)


class ProtocolRevisionRegistry:
    """Framework-owned allowlist of MCP revisions.

    The official mcp-types registry is an input to validation, not a source of
    automatic trust expansion. Future mcp-types releases may know more protocol
    strings; this registry still controls what the framework enables.
    """

    def __init__(
        self,
        descriptors: tuple[ProtocolRevisionDescriptor, ...] = FRAMEWORK_REVISION_DESCRIPTORS,
    ) -> None:
        self._descriptors_by_version = {descriptor.version: descriptor for descriptor in descriptors}
        self._descriptors_by_profile_id = {
            descriptor.framework_profile_id: descriptor for descriptor in descriptors
        }
        self.assert_framework_supported_by_official()

    @property
    def official_known_versions(self) -> tuple[str, ...]:
        return tuple(OFFICIAL_KNOWN_PROTOCOL_VERSIONS)

    def assert_framework_supported_by_official(self) -> None:
        missing = [
            descriptor.version
            for descriptor in self._descriptors_by_version.values()
            if descriptor.framework_enabled
            and descriptor.version not in OFFICIAL_KNOWN_PROTOCOL_VERSIONS
        ]
        if missing:
            raise ProtocolRevisionError(
                f"framework_protocol_revision_not_in_official_registry:{','.join(missing)}"
            )
        legacy_mismatch = [
            descriptor.version
            for descriptor in self._descriptors_by_version.values()
            if descriptor.framework_enabled
            and descriptor.era == ProtocolEra.LEGACY
            and descriptor.version not in OFFICIAL_HANDSHAKE_PROTOCOL_VERSIONS
        ]
        modern_mismatch = [
            descriptor.version
            for descriptor in self._descriptors_by_version.values()
            if descriptor.framework_enabled
            and descriptor.era == ProtocolEra.MODERN
            and descriptor.version not in OFFICIAL_MODERN_PROTOCOL_VERSIONS
        ]
        if legacy_mismatch or modern_mismatch:
            raise ProtocolRevisionError("framework_protocol_era_registry_mismatch")

    def get(self, version: str) -> ProtocolRevisionDescriptor:
        try:
            return self._descriptors_by_version[version]
        except KeyError as exc:
            raise ProtocolRevisionError("unsupported_mcp_protocol_revision") from exc

    def get_by_profile_id(self, profile_id: str) -> ProtocolRevisionDescriptor:
        try:
            return self._descriptors_by_profile_id[profile_id]
        except KeyError as exc:
            raise ProtocolRevisionError("unsupported_mcp_protocol_profile") from exc

    def is_known(self, version: str) -> bool:
        return (
            version in self._descriptors_by_version
            or version in KNOWN_HISTORICAL_UNSUPPORTED_REVISIONS
        )

    def is_framework_supported(self, version: str) -> bool:
        descriptor = self._descriptors_by_version.get(version)
        return descriptor is not None and descriptor.framework_enabled

    def profile_id_for_version(self, version: str) -> str:
        descriptor = self.get(version)
        if not descriptor.framework_enabled:
            raise ProtocolRevisionError("unsupported_mcp_protocol_revision")
        return descriptor.framework_profile_id

    def version_for_profile_id(self, profile_id: str) -> str:
        return self.get_by_profile_id(profile_id).version

    def legacy_versions_preference_order(self) -> tuple[str, ...]:
        return tuple(reversed(LEGACY_FRAMEWORK_SUPPORTED_VERSIONS))

    def modern_versions_preference_order(self) -> tuple[str, ...]:
        return tuple(reversed(MODERN_FRAMEWORK_SUPPORTED_VERSIONS))

    def versions_for_transport(self, transport: TransportKind) -> tuple[str, ...]:
        return tuple(
            descriptor.version
            for descriptor in self._descriptors_by_version.values()
            if descriptor.framework_enabled and transport in descriptor.supported_transport_kinds
        )

    def mutually_supported_modern_version(self, peer_versions: list[str]) -> str | None:
        peer = set(peer_versions)
        for version in self.modern_versions_preference_order():
            if version in peer:
                return version
        return None


class OfficialMCPWireValidator:
    """Small fail-closed adapter around public mcp-types APIs."""

    def validate_client_request(
        self,
        *,
        method: str,
        version: str,
        params: Mapping[str, Any] | None,
    ) -> None:
        try:
            mcp_methods.validate_client_request(method, version, params)
        except Exception as exc:
            raise ProtocolRevisionError("official_client_request_invalid") from exc

    def validate_client_notification(
        self,
        *,
        method: str,
        version: str,
        params: Mapping[str, Any] | None,
    ) -> None:
        try:
            mcp_methods.validate_client_notification(method, version, params)
        except Exception as exc:
            raise ProtocolRevisionError("official_client_notification_invalid") from exc

    def validate_server_result(
        self,
        *,
        method: str,
        version: str,
        result: Mapping[str, Any],
    ) -> None:
        try:
            mcp_methods.validate_server_result(method, version, result)
        except Exception as exc:
            raise ProtocolRevisionError("official_server_result_invalid") from exc

    def serialize_server_result(
        self,
        *,
        method: str,
        version: str,
        result: Mapping[str, Any],
    ) -> dict[str, Any]:
        try:
            return mcp_methods.serialize_server_result(method, version, result)
        except Exception as exc:
            raise ProtocolRevisionError("official_server_result_invalid") from exc

    def method_defined(self, *, method: str, version: str) -> bool:
        if version not in OFFICIAL_KNOWN_PROTOCOL_VERSIONS:
            return False
        return (method, version) in mcp_methods.CLIENT_REQUESTS or (
            method,
            version,
        ) in mcp_methods.CLIENT_NOTIFICATIONS


class RestrictedMethodSurface:
    GOVERNED_METHODS = frozenset({"tools/list", "tools/call"})
    LEGACY_CONTROL_METHODS = frozenset({"initialize", "notifications/initialized"})
    MODERN_CONTROL_METHODS = frozenset({"server/discover"})
    UNSUPPORTED_FEATURE_PREFIXES = (
        "resources/",
        "prompts/",
        "sampling/",
        "elicitation/",
        "tasks/",
        "subscriptions/",
        "completion/",
        "logging/",
        "roots/",
        "ping",
    )

    def supported_methods_for(self, descriptor: ProtocolRevisionDescriptor) -> frozenset[str]:
        if descriptor.era == ProtocolEra.LEGACY:
            return self.GOVERNED_METHODS | self.LEGACY_CONTROL_METHODS
        return self.GOVERNED_METHODS | self.MODERN_CONTROL_METHODS

    def is_framework_supported(self, *, method: str, descriptor: ProtocolRevisionDescriptor) -> bool:
        return method in self.supported_methods_for(descriptor)

    def rejection_code_for(self, method: str) -> str:
        if method.startswith(self.UNSUPPORTED_FEATURE_PREFIXES):
            return "restricted_method_surface_unsupported_feature"
        return "unsupported_mcp_method"


@dataclass(frozen=True)
class NegotiatedProtocol:
    server_ref: str
    era: ProtocolEra
    protocol_version: str
    transport_kind: TransportKind
    negotiation_source: str
    negotiated_at: datetime
    fresh_until: datetime
    server_supported_versions: tuple[str, ...] = ()
    from_cache: bool = False
    evidence: str = "unknown"

    @property
    def framework_profile_id(self) -> str:
        return restricted_profile_id(self.era, self.protocol_version)


def negotiated_now(
    *,
    server_ref: str,
    descriptor: ProtocolRevisionDescriptor,
    negotiation_source: str,
    ttl_seconds: int,
    server_supported_versions: tuple[str, ...] = (),
    evidence: str,
    transport_kind: TransportKind | None = None,
) -> NegotiatedProtocol:
    now = datetime.now(timezone.utc)
    return NegotiatedProtocol(
        server_ref=server_ref,
        era=descriptor.era,
        protocol_version=descriptor.version,
        transport_kind=transport_kind or descriptor.default_transport_kind,
        negotiation_source=negotiation_source,
        negotiated_at=now,
        fresh_until=now + timedelta(seconds=ttl_seconds),
        server_supported_versions=server_supported_versions,
        evidence=evidence,
    )


def recognized_modern_error(message: Mapping[str, Any]) -> bool:
    error = message.get("error")
    if not isinstance(error, Mapping):
        return False
    code = error.get("code")
    if code in {-32020, -32021, -32022}:
        return True
    data = error.get("data")
    return code == -32022 and isinstance(data, Mapping) and isinstance(data.get("supported"), list)


def supported_versions_from_modern_error(message: Mapping[str, Any]) -> list[str]:
    error = message.get("error")
    if not isinstance(error, Mapping):
        return []
    data = error.get("data")
    if not isinstance(data, Mapping):
        return []
    supported = data.get("supported")
    if not isinstance(supported, list):
        return []
    return [value for value in supported if isinstance(value, str)]
