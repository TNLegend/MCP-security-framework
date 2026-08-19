from __future__ import annotations

import base64
from dataclasses import dataclass, field
from typing import Any

from common.canonical_json import canonical_json_bytes, sha256_canonical_json
from proxy.protocol_revisions import (
    FRAMEWORK_SUPPORTED_VERSIONS,
    LEGACY_FRAMEWORK_SUPPORTED_VERSIONS,
    MODERN_FRAMEWORK_SUPPORTED_VERSIONS,
    OfficialMCPWireValidator,
    ProtocolEra,
    ProtocolRevisionDescriptor,
    ProtocolRevisionError,
    ProtocolRevisionRegistry,
    RestrictedMethodSurface,
    TransportKind,
    restricted_profile_id,
)


MODERN_PROFILE_ID = "mcp-modern-2026-07-28-restricted-v1"
LEGACY_PROFILE_ID = "mcp-legacy-2025-11-25-restricted-v1"
MODERN_PROTOCOL_VERSION = "2026-07-28"
LEGACY_PROTOCOL_VERSION = "2025-11-25"
SUPPORTED_MCP_PROTOCOL_VERSIONS = FRAMEWORK_SUPPORTED_VERSIONS
LEGACY_PROTOCOL_VERSIONS = LEGACY_FRAMEWORK_SUPPORTED_VERSIONS
MODERN_PROTOCOL_VERSIONS = MODERN_FRAMEWORK_SUPPORTED_VERSIONS
LEGACY_2024_11_05_PROFILE_ID = restricted_profile_id(ProtocolEra.LEGACY, "2024-11-05")
LEGACY_2025_03_26_PROFILE_ID = restricted_profile_id(ProtocolEra.LEGACY, "2025-03-26")
LEGACY_2025_06_18_PROFILE_ID = restricted_profile_id(ProtocolEra.LEGACY, "2025-06-18")
LEGACY_2025_11_25_PROFILE_ID = LEGACY_PROFILE_ID
MODERN_2026_07_28_PROFILE_ID = MODERN_PROFILE_ID
MODERN_META_PROTOCOL_VERSION = "io.modelcontextprotocol/protocolVersion"
MODERN_META_CLIENT_CAPABILITIES = "io.modelcontextprotocol/clientCapabilities"
MODERN_META_CLIENT_INFO = "io.modelcontextprotocol/clientInfo"
MODERN_META_SERVER_INFO = "io.modelcontextprotocol/serverInfo"
MODERN_PROXY_NAME = "mcp-security-framework-proxy"
MODERN_PROXY_VERSION = "0.1.0"
MODERN_CACHE_TTL_MS = 0
MODERN_DISCOVER_CACHE_SCOPE = "public"
MODERN_TOOLS_LIST_CACHE_SCOPE = "private"
MODERN_ALLOWED_META_KEYS = frozenset(
    {
        MODERN_META_PROTOCOL_VERSION,
        MODERN_META_CLIENT_CAPABILITIES,
        MODERN_META_CLIENT_INFO,
    }
)


class ProtocolProfileError(Exception):
    """Raised when an MCP message violates the selected restricted profile."""


@dataclass(frozen=True)
class CanonicalToolDefinition:
    name: str
    description: str
    input_schema: dict[str, Any]
    output_schema: dict[str, Any] | None = None
    annotations: dict[str, Any] = field(default_factory=dict)
    source_profile_id: str = LEGACY_PROFILE_ID
    protocol_era: str = ProtocolEra.LEGACY.value
    protocol_version: str = LEGACY_PROTOCOL_VERSION
    transport_kind: str = TransportKind.LEGACY_STREAMABLE_HTTP.value


@dataclass(frozen=True)
class NormalizedToolCall:
    server_ref: str
    tool_name: str
    canonical_args: dict[str, Any]
    canonical_args_hash: str
    client_protocol_profile_id: str
    upstream_protocol_profile_id: str
    request_id: str
    client_protocol_era: str = ProtocolEra.LEGACY.value
    client_protocol_version: str = LEGACY_PROTOCOL_VERSION
    client_transport_kind: str = TransportKind.LEGACY_STREAMABLE_HTTP.value
    upstream_protocol_era: str = ProtocolEra.LEGACY.value
    upstream_protocol_version: str = LEGACY_PROTOCOL_VERSION
    upstream_transport_kind: str = TransportKind.LEGACY_STREAMABLE_HTTP.value
    agent_context: dict[str, Any] = field(default_factory=dict)
    session_context: dict[str, Any] = field(default_factory=dict)
    tool_observation: dict[str, Any] = field(default_factory=dict)
    current_fingerprint: str | None = None


class RestrictedProtocolProfile:
    profile_id = ""
    protocol_version = ""
    supported_methods: frozenset[str] = frozenset()
    descriptor: ProtocolRevisionDescriptor | None = None

    def __init__(self, descriptor: ProtocolRevisionDescriptor | None = None) -> None:
        self.wire_validator = OfficialMCPWireValidator()
        self.method_surface = RestrictedMethodSurface()
        if descriptor is not None:
            self.descriptor = descriptor
            self.profile_id = descriptor.framework_profile_id
            self.protocol_version = descriptor.version
            self.supported_methods = self.method_surface.supported_methods_for(descriptor)

    @property
    def protocol_era(self) -> ProtocolEra:
        if self.descriptor is None:
            return ProtocolEra.MODERN if self.profile_id == MODERN_PROFILE_ID else ProtocolEra.LEGACY
        return self.descriptor.era

    @property
    def transport_kind(self) -> TransportKind:
        if self.descriptor is None:
            if self.profile_id == MODERN_PROFILE_ID:
                return TransportKind.MODERN_STREAMABLE_HTTP
            return TransportKind.LEGACY_STREAMABLE_HTTP
        return self.descriptor.default_transport_kind

    def normalize_tool_definition(self, raw_tool: dict[str, Any]) -> CanonicalToolDefinition:
        if not isinstance(raw_tool, dict):
            raise ProtocolProfileError("tool_definition_not_object")
        name = raw_tool.get("name")
        if not isinstance(name, str) or not name.strip():
            raise ProtocolProfileError("tool_definition_missing_name")
        description = raw_tool.get("description")
        if description is None:
            description = ""
        if not isinstance(description, str):
            raise ProtocolProfileError("tool_definition_invalid_description")
        input_schema = raw_tool.get("inputSchema", raw_tool.get("input_schema"))
        if not isinstance(input_schema, dict):
            raise ProtocolProfileError("tool_definition_invalid_input_schema")
        output_schema = raw_tool.get("outputSchema", raw_tool.get("output_schema"))
        if output_schema is not None and not isinstance(output_schema, dict):
            raise ProtocolProfileError("tool_definition_invalid_output_schema")
        annotations = raw_tool.get("annotations") or {}
        if not isinstance(annotations, dict):
            raise ProtocolProfileError("tool_definition_invalid_annotations")
        return CanonicalToolDefinition(
            name=name,
            description=description,
            input_schema=input_schema,
            output_schema=output_schema,
            annotations=annotations,
            source_profile_id=self.profile_id,
            protocol_era=self.protocol_era.value,
            protocol_version=self.protocol_version,
            transport_kind=self.transport_kind.value,
        )

    def canonical_arguments(self, arguments: Any) -> tuple[dict[str, Any], str]:
        if arguments is None:
            arguments = {}
        if not isinstance(arguments, dict):
            raise ProtocolProfileError("tool_arguments_not_object")
        return dict(arguments), sha256_canonical_json(arguments)

    def normalize_tool_call(
        self,
        *,
        server_ref: str,
        tool_name: str,
        arguments: Any,
        client_protocol_profile_id: str,
        request_id: str,
        agent_context: dict[str, Any] | None = None,
        session_context: dict[str, Any] | None = None,
        tool_observation: dict[str, Any] | None = None,
        current_fingerprint: str | None = None,
    ) -> NormalizedToolCall:
        canonical_args, canonical_args_hash = self.canonical_arguments(arguments)
        return NormalizedToolCall(
            server_ref=server_ref,
            tool_name=tool_name,
            canonical_args=canonical_args,
            canonical_args_hash=canonical_args_hash,
            client_protocol_profile_id=client_protocol_profile_id,
            upstream_protocol_profile_id=self.profile_id,
            request_id=request_id,
            client_protocol_era=(
                ProtocolProfileRegistry().get(client_protocol_profile_id).protocol_era.value
            ),
            client_protocol_version=(
                ProtocolProfileRegistry().get(client_protocol_profile_id).protocol_version
            ),
            client_transport_kind=(
                ProtocolProfileRegistry().get(client_protocol_profile_id).transport_kind.value
            ),
            upstream_protocol_era=self.protocol_era.value,
            upstream_protocol_version=self.protocol_version,
            upstream_transport_kind=self.transport_kind.value,
            agent_context=agent_context or {},
            session_context=session_context or {},
            tool_observation=tool_observation or {},
            current_fingerprint=current_fingerprint,
        )

    def validate_inbound_request(
        self,
        payload: dict[str, Any],
        *,
        headers: dict[str, str] | None = None,
    ) -> None:
        if not isinstance(payload, dict):
            raise ProtocolProfileError("jsonrpc_request_not_object")
        method = payload.get("method")
        if not isinstance(method, str) or method not in self.supported_methods:
            raise ProtocolProfileError(self.method_surface.rejection_code_for(str(method)))
        params = payload.get("params")
        if params is not None and not isinstance(params, dict):
            raise ProtocolProfileError("mcp_params_not_object")
        try:
            if "id" in payload:
                self.wire_validator.validate_client_request(
                    method=method,
                    version=self.protocol_version,
                    params=params,
                )
            else:
                self.wire_validator.validate_client_notification(
                    method=method,
                    version=self.protocol_version,
                    params=params,
                )
        except ProtocolRevisionError as exc:
            raise ProtocolProfileError(str(exc)) from exc

    def serialize_tool_call(
        self,
        *,
        request_id: int,
        name: str,
        arguments: dict[str, Any],
    ) -> tuple[dict[str, Any], dict[str, str]]:
        raise NotImplementedError

    def serialize_request(
        self,
        *,
        request_id: int,
        method: str,
        params: dict[str, Any] | None = None,
    ) -> tuple[dict[str, Any], dict[str, str]]:
        raise NotImplementedError

    def validate_tool_response(self, result: dict[str, Any]) -> None:
        if not isinstance(result, dict):
            raise ProtocolProfileError("tool_response_result_not_object")

    def validate_discover_result(self, result: dict[str, Any]) -> None:
        if not isinstance(result, dict):
            raise ProtocolProfileError("discover_result_not_object")

    def validate_list_tools_result(self, result: dict[str, Any]) -> None:
        if not isinstance(result, dict):
            raise ProtocolProfileError("tools_list_result_not_object")


class LegacyEraHandler(RestrictedProtocolProfile):
    def __init__(self, descriptor: ProtocolRevisionDescriptor) -> None:
        if descriptor.era != ProtocolEra.LEGACY:
            raise ProtocolProfileError("legacy_handler_descriptor_invalid")
        super().__init__(descriptor)

    def serialize_request(
        self,
        *,
        request_id: int,
        method: str,
        params: dict[str, Any] | None = None,
    ) -> tuple[dict[str, Any], dict[str, str]]:
        if method not in {"tools/list", "tools/call"}:
            raise ProtocolProfileError("legacy_request_method_unsupported")
        try:
            self.wire_validator.validate_client_request(
                method=method,
                version=self.protocol_version,
                params=params,
            )
        except ProtocolRevisionError as exc:
            raise ProtocolProfileError(str(exc)) from exc
        payload: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params:
            payload["params"] = params
        headers: dict[str, str] = {}
        if self.transport_kind != TransportKind.LEGACY_HTTP_SSE:
            headers["MCP-Protocol-Version"] = self.protocol_version
        return payload, headers

    def serialize_tool_call(
        self,
        *,
        request_id: int,
        name: str,
        arguments: dict[str, Any],
    ) -> tuple[dict[str, Any], dict[str, str]]:
        return self.serialize_request(
            request_id=request_id,
            method="tools/call",
            params={
                "name": name,
                "arguments": arguments,
            },
        )

    def validate_tool_response(self, result: dict[str, Any]) -> None:
        super().validate_tool_response(result)
        try:
            self.wire_validator.validate_server_result(
                method="tools/call",
                version=self.protocol_version,
                result=result,
            )
        except ProtocolRevisionError as exc:
            raise ProtocolProfileError(str(exc)) from exc
        if "method" in result:
            raise ProtocolProfileError("legacy_server_to_client_request_unsupported")
        forbidden = _find_protocol_mechanism(
            result,
            forbidden_keys={"task", "tasks", "requestState", "inputRequests"},
            forbidden_content_types={"resource", "resource_link"},
        )
        if forbidden:
            raise ProtocolProfileError(f"legacy_response_mechanism_unsupported:{forbidden}")

    def validate_list_tools_result(self, result: dict[str, Any]) -> None:
        super().validate_list_tools_result(result)
        try:
            self.wire_validator.validate_server_result(
                method="tools/list",
                version=self.protocol_version,
                result=result,
            )
        except ProtocolRevisionError as exc:
            raise ProtocolProfileError(str(exc)) from exc

    def validate_initialize_result(self, result: dict[str, Any]) -> None:
        if not isinstance(result, dict):
            raise ProtocolProfileError("initialize_result_not_object")
        try:
            self.wire_validator.validate_server_result(
                method="initialize",
                version=self.protocol_version,
                result=result,
            )
        except ProtocolRevisionError as exc:
            raise ProtocolProfileError(str(exc)) from exc


class Legacy20251125Profile(LegacyEraHandler):
    def __init__(self) -> None:
        super().__init__(ProtocolRevisionRegistry().get(LEGACY_PROTOCOL_VERSION))


class ModernEraHandler(RestrictedProtocolProfile):
    forbidden_result_keys = frozenset(
        {
            "inputRequests",
            "requestState",
            "task",
            "tasks",
            "resource_link",
            "resources",
            "prompts",
            "extensions",
        }
    )

    def __init__(self, descriptor: ProtocolRevisionDescriptor) -> None:
        if descriptor.era != ProtocolEra.MODERN:
            raise ProtocolProfileError("modern_handler_descriptor_invalid")
        super().__init__(descriptor)

    def validate_inbound_request(
        self,
        payload: dict[str, Any],
        *,
        headers: dict[str, str] | None = None,
    ) -> None:
        if not isinstance(payload, dict):
            raise ProtocolProfileError("jsonrpc_request_not_object")
        method = payload.get("method")
        if not isinstance(method, str) or method not in self.supported_methods:
            raise ProtocolProfileError(self.method_surface.rejection_code_for(str(method)))
        params = payload.get("params")
        if params is not None and not isinstance(params, dict):
            raise ProtocolProfileError("mcp_params_not_object")
        headers = _normalized_headers(headers or {})
        if not isinstance(params, dict):
            raise ProtocolProfileError("modern_params_not_object")
        meta = params.get("_meta")
        if not isinstance(meta, dict):
            raise ProtocolProfileError("modern_meta_not_object")
        unknown_reserved = {
            key
            for key in meta
            if isinstance(key, str)
            and key.startswith("io.modelcontextprotocol/")
            and key not in MODERN_ALLOWED_META_KEYS
        }
        if unknown_reserved:
            raise ProtocolProfileError("modern_security_metadata_unsupported")
        body_version = meta.get(MODERN_META_PROTOCOL_VERSION)
        header_version = headers.get("mcp-protocol-version")
        if body_version != self.protocol_version:
            raise ProtocolProfileError("modern_protocol_version_mismatch")
        capabilities = meta.get(MODERN_META_CLIENT_CAPABILITIES)
        if not isinstance(capabilities, dict):
            raise ProtocolProfileError("modern_client_capabilities_invalid")
        client_info = meta.get(MODERN_META_CLIENT_INFO)
        if client_info is not None and not _valid_implementation(client_info):
            raise ProtocolProfileError("modern_client_info_invalid")
        if header_version != self.protocol_version:
            raise ProtocolProfileError("modern_protocol_header_mismatch")
        if headers.get("mcp-method") != method:
            raise ProtocolProfileError("modern_method_header_mismatch")
        if method == "tools/call":
            tool_name = params.get("name")
            if not isinstance(tool_name, str) or not tool_name.strip():
                raise ProtocolProfileError("modern_tool_name_missing")
            if _decode_mcp_header_value(headers.get("mcp-name")) != tool_name:
                raise ProtocolProfileError("modern_tool_name_header_mismatch")
        elif "mcp-name" in headers:
            raise ProtocolProfileError("modern_tool_name_header_unexpected")
        if any(name.startswith("mcp-param-") for name in headers):
            raise ProtocolProfileError("modern_parameter_header_unsupported")
        try:
            if "id" in payload:
                self.wire_validator.validate_client_request(
                    method=method,
                    version=self.protocol_version,
                    params=params,
                )
            else:
                self.wire_validator.validate_client_notification(
                    method=method,
                    version=self.protocol_version,
                    params=params,
                )
        except ProtocolRevisionError as exc:
            raise ProtocolProfileError(str(exc)) from exc

    def serialize_request(
        self,
        *,
        request_id: int,
        method: str,
        params: dict[str, Any] | None = None,
    ) -> tuple[dict[str, Any], dict[str, str]]:
        if method not in self.supported_methods:
            raise ProtocolProfileError("modern_request_method_unsupported")
        request_params = dict(params or {})
        if "_meta" in request_params:
            raise ProtocolProfileError("modern_request_meta_must_be_profile_generated")
        request_params["_meta"] = modern_request_meta(protocol_version=self.protocol_version)
        try:
            self.wire_validator.validate_client_request(
                method=method,
                version=self.protocol_version,
                params=request_params,
            )
        except ProtocolRevisionError as exc:
            raise ProtocolProfileError(str(exc)) from exc
        payload = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": request_params,
        }
        headers = {
            "MCP-Protocol-Version": self.protocol_version,
            "Mcp-Method": method,
        }
        if method == "tools/call":
            name = request_params.get("name")
            if not isinstance(name, str) or not name.strip():
                raise ProtocolProfileError("modern_tool_name_missing")
            headers["Mcp-Name"] = _encode_mcp_header_value(name)
        return payload, headers

    def serialize_tool_call(
        self,
        *,
        request_id: int,
        name: str,
        arguments: dict[str, Any],
    ) -> tuple[dict[str, Any], dict[str, str]]:
        return self.serialize_request(
            request_id=request_id,
            method="tools/call",
            params={
                "name": name,
                "arguments": arguments,
            },
        )

    def validate_discover_result(self, result: dict[str, Any]) -> None:
        try:
            self.wire_validator.validate_server_result(
                method="server/discover",
                version=self.protocol_version,
                result=result,
            )
        except ProtocolRevisionError as exc:
            raise ProtocolProfileError(str(exc)) from exc
        self._validate_complete_cacheable_result(result, context="discover")
        supported_versions = result.get("supportedVersions")
        if (
            not isinstance(supported_versions, list)
            or any(not isinstance(item, str) for item in supported_versions)
            or self.protocol_version not in supported_versions
        ):
            raise ProtocolProfileError("modern_discover_supported_versions_invalid")
        if not isinstance(result.get("capabilities"), dict):
            raise ProtocolProfileError("modern_discover_capabilities_invalid")
        if "serverInfo" in result:
            raise ProtocolProfileError("modern_discover_server_info_top_level_unsupported")
        server_info = modern_result_server_info(result)
        if server_info is not None and not _valid_implementation(server_info):
            raise ProtocolProfileError("modern_discover_server_info_invalid")

    def validate_list_tools_result(self, result: dict[str, Any]) -> None:
        self._validate_complete_cacheable_result(result, context="tools_list")
        tools = result.get("tools")
        if not isinstance(tools, list):
            raise ProtocolProfileError("modern_tools_list_tools_invalid")
        try:
            self.wire_validator.validate_server_result(
                method="tools/list",
                version=self.protocol_version,
                result=result,
            )
        except ProtocolRevisionError as exc:
            raise ProtocolProfileError(str(exc)) from exc

    def validate_tool_response(self, result: dict[str, Any]) -> None:
        super().validate_tool_response(result)
        self._validate_complete_result(result)
        for key in {"ttlMs", "cacheScope"}:
            if key in result:
                raise ProtocolProfileError(f"modern_tool_response_unexpected_{key}")
        try:
            self.wire_validator.validate_server_result(
                method="tools/call",
                version=self.protocol_version,
                result=result,
            )
        except ProtocolRevisionError as exc:
            raise ProtocolProfileError(str(exc)) from exc

    def _validate_complete_cacheable_result(self, result: dict[str, Any], *, context: str) -> None:
        self._validate_complete_result(result)
        ttl_ms = result.get("ttlMs")
        if not isinstance(ttl_ms, int) or isinstance(ttl_ms, bool) or ttl_ms < 0:
            raise ProtocolProfileError(f"modern_{context}_ttl_invalid")
        if result.get("cacheScope") not in {"public", "private"}:
            raise ProtocolProfileError(f"modern_{context}_cache_scope_invalid")

    def _validate_complete_result(self, result: dict[str, Any]) -> None:
        super().validate_tool_response(result)
        result_type = result.get("resultType")
        if result_type != "complete":
            if result_type == "input_required":
                raise ProtocolProfileError("modern_mrtr_input_required_unsupported")
            if result_type is None:
                raise ProtocolProfileError("modern_result_type_missing")
            raise ProtocolProfileError("modern_result_type_unsupported")
        for key in self.forbidden_result_keys:
            if key in result:
                raise ProtocolProfileError(f"modern_response_forbidden_{key}")
        forbidden = _find_protocol_mechanism(
            result,
            forbidden_keys=set(self.forbidden_result_keys),
            forbidden_content_types={"resource", "resource_link"},
        )
        if forbidden:
            raise ProtocolProfileError(f"modern_response_mechanism_unsupported:{forbidden}")


class Modern20260728Profile(ModernEraHandler):
    def __init__(self) -> None:
        super().__init__(ProtocolRevisionRegistry().get(MODERN_PROTOCOL_VERSION))


class ProtocolProfileRegistry:
    def __init__(self) -> None:
        self.revision_registry = ProtocolRevisionRegistry()
        self._profiles: dict[str, RestrictedProtocolProfile] = {}
        for version in SUPPORTED_MCP_PROTOCOL_VERSIONS:
            descriptor = self.revision_registry.get(version)
            if descriptor.era == ProtocolEra.LEGACY:
                profile: RestrictedProtocolProfile = LegacyEraHandler(descriptor)
            else:
                profile = ModernEraHandler(descriptor)
            self._profiles[descriptor.framework_profile_id] = profile

    def get(self, profile_id: str | None) -> RestrictedProtocolProfile:
        selected = profile_id or LEGACY_PROFILE_ID
        if selected in SUPPORTED_MCP_PROTOCOL_VERSIONS:
            selected = self.revision_registry.profile_id_for_version(selected)
        try:
            return self._profiles[selected]
        except KeyError as exc:
            raise ProtocolProfileError("unsupported_mcp_protocol_profile") from exc

    def get_by_version(self, version: str) -> RestrictedProtocolProfile:
        try:
            profile_id = self.revision_registry.profile_id_for_version(version)
        except ProtocolRevisionError as exc:
            raise ProtocolProfileError(str(exc)) from exc
        return self.get(profile_id)

    def descriptor_for_profile_id(self, profile_id: str) -> ProtocolRevisionDescriptor:
        try:
            return self.revision_registry.get_by_profile_id(profile_id)
        except ProtocolRevisionError as exc:
            raise ProtocolProfileError(str(exc)) from exc

    def profile_id_for_version(self, version: str) -> str:
        try:
            return self.revision_registry.profile_id_for_version(version)
        except ProtocolRevisionError as exc:
            raise ProtocolProfileError(str(exc)) from exc

    def supported_profile_ids(self) -> tuple[str, ...]:
        return tuple(self._profiles)


def _normalized_headers(headers: dict[str, str]) -> dict[str, str]:
    normalized: dict[str, str] = {}
    for raw_name, value in headers.items():
        name = raw_name.lower()
        if name in normalized and normalized[name] != value:
            raise ProtocolProfileError("modern_conflicting_duplicate_header")
        normalized[name] = value
    return normalized


def _valid_implementation(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    name = value.get("name")
    version = value.get("version")
    return (
        isinstance(name, str)
        and bool(name.strip())
        and isinstance(version, str)
        and bool(version.strip())
    )


def modern_request_meta(
    *,
    protocol_version: str = MODERN_PROTOCOL_VERSION,
    client_name: str = MODERN_PROXY_NAME,
    client_version: str = MODERN_PROXY_VERSION,
) -> dict[str, Any]:
    return {
        MODERN_META_PROTOCOL_VERSION: protocol_version,
        MODERN_META_CLIENT_CAPABILITIES: {},
        MODERN_META_CLIENT_INFO: {
            "name": client_name,
            "version": client_version,
        },
    }


def modern_result_meta(
    *,
    server_name: str = MODERN_PROXY_NAME,
    server_version: str = MODERN_PROXY_VERSION,
) -> dict[str, Any]:
    return {
        MODERN_META_SERVER_INFO: {
            "name": server_name,
            "version": server_version,
        }
    }


def modern_cache_fields(cache_scope: str) -> dict[str, Any]:
    if cache_scope not in {"public", "private"}:
        raise ProtocolProfileError("modern_cache_scope_invalid")
    return {"ttlMs": MODERN_CACHE_TTL_MS, "cacheScope": cache_scope}


def modern_result_server_info(result: dict[str, Any]) -> dict[str, Any] | None:
    meta = result.get("_meta")
    if not isinstance(meta, dict):
        return None
    value = meta.get(MODERN_META_SERVER_INFO)
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ProtocolProfileError("modern_result_server_info_invalid")
    return value


def _encode_mcp_header_value(value: str) -> str:
    if _plain_mcp_header_value(value) and not _is_base64_sentinel(value):
        return value
    encoded = base64.b64encode(value.encode("utf-8")).decode("ascii")
    return f"=?base64?{encoded}?="


def _decode_mcp_header_value(value: str | None) -> str | None:
    if value is None:
        return None
    if _is_base64_sentinel(value):
        encoded = value[len("=?base64?") : -2]
        try:
            return base64.b64decode(encoded, validate=True).decode("utf-8")
        except Exception as exc:
            raise ProtocolProfileError("modern_header_value_encoding_invalid") from exc
    if not _plain_mcp_header_value(value):
        raise ProtocolProfileError("modern_header_value_invalid")
    return value


def _plain_mcp_header_value(value: str) -> bool:
    return (
        bool(value)
        and value == value.strip(" \t")
        and all(ord(character) in {9} or 0x20 <= ord(character) <= 0x7E for character in value)
    )


def _is_base64_sentinel(value: str) -> bool:
    return value.startswith("=?base64?") and value.endswith("?=")


def _find_protocol_mechanism(
    value: Any,
    *,
    forbidden_keys: set[str],
    forbidden_content_types: set[str],
) -> str | None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key in forbidden_keys:
                return key
            if key == "type" and child in forbidden_content_types:
                return str(child)
            found = _find_protocol_mechanism(
                child,
                forbidden_keys=forbidden_keys,
                forbidden_content_types=forbidden_content_types,
            )
            if found:
                return found
    elif isinstance(value, list):
        for child in value:
            found = _find_protocol_mechanism(
                child,
                forbidden_keys=forbidden_keys,
                forbidden_content_types=forbidden_content_types,
            )
            if found:
                return found
    return None
