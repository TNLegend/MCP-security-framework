from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
import ipaddress
from typing import Any
from urllib.parse import urlsplit

from proxy.security_packs import SecurityPackManifest

from proxy.tool_security_v2 import (
    AdapterResolution,
    CapabilityCatalog,
    ClaimedResourceReference,
    NormalizedBindingFacts,
    NormalizedEffectFacts,
    ReferencePrecision,
    ResourceTypeRegistry,
    SecurityModelError,
    ToolEffect,
    effective_precision,
)

SECRET_REFERENCE_PATTERNS = (
    ".env",
    ".env.",
    ".ssh",
    ".aws",
    ".aws/credentials",
    "/etc/passwd",
    "id_rsa",
    "id_ed25519",
    "credentials",
    "tokens",
    "secrets",
    "private.key",
)


@dataclass(frozen=True)
class AdapterManifest:
    adapter_id: str
    adapter_api_version: str
    implementation_version: str
    supported_capabilities: tuple[str, ...]
    supported_resource_types: tuple[str, ...]


class ResourceAdapter(ABC):
    manifest: AdapterManifest

    @abstractmethod
    def resolve(
        self,
        canonical_args: dict[str, Any],
        effect: ToolEffect,
        adapter_resolution: AdapterResolution,
        trusted_authority_context: dict[str, Any],
    ) -> NormalizedEffectFacts:
        raise NotImplementedError


class GenericDeclarativeAdapter(ResourceAdapter):
    manifest = AdapterManifest(
        adapter_id="generic-declarative",
        adapter_api_version="1",
        implementation_version="1.0.0",
        supported_capabilities=("*",),
        supported_resource_types=("*",),
    )

    def __init__(
        self,
        resource_types: ResourceTypeRegistry | None = None,
        capabilities: CapabilityCatalog | None = None,
    ) -> None:
        self.resource_types = resource_types or ResourceTypeRegistry()
        self.capabilities = capabilities or CapabilityCatalog()

    def resolve(
        self,
        canonical_args: dict[str, Any],
        effect: ToolEffect,
        adapter_resolution: AdapterResolution,
        trusted_authority_context: dict[str, Any],
    ) -> NormalizedEffectFacts:
        return _resolve_declaratively(
            canonical_args,
            effect,
            adapter_resolution,
            trusted_authority_context,
            self.resource_types,
            self.capabilities,
        )


class FilesystemAdapter(ResourceAdapter):
    manifest = AdapterManifest(
        adapter_id="filesystem",
        adapter_api_version="1",
        implementation_version="2.0.0",
        supported_capabilities=(
            "filesystem.read",
            "filesystem.list",
            "filesystem.write",
            "filesystem.delete",
        ),
        supported_resource_types=("filesystem_path",),
    )

    def __init__(
        self,
        resource_types: ResourceTypeRegistry | None = None,
        capabilities: CapabilityCatalog | None = None,
    ) -> None:
        self.resource_types = resource_types or ResourceTypeRegistry()
        self.capabilities = capabilities or CapabilityCatalog()

    def resolve(
        self,
        canonical_args: dict[str, Any],
        effect: ToolEffect,
        adapter_resolution: AdapterResolution,
        trusted_authority_context: dict[str, Any],
    ) -> NormalizedEffectFacts:
        return _resolve_declaratively(
            canonical_args,
            effect,
            adapter_resolution,
            trusted_authority_context,
            self.resource_types,
            self.capabilities,
        )


class URLAdapter(ResourceAdapter):
    manifest = AdapterManifest(
        adapter_id="url",
        adapter_api_version="1",
        implementation_version="1.0.0",
        supported_capabilities=("network.request", "network.send"),
        supported_resource_types=("url",),
    )

    def __init__(self, resource_types: ResourceTypeRegistry, capabilities: CapabilityCatalog) -> None:
        self.resource_types = resource_types
        self.capabilities = capabilities

    def resolve(
        self,
        canonical_args: dict[str, Any],
        effect: ToolEffect,
        adapter_resolution: AdapterResolution,
        trusted_authority_context: dict[str, Any],
    ) -> NormalizedEffectFacts:
        return _resolve_declaratively(
            canonical_args,
            effect,
            adapter_resolution,
            trusted_authority_context,
            self.resource_types,
            self.capabilities,
        )


class AdapterRegistry:
    def __init__(
        self,
        *,
        capability_catalog_version: str = "2",
        resource_type_registry_version: str = "2",
        security_packs: tuple[SecurityPackManifest, ...] = (),
    ) -> None:
        self.capabilities = CapabilityCatalog(
            version=capability_catalog_version,
            security_packs=security_packs,
        )
        self.resource_types = ResourceTypeRegistry(
            version=resource_type_registry_version,
            security_packs=security_packs,
        )
        adapters: tuple[ResourceAdapter, ...] = (
            FilesystemAdapter(self.resource_types, self.capabilities),
            GenericDeclarativeAdapter(self.resource_types, self.capabilities),
            URLAdapter(self.resource_types, self.capabilities),
        )
        self._adapters = {adapter.manifest.adapter_id: adapter for adapter in adapters}

    def resolve(self, capability: str, resource_type: str) -> AdapterManifest:
        capability_definition = self.capabilities.get(capability)
        if resource_type not in capability_definition.allowed_resource_types:
            raise SecurityModelError("capability_resource_type_incompatible")
        resource_definition = self.resource_types.get(resource_type)
        adapter = self.get(resource_definition.adapter_id)
        manifest = adapter.manifest
        capability_supported = (
            "*" in manifest.supported_capabilities
            or capability in manifest.supported_capabilities
        )
        resource_supported = (
            "*" in manifest.supported_resource_types
            or resource_type in manifest.supported_resource_types
        )
        if not capability_supported or not resource_supported:
            raise SecurityModelError("adapter_resolution_missing_or_ambiguous")
        if (
            resource_definition.requires_specialized_interpretation
            and manifest.adapter_id == "generic-declarative"
        ):
            raise SecurityModelError("specialized_adapter_required")
        return manifest

    def get(self, adapter_id: str) -> ResourceAdapter:
        try:
            return self._adapters[adapter_id]
        except KeyError as exc:
            raise SecurityModelError("adapter_not_registered") from exc


def resolve_effect_facts(
    canonical_args: dict[str, Any],
    effect: ToolEffect,
    adapter_resolution: AdapterResolution,
    trusted_authority_context: dict[str, Any],
    *,
    registry: AdapterRegistry | None = None,
) -> NormalizedEffectFacts:
    adapters = registry or AdapterRegistry()
    adapter = adapters.get(adapter_resolution.adapter_id)
    manifest = adapter.manifest
    if (
        manifest.adapter_api_version != adapter_resolution.adapter_api_version
        or manifest.implementation_version != adapter_resolution.implementation_version
    ):
        raise SecurityModelError("adapter_resolution_stale")
    return adapter.resolve(
        canonical_args,
        effect,
        adapter_resolution,
        trusted_authority_context,
    )


def _resolve_declaratively(
    canonical_args: dict[str, Any],
    effect: ToolEffect,
    adapter_resolution: AdapterResolution,
    trusted_authority_context: dict[str, Any],
    resource_types: ResourceTypeRegistry,
    capabilities: CapabilityCatalog,
) -> NormalizedEffectFacts:
    authority = trusted_authority_context.get("authority")
    if not isinstance(authority, str) or not authority.strip():
        raise SecurityModelError("trusted_authority_missing")
    bindings: list[NormalizedBindingFacts] = []
    runtime_precision = ReferencePrecision.EXPLICIT
    if effect.fixed_resource is not None:
        try:
            canonical, ancestors = resource_types.canonicalize(
                effect.fixed_resource.resource_type,
                effect.fixed_resource.canonical_value,
                trusted_authority_context.get("resource_type_config"),
            )
            flags, sensitivity = _classify_reference_sensitivity(
                effect.fixed_resource.resource_type,
                canonical,
            )
            references = (
                ClaimedResourceReference(
                    authority=authority,
                    resource_type=effect.fixed_resource.resource_type,
                    canonical_value=canonical,
                    ancestors=ancestors,
                    resource_sensitivity=sensitivity,
                    resource_flags=tuple(flags),
                ),
            )
            bindings.append(
                NormalizedBindingFacts(
                    path=(),
                    status="resolved",
                    resource_type=effect.fixed_resource.resource_type,
                    role=effect.fixed_resource.role,
                    occurrence_count=1,
                    truncated=False,
                    references=references,
                )
            )
        except SecurityModelError:
            runtime_precision = ReferencePrecision.OPAQUE
            bindings.append(
                NormalizedBindingFacts(
                    path=(),
                    status="invalid",
                    resource_type=effect.fixed_resource.resource_type,
                    role=effect.fixed_resource.role,
                    occurrence_count=0,
                    truncated=False,
                    references=(),
                )
            )
    for binding in effect.resource_bindings:
        values, extraction_status = extract_values_at_path(canonical_args, binding.path)
        references: list[ClaimedResourceReference] = []
        status = extraction_status
        for value in values:
            try:
                canonical, ancestors = resource_types.canonicalize(
                    binding.resource_type,
                    value,
                    trusted_authority_context.get("resource_type_config"),
                )
            except SecurityModelError:
                status = "invalid"
                runtime_precision = ReferencePrecision.OPAQUE
                references = []
                break
            flags, sensitivity = _classify_reference_sensitivity(
                binding.resource_type,
                canonical,
            )
            references.append(
                ClaimedResourceReference(
                    authority=authority,
                    resource_type=binding.resource_type,
                    canonical_value=canonical,
                    ancestors=ancestors,
                    resource_sensitivity=sensitivity,
                    resource_flags=tuple(flags),
                )
            )
        bindings.append(
            NormalizedBindingFacts(
                path=binding.path,
                status=status,
                resource_type=binding.resource_type,
                role=binding.role,
                occurrence_count=len(values),
                truncated=False,
                references=tuple(references),
            )
        )
    capability = capabilities.get(effect.capability)
    return NormalizedEffectFacts(
        effect_id=effect.effect_id,
        capability_id=effect.capability,
        requires_resource=capability.requires_resource,
        adapter_id=adapter_resolution.adapter_id,
        adapter_api_version=adapter_resolution.adapter_api_version,
        declared_reference_precision=effect.declared_reference_precision,
        runtime_reference_precision=runtime_precision,
        effective_reference_precision=effective_precision(
            effect.declared_reference_precision,
            runtime_precision,
        ),
        max_resource_cardinality=effect.max_resource_cardinality,
        bindings=tuple(bindings),
    )


def _classify_reference_sensitivity(
    resource_type: str,
    canonical_value: str,
) -> tuple[tuple[str, ...], str]:
    if resource_type == "url":
        host = urlsplit(canonical_value).hostname or ""
        if host.lower() == "localhost":
            return ("private_network_destination",), "secret"
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            return (), "unknown"
        if (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_reserved
            or address.is_unspecified
        ):
            return ("private_network_destination",), "secret"
        return (), "unknown"
    if resource_type != "filesystem_path":
        return (), "unknown"
    comparison = canonical_value.lower()
    flags: set[str] = set()
    if any(pattern in comparison for pattern in SECRET_REFERENCE_PATTERNS):
        flags.add("sensitive_name")
    parts = {part for part in comparison.split("/") if part}
    if parts.intersection({".ssh", ".aws", "secrets"}):
        flags.add("sensitive_directory")
    if flags:
        return tuple(sorted(flags)), "secret"
    return (), "internal"


def extract_values_at_path(
    root: dict[str, Any],
    path: tuple[str, ...],
) -> tuple[list[Any], str]:
    current: list[Any] = [root]
    for token in path:
        next_values: list[Any] = []
        for value in current:
            if token == "*":
                if not isinstance(value, list):
                    return [], "invalid"
                next_values.extend(value)
            elif token.isdigit():
                if not isinstance(value, list) or int(token) >= len(value):
                    return [], "missing"
                next_values.append(value[int(token)])
            else:
                if not isinstance(value, dict) or token not in value:
                    return [], "missing"
                next_values.append(value[token])
        current = next_values
    return current, "resolved" if current else "missing"
