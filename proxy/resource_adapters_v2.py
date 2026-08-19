from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

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
        supported_capabilities=("message.send",),
        supported_resource_types=("email_address", "hierarchical_name"),
    )

    def __init__(self, resource_types: ResourceTypeRegistry | None = None) -> None:
        self.resource_types = resource_types or ResourceTypeRegistry()

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
        )


class FilesystemAdapter(ResourceAdapter):
    manifest = AdapterManifest(
        adapter_id="filesystem",
        adapter_api_version="1",
        implementation_version="2.0.0",
        supported_capabilities=("filesystem.read", "filesystem.list"),
        supported_resource_types=("filesystem_path",),
    )

    def __init__(self, resource_types: ResourceTypeRegistry | None = None) -> None:
        self.resource_types = resource_types or ResourceTypeRegistry()

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
        )


class AdapterRegistry:
    def __init__(self) -> None:
        adapters: tuple[ResourceAdapter, ...] = (
            FilesystemAdapter(),
            GenericDeclarativeAdapter(),
        )
        self._adapters = {adapter.manifest.adapter_id: adapter for adapter in adapters}

    def resolve(self, capability: str, resource_type: str) -> AdapterManifest:
        matches = [
            adapter.manifest
            for adapter in self._adapters.values()
            if capability in adapter.manifest.supported_capabilities
            and resource_type in adapter.manifest.supported_resource_types
        ]
        if len(matches) != 1:
            raise SecurityModelError("adapter_resolution_missing_or_ambiguous")
        return matches[0]

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
) -> NormalizedEffectFacts:
    authority = trusted_authority_context.get("authority")
    if not isinstance(authority, str) or not authority.strip():
        raise SecurityModelError("trusted_authority_missing")
    bindings: list[NormalizedBindingFacts] = []
    runtime_precision = ReferencePrecision.EXPLICIT
    for binding in effect.resource_bindings:
        values, extraction_status = _extract_values(canonical_args, binding.path)
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
            references.append(
                ClaimedResourceReference(
                    authority=authority,
                    resource_type=binding.resource_type,
                    canonical_value=canonical,
                    ancestors=ancestors,
                )
            )
        bindings.append(
            NormalizedBindingFacts(
                path=binding.path,
                status=status,
                resource_type=binding.resource_type,
                occurrence_count=len(values),
                truncated=False,
                references=tuple(references),
            )
        )
    capability = CapabilityCatalog().get(effect.capability)
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


def _extract_values(
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
