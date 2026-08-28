from __future__ import annotations

from abc import ABC, abstractmethod
import base64
import binascii
from dataclasses import dataclass, field
from hashlib import sha256
import ipaddress
import re
from threading import RLock
from typing import Any, Callable
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

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
    display_name: str = ""
    family: str = "general"
    publisher: str = "mcp-security-framework"
    trust_level: str = "BUILTIN_REVIEWED"
    argument_validation: str = "schema_and_resource"
    result_validation: str = "mcp_envelope"


@dataclass(frozen=True)
class AdapterResultInspection:
    blocked: bool = False
    finding_codes: tuple[str, ...] = ()


@dataclass(frozen=True)
class CanonicalAdapterReference:
    canonical_value: str
    ancestors: tuple[str, ...] = ()
    resource_sensitivity: str = "unknown"
    resource_flags: tuple[str, ...] = ()


@dataclass(frozen=True)
class TrustedAdapterRegistration:
    adapter: "ResourceAdapter"
    distribution_sha256: str
    signer_key_fingerprint: str
    _verification_marker: object = field(repr=False)


_TRUSTED_REGISTRATION_MARKER = object()
_TRUSTED_REGISTRATION_LOCK = RLock()
_TRUSTED_ADAPTER_REGISTRATIONS: tuple[TrustedAdapterRegistration, ...] = ()


def verify_trusted_adapter_distribution(
    adapter: "ResourceAdapter",
    *,
    distribution: bytes,
    public_key_pem: str,
    signature_base64: str,
) -> TrustedAdapterRegistration:
    if not distribution:
        raise SecurityModelError("adapter_distribution_empty")
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
        signature = base64.b64decode(signature_base64, validate=True)
    except (ValueError, TypeError, UnicodeError, binascii.Error) as exc:
        raise SecurityModelError("adapter_signature_invalid") from exc
    if not isinstance(public_key, ed25519.Ed25519PublicKey):
        raise SecurityModelError("adapter_signature_key_type_unsupported")
    try:
        public_key.verify(signature, distribution)
    except InvalidSignature as exc:
        raise SecurityModelError("adapter_signature_invalid") from exc
    public_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return TrustedAdapterRegistration(
        adapter=adapter,
        distribution_sha256=sha256(distribution).hexdigest(),
        signer_key_fingerprint=sha256(public_der).hexdigest(),
        _verification_marker=_TRUSTED_REGISTRATION_MARKER,
    )


def register_trusted_adapter(registration: TrustedAdapterRegistration) -> None:
    if registration._verification_marker is not _TRUSTED_REGISTRATION_MARKER:
        raise SecurityModelError("external_adapter_signature_required")
    adapter_id = registration.adapter.manifest.adapter_id
    global _TRUSTED_ADAPTER_REGISTRATIONS
    with _TRUSTED_REGISTRATION_LOCK:
        if any(
            item.adapter.manifest.adapter_id == adapter_id
            for item in _TRUSTED_ADAPTER_REGISTRATIONS
        ):
            raise SecurityModelError("adapter_id_collision")
        _TRUSTED_ADAPTER_REGISTRATIONS = (
            *_TRUSTED_ADAPTER_REGISTRATIONS,
            registration,
        )


def registered_trusted_adapters() -> tuple[TrustedAdapterRegistration, ...]:
    with _TRUSTED_REGISTRATION_LOCK:
        return _TRUSTED_ADAPTER_REGISTRATIONS


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

    def inspect_result(self, result: Any) -> AdapterResultInspection:
        return AdapterResultInspection()


class GenericDeclarativeAdapter(ResourceAdapter):
    manifest = AdapterManifest(
        adapter_id="generic-declarative",
        adapter_api_version="1",
        implementation_version="1.0.0",
        supported_capabilities=("*",),
        supported_resource_types=("*",),
        display_name="Generic Declarative",
        family="declarative",
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
        display_name="Filesystem",
        family="filesystem",
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
        display_name="HTTP URL",
        family="http-api",
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
        trusted_adapters: tuple[TrustedAdapterRegistration, ...] | None = None,
    ) -> None:
        self.capabilities = CapabilityCatalog(
            version=capability_catalog_version,
            security_packs=security_packs,
        )
        self.resource_types = ResourceTypeRegistry(
            version=resource_type_registry_version,
            security_packs=security_packs,
        )
        from proxy.specialized_adapters import builtin_specialized_adapters

        builtin_adapters: tuple[ResourceAdapter, ...] = (
            FilesystemAdapter(self.resource_types, self.capabilities),
            GenericDeclarativeAdapter(self.resource_types, self.capabilities),
            URLAdapter(self.resource_types, self.capabilities),
            *builtin_specialized_adapters(self.resource_types, self.capabilities),
        )
        self._adapters: dict[str, ResourceAdapter] = {}
        self._provenance: dict[str, TrustedAdapterRegistration] = {}
        for adapter in builtin_adapters:
            self._register(adapter, builtin=True, registration=None)
        for registration in (
            registered_trusted_adapters()
            if trusted_adapters is None
            else trusted_adapters
        ):
            self._register(
                registration.adapter,
                builtin=False,
                registration=registration,
            )

    def _register(
        self,
        adapter: ResourceAdapter,
        *,
        builtin: bool,
        registration: TrustedAdapterRegistration | None,
    ) -> None:
        manifest = adapter.manifest
        if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,127}", manifest.adapter_id):
            raise SecurityModelError("adapter_manifest_invalid_id")
        if manifest.adapter_api_version != "1":
            raise SecurityModelError("adapter_api_version_unsupported")
        if not re.fullmatch(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", manifest.implementation_version):
            raise SecurityModelError("adapter_implementation_version_invalid")
        if manifest.trust_level not in {"BUILTIN_REVIEWED", "SIGNED_REVIEWED"}:
            raise SecurityModelError("adapter_trust_level_invalid")
        if builtin and manifest.trust_level != "BUILTIN_REVIEWED":
            raise SecurityModelError("builtin_adapter_trust_invalid")
        if not builtin and (
            manifest.trust_level != "SIGNED_REVIEWED"
            or registration is None
            or registration._verification_marker is not _TRUSTED_REGISTRATION_MARKER
            or re.fullmatch(r"[0-9a-f]{64}", registration.distribution_sha256) is None
            or re.fullmatch(r"[0-9a-f]{64}", registration.signer_key_fingerprint) is None
        ):
            raise SecurityModelError("external_adapter_signature_required")
        if manifest.adapter_id in self._adapters:
            raise SecurityModelError("adapter_id_collision")
        self._adapters[manifest.adapter_id] = adapter
        if registration is not None:
            self._provenance[manifest.adapter_id] = registration

    def catalog(self) -> tuple[dict[str, Any], ...]:
        return tuple(
            {
                "adapter_id": manifest.adapter_id,
                "display_name": manifest.display_name or manifest.adapter_id,
                "family": manifest.family,
                "adapter_api_version": manifest.adapter_api_version,
                "implementation_version": manifest.implementation_version,
                "publisher": manifest.publisher,
                "trust_level": manifest.trust_level,
                "distribution_sha256": (
                    self._provenance[manifest.adapter_id].distribution_sha256
                    if manifest.adapter_id in self._provenance
                    else None
                ),
                "signer_key_fingerprint": (
                    self._provenance[manifest.adapter_id].signer_key_fingerprint
                    if manifest.adapter_id in self._provenance
                    else None
                ),
                "signature_verified": manifest.adapter_id in self._provenance,
                "supported_capabilities": manifest.supported_capabilities,
                "supported_resource_types": manifest.supported_resource_types,
                "argument_validation": manifest.argument_validation,
                "result_validation": manifest.result_validation,
            }
            for manifest in sorted(
                (adapter.manifest for adapter in self._adapters.values()),
                key=lambda value: value.adapter_id,
            )
        )

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


def inspect_adapter_result(
    result: Any,
    adapter_resolutions: tuple[AdapterResolution, ...],
    *,
    registry: AdapterRegistry | None = None,
) -> AdapterResultInspection:
    adapters = registry or AdapterRegistry()
    findings: set[str] = set()
    inspected: set[tuple[str, str, str]] = set()
    for resolution in adapter_resolutions:
        key = (
            resolution.adapter_id,
            resolution.adapter_api_version,
            resolution.implementation_version,
        )
        if key in inspected:
            continue
        inspected.add(key)
        adapter = adapters.get(resolution.adapter_id)
        manifest = adapter.manifest
        if (
            manifest.adapter_api_version != resolution.adapter_api_version
            or manifest.implementation_version != resolution.implementation_version
        ):
            return AdapterResultInspection(True, ("adapter_resolution_stale",))
        try:
            inspection = adapter.inspect_result(result)
        except Exception:
            return AdapterResultInspection(
                True,
                ("adapter_result_inspection_error",),
            )
        if not isinstance(inspection, AdapterResultInspection):
            return AdapterResultInspection(
                True,
                ("adapter_result_inspection_invalid",),
            )
        findings.update(inspection.finding_codes)
    return AdapterResultInspection(bool(findings), tuple(sorted(findings)))


def _resolve_declaratively(
    canonical_args: dict[str, Any],
    effect: ToolEffect,
    adapter_resolution: AdapterResolution,
    trusted_authority_context: dict[str, Any],
    resource_types: ResourceTypeRegistry,
    capabilities: CapabilityCatalog,
    reference_normalizer: Callable[
        [str, Any, dict[str, Any]], tuple[CanonicalAdapterReference, ...]
    ] | None = None,
) -> NormalizedEffectFacts:
    authority = trusted_authority_context.get("authority")
    if not isinstance(authority, str) or not authority.strip():
        raise SecurityModelError("trusted_authority_missing")
    bindings: list[NormalizedBindingFacts] = []
    runtime_precision = ReferencePrecision.EXPLICIT
    normalize = reference_normalizer or (
        lambda resource_type, value, config: _registry_references(
            resource_types,
            resource_type,
            value,
            config,
        )
    )
    if effect.fixed_resource is not None:
        try:
            normalized = normalize(
                effect.fixed_resource.resource_type,
                effect.fixed_resource.canonical_value,
                trusted_authority_context.get("resource_type_config") or {},
            )
            references = tuple(
                ClaimedResourceReference(
                    authority=authority,
                    resource_type=effect.fixed_resource.resource_type,
                    canonical_value=reference.canonical_value,
                    ancestors=reference.ancestors,
                    resource_sensitivity=reference.resource_sensitivity,
                    resource_flags=reference.resource_flags,
                )
                for reference in normalized
            )
            bindings.append(
                NormalizedBindingFacts(
                    path=(),
                    status="resolved",
                    resource_type=effect.fixed_resource.resource_type,
                    role=effect.fixed_resource.role,
                    occurrence_count=len(references),
                    truncated=False,
                    references=references,
                )
            )
        except (SecurityModelError, ValueError):
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
                normalized = normalize(
                    binding.resource_type,
                    value,
                    trusted_authority_context.get("resource_type_config") or {},
                )
            except (SecurityModelError, ValueError):
                status = "invalid"
                runtime_precision = ReferencePrecision.OPAQUE
                references = []
                break
            references.extend(
                ClaimedResourceReference(
                    authority=authority,
                    resource_type=binding.resource_type,
                    canonical_value=reference.canonical_value,
                    ancestors=reference.ancestors,
                    resource_sensitivity=reference.resource_sensitivity,
                    resource_flags=reference.resource_flags,
                )
                for reference in normalized
            )
        bindings.append(
            NormalizedBindingFacts(
                path=binding.path,
                status=status,
                resource_type=binding.resource_type,
                role=binding.role,
                occurrence_count=len(references),
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


def _registry_references(
    resource_types: ResourceTypeRegistry,
    resource_type: str,
    value: Any,
    authority_config: dict[str, Any],
) -> tuple[CanonicalAdapterReference, ...]:
    canonical, ancestors = resource_types.canonicalize(
        resource_type,
        value,
        authority_config,
    )
    flags, sensitivity = _classify_reference_sensitivity(resource_type, canonical)
    return (
        CanonicalAdapterReference(
            canonical_value=canonical,
            ancestors=ancestors,
            resource_sensitivity=sensitivity,
            resource_flags=flags,
        ),
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
