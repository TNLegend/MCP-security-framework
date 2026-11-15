from __future__ import annotations

import math
import re
from typing import Any, Iterable, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, model_validator

from common.canonical_json import sha256_canonical_json


PACK_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
SECURITY_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")
SEMVER_PATTERN = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")


class SecurityPackError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code




def parse_security_pack_version(value: str) -> tuple[int, int, int]:
    match = SEMVER_PATTERN.fullmatch(value)
    if match is None:
        raise ValueError("security pack version must be strict semantic version MAJOR.MINOR.PATCH")
    return tuple(int(part) for part in match.groups())


class SecurityPackDependency(BaseModel):
    pack_id: str
    min_version: str | None = None
    max_version_exclusive: str | None = None

    model_config = ConfigDict(extra="forbid", frozen=True)

    @model_validator(mode="after")
    def validate_dependency(self) -> "SecurityPackDependency":
        if not PACK_ID_PATTERN.fullmatch(self.pack_id):
            raise ValueError("invalid security pack dependency id")
        minimum = parse_security_pack_version(self.min_version) if self.min_version else None
        maximum = (
            parse_security_pack_version(self.max_version_exclusive)
            if self.max_version_exclusive
            else None
        )
        if minimum is not None and maximum is not None and minimum >= maximum:
            raise ValueError("security pack dependency version range is empty")
        return self

    def accepts(self, version: str) -> bool:
        parsed = parse_security_pack_version(version)
        if self.min_version is not None and parsed < parse_security_pack_version(self.min_version):
            return False
        if (
            self.max_version_exclusive is not None
            and parsed >= parse_security_pack_version(self.max_version_exclusive)
        ):
            return False
        return True


class PackCapability(BaseModel):
    id: str
    domain: str
    verb: str
    destructive: bool = False
    external_effect: bool = False
    # Explicit data-production semantics; None is UNKNOWN, never False.
    # Omit absent metadata from historical signed manifest hashes.
    produces_data: StrictBool | None = Field(
        default=None, exclude_if=lambda value: value is None
    )
    requires_resource: bool = True
    allowed_resource_types: tuple[str, ...] = ()
    lifecycle: Literal["ACTIVE", "DEPRECATED"] = "ACTIVE"

    model_config = ConfigDict(extra="forbid", frozen=True)


class PackResourceType(BaseModel):
    id: str
    version: str = "1"
    canonicalizer: Literal[
        "filesystem_path",
        "hierarchical_name",
        "email_address",
        "url",
    ]
    hierarchy_support: bool
    allowed_matching_modes: tuple[Literal["SELF", "SUBTREE"], ...]
    adapter_id: str
    requires_specialized_interpretation: bool = False
    case_semantics: str = "authority-defined"
    unicode_policy: str = "NFC-strict"

    model_config = ConfigDict(extra="forbid", frozen=True)


class TemplateBinding(BaseModel):
    key: str
    resource_type: str
    role: Literal["RESOURCE", "SOURCE", "DESTINATION"] = "RESOURCE"
    required: bool = True
    multiple: bool = False
    argument_hints: tuple[str, ...] = ()

    model_config = ConfigDict(extra="forbid", frozen=True)


def _safe_constraint_number(value: Any) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
    )


def _safe_constraint_scalar(value: Any) -> bool:
    return isinstance(value, (str, bool)) or _safe_constraint_number(value)


class TemplateArgumentConstraint(BaseModel):
    key: str
    operator: Literal[
        "EQ",
        "NE",
        "LT",
        "LE",
        "GT",
        "GE",
        "IN",
        "NOT_IN",
        "MAX_OCCURRENCES",
    ]
    value: Any
    required: bool = True
    argument_hints: tuple[str, ...] = ()
    # Optional semantic assertion: this field determines which effect the
    # MCP performs, so only a required exact-value constraint may govern it.
    effect_selector: bool = Field(default=False, exclude_if=lambda value: not value)

    model_config = ConfigDict(extra="forbid", frozen=True)

    @model_validator(mode="after")
    def validate_constraint(self) -> "TemplateArgumentConstraint":
        if self.effect_selector and (not self.required or self.operator != "EQ"):
            raise ValueError("effect_selector_requires_exact_required_constraint")
        if not SECURITY_ID_PATTERN.fullmatch(self.key):
            raise ValueError("invalid template argument constraint key")
        if self.operator in {"EQ", "NE"}:
            if not _safe_constraint_scalar(self.value):
                raise ValueError("equality constraint requires a scalar value")
        elif self.operator in {"LT", "LE", "GT", "GE"}:
            if not _safe_constraint_number(self.value):
                raise ValueError("ordered constraint requires a finite number")
        elif self.operator in {"IN", "NOT_IN"}:
            if (
                not isinstance(self.value, (list, tuple))
                or not self.value
                or len(self.value) > 100
                or not all(_safe_constraint_scalar(item) for item in self.value)
            ):
                raise ValueError("membership constraint requires bounded scalar values")
        elif self.operator == "MAX_OCCURRENCES":
            if (
                not isinstance(self.value, int)
                or isinstance(self.value, bool)
                or self.value < 0
                or self.value > 1000
            ):
                raise ValueError("max occurrences constraint requires a bounded integer")
        return self


class TemplateArgumentRole(BaseModel):
    """Explicit reviewed semantic assertion for a mapped argument.

    Resource roles are already declared in TemplateBinding and selectors in
    TemplateArgumentConstraint(effect_selector=True); only remaining leaves
    require independent DATA or unsupported PROGRAM assertions.
    """
    key: str
    role: Literal["DATA", "PROGRAM"]
    argument_hints: tuple[str, ...] = ()

    model_config = ConfigDict(extra="forbid", frozen=True)

    @model_validator(mode="after")
    def validate_role(self) -> "TemplateArgumentRole":
        if not SECURITY_ID_PATTERN.fullmatch(self.key):
            raise ValueError("invalid template argument role key")
        return self


class TemplateResultControl(BaseModel):
    classification: Literal["UNSPECIFIED", "INTERNAL", "SENSITIVE", "SECRET"] = "UNSPECIFIED"
    track_for_exfiltration: bool = False
    produces_data: StrictBool | None = Field(
        default=None, exclude_if=lambda value: value is None
    )

    model_config = ConfigDict(extra="forbid", frozen=True)


class TemplateEffect(BaseModel):
    key: str
    capability: str
    bindings: tuple[TemplateBinding, ...] = ()
    max_resource_cardinality: int | None = Field(default=None, ge=1, le=1000)
    declared_reference_precision: Literal["EXPLICIT"] = "EXPLICIT"

    model_config = ConfigDict(extra="forbid", frozen=True)

    @model_validator(mode="after")
    def validate_effect(self) -> "TemplateEffect":
        if not SECURITY_ID_PATTERN.fullmatch(self.key):
            raise ValueError("invalid template effect key")
        if not SECURITY_ID_PATTERN.fullmatch(self.capability):
            raise ValueError("invalid template effect capability")
        binding_keys = [binding.key for binding in self.bindings]
        if len(binding_keys) != len(set(binding_keys)):
            raise ValueError("duplicate binding key in template effect")
        return self


class ToolContractTemplate(BaseModel):
    id: str
    title: str
    description: str
    capability: str | None = None
    keywords: tuple[str, ...] = ()
    bindings: tuple[TemplateBinding, ...] = ()
    max_resource_cardinality: int | None = Field(default=None, ge=1, le=1000)
    declared_reference_precision: Literal["EXPLICIT"] = "EXPLICIT"
    effects: tuple[TemplateEffect, ...] = ()
    constraints: tuple[TemplateArgumentConstraint, ...] = ()
    # Omitted from historical Security Pack/template hashes. An opt-in
    # reviewer must map EVERY remaining DATA or PROGRAM input explicitly.
    argument_roles: tuple[TemplateArgumentRole, ...] = Field(
        default_factory=tuple, exclude_if=lambda entries: not entries
    )
    result_control: TemplateResultControl = TemplateResultControl()

    model_config = ConfigDict(extra="forbid", frozen=True)

    @model_validator(mode="after")
    def validate_template_shape(self) -> "ToolContractTemplate":
        if self.effects:
            if (
                self.capability is not None
                or self.bindings
                or self.max_resource_cardinality is not None
                or self.declared_reference_precision != "EXPLICIT"
            ):
                raise ValueError("advanced template cannot mix legacy effect fields")
            effect_keys = [effect.key for effect in self.effects]
            if len(effect_keys) != len(set(effect_keys)):
                raise ValueError("duplicate effect key in tool contract template")
            binding_keys = [
                binding.key
                for effect in self.effects
                for binding in effect.bindings
            ]
            if len(binding_keys) != len(set(binding_keys)):
                raise ValueError("template binding keys must be unique across effects")
        elif not self.capability:
            raise ValueError("template requires a capability or effects")
        else:
            binding_keys = [binding.key for binding in self.bindings]

        constraint_keys = [constraint.key for constraint in self.constraints]
        if len(constraint_keys) != len(set(constraint_keys)):
            raise ValueError("template constraint keys must be unique")
        if set(constraint_keys).intersection(binding_keys):
            raise ValueError("template constraint keys cannot collide with binding keys")
        role_keys = [entry.key for entry in self.argument_roles]
        if len(set(role_keys)) != len(role_keys):
            raise ValueError("duplicate template argument role key")
        if set(role_keys).intersection(set(constraint_keys) | set(binding_keys)):
            raise ValueError("template argument roles cannot override resource or selector keys")
        return self

    def resolved_effects(self) -> tuple[TemplateEffect, ...]:
        if self.effects:
            return self.effects
        return (
            TemplateEffect(
                key="primary",
                capability=self.capability or "",
                bindings=self.bindings,
                max_resource_cardinality=self.max_resource_cardinality,
                declared_reference_precision=self.declared_reference_precision,
            ),
        )


class SecurityPackManifest(BaseModel):
    id: str
    version: str
    title: str
    description: str
    origin: Literal["BUILTIN", "DECLARATIVE"] = "BUILTIN"
    dependencies: tuple[SecurityPackDependency, ...] = ()
    capabilities: tuple[PackCapability, ...]
    resource_types: tuple[PackResourceType, ...] = ()
    templates: tuple[ToolContractTemplate, ...] = ()
    semantic_categories: tuple[str, ...] = ()

    model_config = ConfigDict(extra="forbid", frozen=True)

    @model_validator(mode="after")
    def validate_manifest(self) -> "SecurityPackManifest":
        if not PACK_ID_PATTERN.fullmatch(self.id):
            raise ValueError("invalid security pack id")
        parse_security_pack_version(self.version)
        if len(self.capabilities) > 128 or len(self.resource_types) > 128 or len(self.templates) > 128:
            raise ValueError("security pack manifest exceeds bounded collection limits")
        if len(self.dependencies) > 32 or len(self.semantic_categories) > 128:
            raise ValueError("security pack manifest exceeds bounded metadata limits")
        dependency_ids = [item.pack_id for item in self.dependencies]
        if len(dependency_ids) != len(set(dependency_ids)):
            raise ValueError("duplicate security pack dependency")
        if self.id in dependency_ids:
            raise ValueError("security pack cannot depend on itself")
        capability_ids = [item.id for item in self.capabilities]
        resource_ids = [item.id for item in self.resource_types]
        template_ids = [item.id for item in self.templates]
        for value in capability_ids + resource_ids + template_ids:
            if not SECURITY_ID_PATTERN.fullmatch(value):
                raise ValueError("invalid security pack identifier")
        if len(capability_ids) != len(set(capability_ids)):
            raise ValueError("duplicate capability in security pack")
        if len(resource_ids) != len(set(resource_ids)):
            raise ValueError("duplicate resource type in security pack")
        if len(template_ids) != len(set(template_ids)):
            raise ValueError("duplicate template in security pack")
        known_capabilities = set(capability_ids)
        known_resources = set(resource_ids)
        capability_map = {item.id: item for item in self.capabilities}
        for capability in self.capabilities:
            if capability.requires_resource and not capability.allowed_resource_types:
                raise ValueError("resource capability requires allowed resource types")
        for template in self.templates:
            for effect in template.resolved_effects():
                if effect.capability not in known_capabilities:
                    raise ValueError("template references unknown pack capability")
                capability = capability_map[effect.capability]
                if any(
                    binding.resource_type not in known_resources
                    for binding in effect.bindings
                ):
                    raise ValueError("template references unknown pack resource type")
                if capability.requires_resource and not effect.bindings:
                    raise ValueError("resource capability template effect requires bindings")
                if not capability.requires_resource and effect.bindings:
                    raise ValueError("non-resource capability template effect cannot bind resources")
                if any(
                    binding.resource_type not in capability.allowed_resource_types
                    for binding in effect.bindings
                ):
                    raise ValueError("template binding resource type is not allowed by capability")
        return self


def security_pack_manifest_hash(manifest: SecurityPackManifest) -> str:
    return sha256_canonical_json(manifest.model_dump(mode="json"))


class SecurityPackInstalledVersion(BaseModel):
    version: str
    manifest: SecurityPackManifest
    manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    installed_at: str | None = None
    signature_verified: bool = False
    signer_key_fingerprint: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    deprecated: bool = False

    model_config = ConfigDict(extra="forbid", frozen=True)

    @model_validator(mode="after")
    def validate_installed_version(self) -> "SecurityPackInstalledVersion":
        parse_security_pack_version(self.version)
        if self.manifest.version != self.version:
            raise ValueError("installed security pack version does not match manifest")
        if security_pack_manifest_hash(self.manifest) != self.manifest_sha256:
            raise ValueError("installed security pack manifest hash mismatch")
        if self.signer_key_fingerprint is not None and not self.signature_verified:
            raise ValueError("signer fingerprint requires verified signature")
        return self


class SecurityPackInstallation(BaseModel):
    pack_id: str
    active_version: str
    enabled: bool = False
    versions: tuple[SecurityPackInstalledVersion, ...] = Field(min_length=1, max_length=64)

    model_config = ConfigDict(extra="forbid", frozen=True)

    @model_validator(mode="after")
    def validate_installation(self) -> "SecurityPackInstallation":
        if not PACK_ID_PATTERN.fullmatch(self.pack_id):
            raise ValueError("invalid installed security pack id")
        version_ids = [item.version for item in self.versions]
        if len(version_ids) != len(set(version_ids)):
            raise ValueError("duplicate installed security pack version")
        if self.active_version not in version_ids:
            raise ValueError("active security pack version is not installed")
        if any(item.manifest.id != self.pack_id for item in self.versions):
            raise ValueError("installed security pack id does not match manifest")
        return self

    def active(self) -> SecurityPackInstalledVersion:
        for item in self.versions:
            if item.version == self.active_version:
                return item
        raise SecurityPackError("active_security_pack_version_missing")


def active_lifecycle_manifests(
    installations: Iterable[SecurityPackInstallation],
) -> tuple[SecurityPackManifest, ...]:
    return tuple(
        installation.active().manifest
        for installation in installations
        if installation.enabled
    )


def validate_security_pack_lifecycle(
    security_packs: Iterable[SecurityPackManifest],
    installations: Iterable[SecurityPackInstallation],
) -> None:
    custom = tuple(security_packs)
    installed = tuple(installations)
    if not installed:
        # Backward compatibility for pre-Lot-4 signed revisions.
        SecurityPackRegistry(custom)
        return
    ids = [item.pack_id for item in installed]
    if len(ids) != len(set(ids)):
        raise SecurityPackError("duplicate_security_pack_installation")
    builtin_by_id = {pack.id: pack for pack in builtin_security_packs()}
    if set(ids).intersection(builtin_by_id):
        raise SecurityPackError("builtin_security_pack_cannot_be_managed")
    projected = active_lifecycle_manifests(installed)
    projected_by_id = {pack.id: pack for pack in projected}
    custom_by_id = {pack.id: pack for pack in custom}
    if set(projected_by_id) != set(custom_by_id):
        raise SecurityPackError("security_pack_lifecycle_projection_mismatch")
    for pack_id, manifest in projected_by_id.items():
        if security_pack_manifest_hash(manifest) != security_pack_manifest_hash(custom_by_id[pack_id]):
            raise SecurityPackError("security_pack_lifecycle_projection_mismatch")
    SecurityPackRegistry(projected)

    installed_by_id = {item.pack_id: item for item in installed}
    for installation in installed:
        for version_record in installation.versions:
            for dependency in version_record.manifest.dependencies:
                builtin = builtin_by_id.get(dependency.pack_id)
                if builtin is not None:
                    if not dependency.accepts(builtin.version):
                        raise SecurityPackError("security_pack_dependency_version_unsatisfied")
                    continue
                dependency_install = installed_by_id.get(dependency.pack_id)
                if dependency_install is None:
                    raise SecurityPackError("security_pack_dependency_missing")
                if not any(dependency.accepts(item.version) for item in dependency_install.versions):
                    raise SecurityPackError("security_pack_dependency_version_unsatisfied")

        if not installation.enabled:
            continue
        active_manifest = installation.active().manifest
        for dependency in active_manifest.dependencies:
            if dependency.pack_id in builtin_by_id:
                continue
            dependency_install = installed_by_id[dependency.pack_id]
            if not dependency_install.enabled:
                raise SecurityPackError("enabled_security_pack_dependency_disabled")
            if not dependency.accepts(dependency_install.active_version):
                raise SecurityPackError("enabled_security_pack_dependency_version_unsatisfied")

    graph: dict[str, set[str]] = {}
    for installation in installed:
        active_manifest = installation.active().manifest
        graph[installation.pack_id] = {
            dependency.pack_id
            for dependency in active_manifest.dependencies
            if dependency.pack_id in installed_by_id
        }
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(pack_id: str) -> None:
        if pack_id in visiting:
            raise SecurityPackError("security_pack_dependency_cycle")
        if pack_id in visited:
            return
        visiting.add(pack_id)
        for dependency_id in graph.get(pack_id, set()):
            visit(dependency_id)
        visiting.remove(pack_id)
        visited.add(pack_id)

    for pack_id in graph:
        visit(pack_id)


class SecurityPackRegistry:
    def __init__(
        self,
        additional_packs: Iterable[SecurityPackManifest] = (),
    ) -> None:
        packs = (*builtin_security_packs(), *tuple(additional_packs))
        self._packs: dict[str, SecurityPackManifest] = {}
        self._capabilities: dict[str, PackCapability] = {}
        self._resource_types: dict[str, PackResourceType] = {}
        self._templates: dict[str, tuple[SecurityPackManifest, ToolContractTemplate]] = {}
        for pack in packs:
            if pack.id in self._packs:
                raise SecurityPackError("duplicate_security_pack")
            self._packs[pack.id] = pack
            for capability in pack.capabilities:
                if capability.id in self._capabilities:
                    raise SecurityPackError("duplicate_pack_capability")
                self._capabilities[capability.id] = capability
            for resource_type in pack.resource_types:
                if resource_type.id in self._resource_types:
                    raise SecurityPackError("duplicate_pack_resource_type")
                self._resource_types[resource_type.id] = resource_type
            for template in pack.templates:
                if template.id in self._templates:
                    raise SecurityPackError("duplicate_pack_template")
                self._templates[template.id] = (pack, template)
        for capability in self._capabilities.values():
            if any(value not in self._resource_types for value in capability.allowed_resource_types):
                raise SecurityPackError("capability_resource_type_unavailable")

    def packs(self) -> tuple[SecurityPackManifest, ...]:
        return tuple(self._packs[key] for key in sorted(self._packs))

    def capability(self, capability_id: str) -> PackCapability:
        try:
            return self._capabilities[capability_id]
        except KeyError as exc:
            raise SecurityPackError("unknown_pack_capability") from exc

    def resource_type(self, resource_type_id: str) -> PackResourceType:
        try:
            return self._resource_types[resource_type_id]
        except KeyError as exc:
            raise SecurityPackError("unknown_pack_resource_type") from exc

    def template(
        self,
        template_id: str,
    ) -> tuple[SecurityPackManifest, ToolContractTemplate]:
        try:
            return self._templates[template_id]
        except KeyError as exc:
            raise SecurityPackError("unknown_pack_template") from exc

    def templates(self) -> tuple[tuple[SecurityPackManifest, ToolContractTemplate], ...]:
        return tuple(self._templates[key] for key in sorted(self._templates))


def builtin_security_packs() -> tuple[SecurityPackManifest, ...]:
    return (
        _core_pack(),
        _filesystem_pack(),
        _http_pack(),
        _database_pack(),
        _messaging_pack(),
        _cloud_pack(),
        _calendar_pack(),
        _payments_pack(),
        _process_pack(),
        _trusted_adapter_examples_pack(),
    )


def _resource(
    resource_id: str,
    canonicalizer: str = "hierarchical_name",
    *,
    hierarchy: bool = True,
    adapter_id: str = "generic-declarative",
    specialized: bool = False,
) -> PackResourceType:
    return PackResourceType(
        id=resource_id,
        canonicalizer=canonicalizer,
        hierarchy_support=hierarchy,
        allowed_matching_modes=("SELF", "SUBTREE") if hierarchy else ("SELF",),
        adapter_id=adapter_id,
        requires_specialized_interpretation=specialized,
    )


def _capability(
    capability_id: str,
    resource_types: tuple[str, ...] = (),
    *,
    destructive: bool = False,
    external: bool = False,
) -> PackCapability:
    domain, verb = capability_id.rsplit(".", 1)
    return PackCapability(
        id=capability_id,
        domain=domain,
        verb=verb,
        destructive=destructive,
        external_effect=external,
        requires_resource=bool(resource_types),
        allowed_resource_types=resource_types,
    )


def _template(
    template_id: str,
    title: str,
    capability: str,
    resource_type: str | None,
    hints: tuple[str, ...],
    keywords: tuple[str, ...],
) -> ToolContractTemplate:
    bindings = (
        TemplateBinding(
            key="resource",
            resource_type=resource_type,
            argument_hints=hints,
        ),
    ) if resource_type else ()
    return ToolContractTemplate(
        id=template_id,
        title=title,
        description=f"Govern a {capability} tool.",
        capability=capability,
        keywords=keywords,
        bindings=bindings,
        max_resource_cardinality=100 if resource_type else None,
    )


def _core_pack() -> SecurityPackManifest:
    resource = _resource("hierarchical_name")
    capabilities = (
        _capability("system.ping"),
        _capability("identity.read", (resource.id,)),
        _capability("identity.manage", (resource.id,), destructive=True, external=True),
        _capability("secret.read", (resource.id,)),
    )
    return SecurityPackManifest(
        id="core",
        version="1.0.0",
        title="Core",
        description="Generic identities, secrets and non-resource health operations.",
        capabilities=capabilities,
        resource_types=(resource,),
        templates=(
            _template("core.system-ping", "System Ping", "system.ping", None, (), ("ping", "health", "status")),
            _template("core.identity-read", "Read Identity", "identity.read", resource.id, ("user", "account", "identity", "id"), ("get user", "read account", "identity")),
            _template("core.secret-read", "Read Secret Reference", "secret.read", resource.id, ("secret", "name", "id"), ("read secret", "get secret", "vault")),
        ),
        semantic_categories=("cross_tenant_access", "privilege_escalation"),
    )


def _filesystem_pack() -> SecurityPackManifest:
    resource = _resource(
        "filesystem_path",
        "filesystem_path",
        adapter_id="filesystem",
        specialized=True,
    )
    capabilities = tuple(
        _capability(
            f"filesystem.{verb}",
            (resource.id,),
            destructive=verb == "delete",
        )
        for verb in ("read", "list", "write", "delete")
    )
    return SecurityPackManifest(
        id="filesystem",
        version="1.0.0",
        title="Filesystem",
        description="Filesystem reads, listings, writes and destructive operations.",
        capabilities=capabilities,
        resource_types=(resource,),
        templates=tuple(
            _template(
                f"filesystem.{verb}",
                f"{verb.title()} Filesystem",
                f"filesystem.{verb}",
                resource.id,
                ("path", "file", "directory", "folder", "root"),
                (verb, "file", "folder", "directory"),
            )
            for verb in ("read", "list", "write", "delete")
        ),
        semantic_categories=("unexpected_destructive_operation", "sensitive_path_access"),
    )


def _http_pack() -> SecurityPackManifest:
    resource = _resource("url", "url", adapter_id="url", specialized=True)
    capabilities = (
        _capability("network.request", (resource.id,), external=True),
        _capability("network.send", (resource.id,), external=True),
    )
    return SecurityPackManifest(
        id="http-api",
        version="1.0.0",
        title="HTTP and API",
        description="Outbound HTTP requests and data transmission.",
        capabilities=capabilities,
        resource_types=(resource,),
        templates=(
            _template("http.request", "Call HTTP API", "network.request", resource.id, ("url", "endpoint", "uri", "host"), ("http", "api", "request", "fetch")),
            _template("http.send", "Send Data", "network.send", resource.id, ("url", "endpoint", "destination", "webhook"), ("send", "upload", "webhook", "post")),
        ),
        semantic_categories=("server_side_request_forgery", "data_exfiltration"),
    )


def _database_pack() -> SecurityPackManifest:
    resource = _resource("database_object")
    capabilities = tuple(
        _capability(
            f"database.{verb}",
            (resource.id,),
            destructive=verb == "delete",
        )
        for verb in ("read", "write", "delete")
    )
    return SecurityPackManifest(
        id="database",
        version="1.0.0",
        title="Database",
        description="Database, schema, table and collection operations.",
        capabilities=capabilities,
        resource_types=(resource,),
        templates=tuple(
            _template(f"database.{verb}", f"{verb.title()} Database", f"database.{verb}", resource.id, ("database", "schema", "table", "collection"), (verb, "query", "database", "table"))
            for verb in ("read", "write", "delete")
        ),
        semantic_categories=("cross_tenant_access", "unbounded_query", "unexpected_destructive_operation"),
    )


def _messaging_pack() -> SecurityPackManifest:
    address = _resource("email_address", "email_address", hierarchy=False)
    mailbox = _resource("mailbox")
    capabilities = (
        _capability("message.send", (address.id,), external=True),
        _capability("message.read", (mailbox.id,)),
        _capability("message.delete", (mailbox.id,), destructive=True, external=True),
    )
    return SecurityPackManifest(
        id="messaging",
        version="1.0.0",
        title="Messaging",
        description="Email and message operations.",
        capabilities=capabilities,
        resource_types=(address, mailbox),
        templates=(
            _template("messaging.send", "Send Message", "message.send", address.id, ("to", "recipient", "email", "address"), ("send", "email", "message")),
            _template("messaging.read", "Read Messages", "message.read", mailbox.id, ("mailbox", "folder", "account"), ("read", "list", "email", "message")),
            _template("messaging.delete", "Delete Message", "message.delete", mailbox.id, ("message", "mailbox", "id"), ("delete", "remove", "email", "message")),
        ),
        semantic_categories=("external_recipient", "bulk_messaging", "user_deception"),
    )


def _cloud_pack() -> SecurityPackManifest:
    resource = _resource("cloud_object")
    capabilities = tuple(
        _capability(
            f"cloud.object.{verb}",
            (resource.id,),
            destructive=verb == "delete",
            external=verb != "read",
        )
        for verb in ("read", "write", "delete")
    )
    return SecurityPackManifest(
        id="cloud-storage",
        version="1.0.0",
        title="Cloud Storage",
        description="Buckets, containers and cloud objects.",
        capabilities=capabilities,
        resource_types=(resource,),
        templates=tuple(
            _template(f"cloud-object.{verb}", f"{verb.title()} Cloud Object", f"cloud.object.{verb}", resource.id, ("bucket", "container", "object", "key"), (verb, "bucket", "object", "storage"))
            for verb in ("read", "write", "delete")
        ),
        semantic_categories=("public_sharing", "cross_account_access"),
    )


def _calendar_pack() -> SecurityPackManifest:
    resource = _resource("calendar_object")
    capabilities = tuple(
        _capability(
            f"calendar.{verb}",
            (resource.id,),
            destructive=verb == "delete",
            external=verb != "read",
        )
        for verb in ("read", "write", "delete")
    )
    return SecurityPackManifest(
        id="calendar",
        version="1.0.0",
        title="Calendar",
        description="Calendars and events.",
        capabilities=capabilities,
        resource_types=(resource,),
        templates=tuple(
            _template(f"calendar.{verb}", f"{verb.title()} Calendar", f"calendar.{verb}", resource.id, ("calendar", "event", "id"), (verb, "calendar", "event", "meeting"))
            for verb in ("read", "write", "delete")
        ),
        semantic_categories=("external_invitation", "user_deception"),
    )


def _payments_pack() -> SecurityPackManifest:
    resource = _resource("payment_account")
    capabilities = (
        _capability("payment.read", (resource.id,)),
        _capability("payment.initiate", (resource.id,), destructive=True, external=True),
        _capability("payment.refund", (resource.id,), destructive=True, external=True),
    )
    return SecurityPackManifest(
        id="payments",
        version="1.0.0",
        title="Payments",
        description="Payment accounts, transfers and refunds.",
        capabilities=capabilities,
        resource_types=(resource,),
        templates=(
            _template("payment.read", "Read Payment", "payment.read", resource.id, ("account", "merchant", "payment", "id"), ("read", "payment", "transaction", "balance")),
            _template("payment.initiate", "Initiate Payment", "payment.initiate", resource.id, ("account", "merchant", "recipient", "beneficiary"), ("pay", "payment", "transfer", "purchase")),
            _template("payment.refund", "Refund Payment", "payment.refund", resource.id, ("account", "merchant", "payment", "transaction"), ("refund", "reimburse", "payment", "transaction")),
        ),
        semantic_categories=(
            "unauthorized_financial_transaction",
            "cross_tenant_access",
            "user_deception",
        ),
    )


def _process_pack() -> SecurityPackManifest:
    resource = _resource("process_command")
    capability = _capability("process.execute", (resource.id,), destructive=True, external=True)
    return SecurityPackManifest(
        id="process",
        version="1.0.0",
        title="Process Execution",
        description="Explicit command and process execution.",
        capabilities=(capability,),
        resource_types=(resource,),
        templates=(
            _template("process.execute", "Execute Process", capability.id, resource.id, ("command", "script", "executable", "program"), ("execute", "command", "shell", "script", "process")),
        ),
        semantic_categories=("shell_injection", "privilege_escalation"),
    )


def _trusted_adapter_examples_pack() -> SecurityPackManifest:
    resources = (
        _resource("sql_database_object", adapter_id="sql", specialized=True),
        _resource("shell_executable", adapter_id="shell", specialized=True),
        _resource("payment_destination", adapter_id="payment", specialized=True),
        _resource("cloud_iam_resource", adapter_id="cloud-iam", specialized=True),
        _resource("git_repository_ref", adapter_id="git", specialized=True),
        _resource("message_destination", adapter_id="messaging", specialized=True),
    )
    capabilities = (
        _capability("database.sql.read", (resources[0].id,)),
        _capability("database.sql.write", (resources[0].id,), external=True),
        _capability("database.sql.delete", (resources[0].id,), destructive=True, external=True),
        _capability("process.shell.execute", (resources[1].id,), destructive=True, external=True),
        _capability("payment.transfer.execute", (resources[2].id,), destructive=True, external=True),
        _capability("cloud.iam.mutate", (resources[3].id,), destructive=True, external=True),
        _capability("git.repository.write", (resources[4].id,), destructive=True, external=True),
        _capability("message.delivery.send", (resources[5].id,), external=True),
    )
    templates = (
        _template("trusted.sql-read", "Read with SQL", capabilities[0].id, resources[0].id, ("query", "sql", "statement"), ("select", "sql", "query", "database")),
        _template("trusted.sql-write", "Write with SQL", capabilities[1].id, resources[0].id, ("query", "sql", "statement"), ("insert", "update", "sql", "database")),
        _template("trusted.sql-delete", "Delete with SQL", capabilities[2].id, resources[0].id, ("query", "sql", "statement"), ("delete", "sql", "database")),
        _template("trusted.shell", "Execute Shell Command", capabilities[3].id, resources[1].id, ("command", "script"), ("shell", "command", "execute")),
        ToolContractTemplate(
            id="trusted.payment",
            title="Execute Payment Transfer",
            description="Execute a payment transfer with a positive bounded amount.",
            capability=capabilities[4].id,
            keywords=("payment", "transfer", "pay"),
            bindings=(TemplateBinding(
                key="resource",
                resource_type=resources[2].id,
                argument_hints=("recipient", "beneficiary", "destination"),
            ),),
            constraints=(TemplateArgumentConstraint(
                key="amount",
                operator="GT",
                value=0,
                argument_hints=("amount", "value", "total"),
            ),),
            max_resource_cardinality=1,
        ),
        _template("trusted.cloud-iam", "Mutate Cloud IAM", capabilities[5].id, resources[3].id, ("arn", "resource", "principal", "role"), ("iam", "policy", "permission", "role")),
        _template("trusted.git", "Write Git Repository", capabilities[6].id, resources[4].id, ("repository", "repo", "ref", "branch"), ("git", "commit", "branch", "repository")),
        _template("trusted.messaging", "Send to Messaging Destination", capabilities[7].id, resources[5].id, ("recipient", "channel", "topic", "destination"), ("send", "message", "channel", "topic")),
    )
    return SecurityPackManifest(
        id="trusted-adapter-examples",
        version="1.0.0",
        title="Trusted Adapter SDK Examples",
        description="Reviewed specialized adapters for common high-risk MCP tool families.",
        capabilities=capabilities,
        resource_types=resources,
        templates=templates,
        semantic_categories=(
            "sql_injection",
            "shell_injection",
            "unauthorized_financial_transaction",
            "privilege_escalation",
            "source_control_write",
            "external_recipient",
        ),
    )
