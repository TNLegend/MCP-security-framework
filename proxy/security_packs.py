from __future__ import annotations

import re
from typing import Iterable, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


PACK_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
SECURITY_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")


class SecurityPackError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class PackCapability(BaseModel):
    id: str
    domain: str
    verb: str
    destructive: bool = False
    external_effect: bool = False
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
    required: bool = True
    multiple: bool = False
    argument_hints: tuple[str, ...] = ()

    model_config = ConfigDict(extra="forbid", frozen=True)


class ToolContractTemplate(BaseModel):
    id: str
    title: str
    description: str
    capability: str
    keywords: tuple[str, ...] = ()
    bindings: tuple[TemplateBinding, ...] = ()
    max_resource_cardinality: int | None = Field(default=None, ge=1, le=1000)
    declared_reference_precision: Literal["EXPLICIT"] = "EXPLICIT"

    model_config = ConfigDict(extra="forbid", frozen=True)


class SecurityPackManifest(BaseModel):
    id: str
    version: str
    title: str
    description: str
    origin: Literal["BUILTIN", "DECLARATIVE"] = "BUILTIN"
    capabilities: tuple[PackCapability, ...]
    resource_types: tuple[PackResourceType, ...] = ()
    templates: tuple[ToolContractTemplate, ...] = ()
    semantic_categories: tuple[str, ...] = ()

    model_config = ConfigDict(extra="forbid", frozen=True)

    @model_validator(mode="after")
    def validate_manifest(self) -> "SecurityPackManifest":
        if not PACK_ID_PATTERN.fullmatch(self.id):
            raise ValueError("invalid security pack id")
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
        for capability in self.capabilities:
            if capability.requires_resource and not capability.allowed_resource_types:
                raise ValueError("resource capability requires allowed resource types")
        for template in self.templates:
            if template.capability not in known_capabilities:
                raise ValueError("template references unknown pack capability")
            if any(binding.resource_type not in known_resources for binding in template.bindings):
                raise ValueError("template references unknown pack resource type")
        return self


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
