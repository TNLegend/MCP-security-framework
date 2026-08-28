from __future__ import annotations

from abc import abstractmethod
import re
import shlex
import unicodedata
from typing import Any

from proxy.resource_adapters_v2 import (
    AdapterManifest,
    AdapterResultInspection,
    CanonicalAdapterReference,
    ResourceAdapter,
    _resolve_declaratively,
)
from proxy.tool_security_v2 import (
    AdapterResolution,
    CapabilityCatalog,
    NormalizedEffectFacts,
    ResourceTypeRegistry,
    SecurityModelError,
    ToolEffect,
)


SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,511}$")
SQL_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_$]*(?:\.[A-Za-z_][A-Za-z0-9_$]*){0,2}$")
SQL_RESOURCE = re.compile(
    r"\b(?:from|join|update|into|table)\s+([A-Za-z_][A-Za-z0-9_$]*(?:\.[A-Za-z_][A-Za-z0-9_$]*){0,2})\b",
    re.IGNORECASE,
)
SHELL_META = re.compile(r"(?:&&|\|\||[;&|<>`$*?{}~()%^]|\r|\n|\x00)")
ARN_PATTERN = re.compile(
    r"^arn:(aws|aws-us-gov|aws-cn):([a-z0-9-]+):([a-z0-9-]*):([0-9]{0,12}):(.+)$",
    re.IGNORECASE,
)
GIT_REPOSITORY = re.compile(
    r"^(?:(https?://|ssh://|git@)?([^/:\s]+)[:/])?([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?(?:#([A-Za-z0-9_./-]+))?$"
)
PAYMENT_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$")
MESSAGE_DESTINATION = re.compile(
    r"^(?:[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+|(?:channel|topic|queue|user):[A-Za-z0-9_.:@/-]+)$",
    re.IGNORECASE,
)


class SpecializedAdapter(ResourceAdapter):
    def __init__(
        self,
        resource_types: ResourceTypeRegistry,
        capabilities: CapabilityCatalog,
    ) -> None:
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
            reference_normalizer=lambda resource_type, value, config: self.normalize_reference(
                resource_type,
                value,
                config,
                effect.capability,
            ),
        )

    def canonical_reference(
        self,
        resource_type: str,
        value: str,
        authority_config: dict[str, Any],
        *,
        flags: tuple[str, ...] = (),
        sensitivity: str = "internal",
    ) -> CanonicalAdapterReference:
        canonical, ancestors = self.resource_types.canonicalize(
            resource_type,
            value,
            authority_config,
        )
        return CanonicalAdapterReference(
            canonical_value=canonical,
            ancestors=ancestors,
            resource_sensitivity=sensitivity,
            resource_flags=flags,
        )

    @abstractmethod
    def normalize_reference(
        self,
        resource_type: str,
        value: Any,
        authority_config: dict[str, Any],
        capability: str,
    ) -> tuple[CanonicalAdapterReference, ...]:
        raise NotImplementedError

    def inspect_result(self, result: Any) -> AdapterResultInspection:
        if not isinstance(result, dict):
            return AdapterResultInspection(True, ("adapter_result_envelope_invalid",))
        structured = result.get("structuredContent")
        if structured is not None and not isinstance(structured, dict):
            return AdapterResultInspection(True, ("adapter_result_structured_content_invalid",))
        return self.inspect_structured_result(structured or {})

    def inspect_structured_result(
        self,
        structured: dict[str, Any],
    ) -> AdapterResultInspection:
        return AdapterResultInspection()


class SQLAdapter(SpecializedAdapter):
    manifest = AdapterManifest(
        adapter_id="sql",
        adapter_api_version="1",
        implementation_version="1.0.0",
        supported_capabilities=(
            "database.sql.read",
            "database.sql.write",
            "database.sql.delete",
        ),
        supported_resource_types=("sql_database_object",),
        display_name="SQL Statement",
        family="database",
        argument_validation="single_statement_and_object_extraction",
        result_validation="bounded_structured_rows",
    )

    def normalize_reference(self, resource_type, value, authority_config, capability):
        if resource_type != "sql_database_object" or not isinstance(value, str):
            raise SecurityModelError("sql_statement_invalid")
        statement = unicodedata.normalize("NFC", value).strip()
        if not statement or len(statement) > 65_536 or "\x00" in statement:
            raise SecurityModelError("sql_statement_invalid")
        if "--" in statement or "/*" in statement or "*/" in statement:
            raise SecurityModelError("sql_comments_unsupported")
        body = statement[:-1].rstrip() if statement.endswith(";") else statement
        if ";" in body:
            raise SecurityModelError("sql_multiple_statements")
        operation = body.split(None, 1)[0].upper() if body.split(None, 1) else ""
        if operation not in {"SELECT", "INSERT", "UPDATE", "DELETE", "MERGE"}:
            raise SecurityModelError("sql_operation_unsupported")
        allowed_operations = {
            "database.sql.read": {"SELECT"},
            "database.sql.write": {"INSERT", "UPDATE", "MERGE"},
            "database.sql.delete": {"DELETE"},
        }
        if operation not in allowed_operations.get(capability, set()):
            raise SecurityModelError("sql_operation_capability_mismatch")
        objects = tuple(dict.fromkeys(match.group(1) for match in SQL_RESOURCE.finditer(body)))
        if not objects or len(objects) > 64:
            raise SecurityModelError("sql_resource_extraction_failed")
        case_sensitive = bool(authority_config.get("case_sensitive", False))
        return tuple(
            self.canonical_reference(
                resource_type,
                identifier if case_sensitive else identifier.lower(),
                authority_config,
                flags=(f"sql_operation:{operation.lower()}",),
            )
            for identifier in objects
            if SQL_IDENTIFIER.fullmatch(identifier)
        ) or _raise("sql_resource_extraction_failed")

    def inspect_structured_result(self, structured: dict[str, Any]) -> AdapterResultInspection:
        rows = structured.get("rows")
        if rows is not None and (not isinstance(rows, list) or len(rows) > 10_000):
            return AdapterResultInspection(True, ("sql_result_rows_invalid",))
        return AdapterResultInspection()


class ShellAdapter(SpecializedAdapter):
    manifest = AdapterManifest(
        adapter_id="shell",
        adapter_api_version="1",
        implementation_version="1.0.0",
        supported_capabilities=("process.shell.execute",),
        supported_resource_types=("shell_executable",),
        display_name="Shell Command",
        family="process",
        argument_validation="argv_only_no_shell_operators",
        result_validation="typed_exit_status",
    )

    def normalize_reference(self, resource_type, value, authority_config, capability):
        if resource_type != "shell_executable" or not isinstance(value, str):
            raise SecurityModelError("shell_command_invalid")
        command = unicodedata.normalize("NFC", value).strip()
        if not command or len(command) > 16_384 or SHELL_META.search(command):
            raise SecurityModelError("shell_control_operator_unsupported")
        try:
            argv = shlex.split(command, posix=True)
        except ValueError as exc:
            raise SecurityModelError("shell_command_invalid") from exc
        if not argv or len(argv) > 256 or any(len(part) > 4096 for part in argv):
            raise SecurityModelError("shell_command_invalid")
        executable = argv[0].replace("\\", "/")
        if not SAFE_IDENTIFIER.fullmatch(executable):
            raise SecurityModelError("shell_executable_invalid")
        if executable.startswith("/"):
            executable = f"abs:{executable[1:]}"
        return (self.canonical_reference(
            resource_type,
            executable,
            authority_config,
            flags=("process_execution",),
        ),)

    def inspect_structured_result(self, structured: dict[str, Any]) -> AdapterResultInspection:
        exit_code = structured.get("exit_code")
        if exit_code is not None and (not isinstance(exit_code, int) or isinstance(exit_code, bool)):
            return AdapterResultInspection(True, ("shell_result_exit_code_invalid",))
        for field in ("stdout", "stderr"):
            if field in structured and not isinstance(structured[field], str):
                return AdapterResultInspection(True, (f"shell_result_{field}_invalid",))
        return AdapterResultInspection()


class PaymentAdapter(SpecializedAdapter):
    manifest = AdapterManifest(
        adapter_id="payment",
        adapter_api_version="1",
        implementation_version="1.0.0",
        supported_capabilities=("payment.transfer.execute",),
        supported_resource_types=("payment_destination",),
        display_name="Payment Destination",
        family="payments",
        argument_validation="bounded_destination_reference",
        result_validation="known_payment_status",
    )

    def normalize_reference(self, resource_type, value, authority_config, capability):
        if resource_type != "payment_destination" or not isinstance(value, str):
            raise SecurityModelError("payment_destination_invalid")
        normalized = unicodedata.normalize("NFC", value).strip()
        if not PAYMENT_REFERENCE.fullmatch(normalized):
            raise SecurityModelError("payment_destination_invalid")
        return (self.canonical_reference(
            resource_type,
            normalized,
            authority_config,
            flags=("financial_destination",),
            sensitivity="confidential",
        ),)

    def inspect_structured_result(self, structured: dict[str, Any]) -> AdapterResultInspection:
        status = structured.get("status")
        if status is not None and status not in {"pending", "authorized", "succeeded", "failed", "cancelled", "refunded"}:
            return AdapterResultInspection(True, ("payment_result_status_invalid",))
        return AdapterResultInspection()


class CloudIAMAdapter(SpecializedAdapter):
    manifest = AdapterManifest(
        adapter_id="cloud-iam",
        adapter_api_version="1",
        implementation_version="1.0.0",
        supported_capabilities=("cloud.iam.mutate",),
        supported_resource_types=("cloud_iam_resource",),
        display_name="Cloud IAM Resource",
        family="cloud-iam",
        argument_validation="canonical_arn_or_provider_resource",
        result_validation="bounded_changed_resources",
    )

    def normalize_reference(self, resource_type, value, authority_config, capability):
        if resource_type != "cloud_iam_resource" or not isinstance(value, str):
            raise SecurityModelError("cloud_iam_resource_invalid")
        normalized = unicodedata.normalize("NFC", value).strip()
        arn = ARN_PATTERN.fullmatch(normalized)
        if arn:
            canonical = "arn:" + ":".join(part.lower() for part in arn.groups()[:4]) + ":" + arn.group(5)
        elif SAFE_IDENTIFIER.fullmatch(normalized) and ":" in normalized:
            canonical = normalized.lower()
        else:
            raise SecurityModelError("cloud_iam_resource_invalid")
        return (self.canonical_reference(
            resource_type,
            canonical,
            authority_config,
            flags=("iam_mutation",),
            sensitivity="confidential",
        ),)

    def inspect_structured_result(self, structured: dict[str, Any]) -> AdapterResultInspection:
        changed = structured.get("changed_resources")
        if changed is not None and (not isinstance(changed, list) or len(changed) > 1000):
            return AdapterResultInspection(True, ("cloud_iam_result_resources_invalid",))
        return AdapterResultInspection()


class GitAdapter(SpecializedAdapter):
    manifest = AdapterManifest(
        adapter_id="git",
        adapter_api_version="1",
        implementation_version="1.0.0",
        supported_capabilities=("git.repository.write",),
        supported_resource_types=("git_repository_ref",),
        display_name="Git Repository",
        family="source-control",
        argument_validation="canonical_repository_and_ref",
        result_validation="bounded_changed_files",
    )

    def normalize_reference(self, resource_type, value, authority_config, capability):
        if resource_type != "git_repository_ref" or not isinstance(value, str):
            raise SecurityModelError("git_repository_invalid")
        normalized = unicodedata.normalize("NFC", value).strip()
        match = GIT_REPOSITORY.fullmatch(normalized)
        if not match:
            raise SecurityModelError("git_repository_invalid")
        _, host, owner, repository, ref = match.groups()
        canonical = "/".join(part for part in ((host or "local").lower(), owner.lower(), repository.lower()) if part)
        if ref:
            canonical = f"{canonical}:{ref}"
        return (self.canonical_reference(
            resource_type,
            canonical,
            authority_config,
            flags=("source_control_write",),
        ),)

    def inspect_structured_result(self, structured: dict[str, Any]) -> AdapterResultInspection:
        changed = structured.get("changed_files")
        if changed is not None and (not isinstance(changed, list) or len(changed) > 10_000):
            return AdapterResultInspection(True, ("git_result_changed_files_invalid",))
        return AdapterResultInspection()


class MessagingAdapter(SpecializedAdapter):
    manifest = AdapterManifest(
        adapter_id="messaging",
        adapter_api_version="1",
        implementation_version="1.0.0",
        supported_capabilities=("message.delivery.send",),
        supported_resource_types=("message_destination",),
        display_name="Messaging Destination",
        family="messaging",
        argument_validation="canonical_address_or_channel",
        result_validation="bounded_delivery_receipts",
    )

    def normalize_reference(self, resource_type, value, authority_config, capability):
        if resource_type != "message_destination" or not isinstance(value, str):
            raise SecurityModelError("message_destination_invalid")
        normalized = unicodedata.normalize("NFC", value).strip()
        if not MESSAGE_DESTINATION.fullmatch(normalized):
            raise SecurityModelError("message_destination_invalid")
        if "@" in normalized and not normalized.lower().startswith(("channel:", "topic:", "queue:", "user:")):
            local, domain = normalized.rsplit("@", 1)
            if not re.fullmatch(r"[A-Za-z0-9_.-]+", local):
                raise SecurityModelError("message_destination_invalid")
            normalized = f"email:{local}:{domain.lower()}"
        return (self.canonical_reference(
            resource_type,
            normalized,
            authority_config,
            flags=("external_message_destination",),
        ),)

    def inspect_structured_result(self, structured: dict[str, Any]) -> AdapterResultInspection:
        receipts = structured.get("receipts")
        if receipts is not None and (not isinstance(receipts, list) or len(receipts) > 1000):
            return AdapterResultInspection(True, ("messaging_result_receipts_invalid",))
        return AdapterResultInspection()


def builtin_specialized_adapters(
    resource_types: ResourceTypeRegistry,
    capabilities: CapabilityCatalog,
) -> tuple[ResourceAdapter, ...]:
    return (
        SQLAdapter(resource_types, capabilities),
        ShellAdapter(resource_types, capabilities),
        PaymentAdapter(resource_types, capabilities),
        CloudIAMAdapter(resource_types, capabilities),
        GitAdapter(resource_types, capabilities),
        MessagingAdapter(resource_types, capabilities),
    )


def _raise(code: str):
    raise SecurityModelError(code)
