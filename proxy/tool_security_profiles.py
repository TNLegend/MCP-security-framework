from dataclasses import dataclass
from pathlib import Path
import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
import yaml

from proxy.identity_config import ToolSecurityProfilesConfig


IDENTIFIER_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,255}$")
SERVER_REF_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._:/-]{0,511}$")
CAPABILITY_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
MAX_TOOL_PROFILE_BINDINGS = 1000
SUPPORTED_RESOURCE_ADAPTERS = {"filesystem"}
SUPPORTED_OPERATIONS = {"read", "list"}
SUPPORTED_EXPECTED_TYPES = {"file", "directory"}


class ToolSecurityProfileError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class ToolResourceProfile(BaseModel):
    adapter: str = Field(min_length=1)
    argument_name: str = Field(min_length=1, max_length=128)
    expected_type: str = Field(min_length=1)
    relative_base_scope: str | None = None
    allowed_scope_candidates: list[str] = Field(default_factory=list)

    model_config = ConfigDict(extra="forbid", frozen=True)

    @field_validator("adapter")
    @classmethod
    def validate_adapter(cls, value: str) -> str:
        if value not in SUPPORTED_RESOURCE_ADAPTERS:
            raise ValueError("unsupported resource adapter.")
        return value

    @field_validator("argument_name")
    @classmethod
    def validate_argument_name(cls, value: str) -> str:
        return _validate_capability_like(value, "argument_name")

    @field_validator("expected_type")
    @classmethod
    def validate_expected_type(cls, value: str) -> str:
        if value not in SUPPORTED_EXPECTED_TYPES:
            raise ValueError("unsupported expected resource type.")
        return value

    @field_validator("relative_base_scope")
    @classmethod
    def validate_relative_base_scope(cls, value: str | None) -> str | None:
        if value is None:
            return value
        return _validate_identifier(value, "relative_base_scope")

    @field_validator("allowed_scope_candidates")
    @classmethod
    def validate_allowed_scope_candidates(cls, value: list[str]) -> list[str]:
        seen = set()
        for scope in value:
            _validate_identifier(scope, "allowed_scope_candidate")
            if scope in seen:
                raise ValueError("allowed scope candidates must be unique.")
            seen.add(scope)
        return value


class ToolSecurityProfileBinding(BaseModel):
    server_ref: str = Field(min_length=1, max_length=512)
    tool_name: str = Field(min_length=1, max_length=255)
    operation: str = Field(min_length=1)
    required_capability: str = Field(min_length=1, max_length=128)
    resource: ToolResourceProfile

    model_config = ConfigDict(extra="forbid", frozen=True)

    @field_validator("server_ref")
    @classmethod
    def validate_server_ref(cls, value: str) -> str:
        if not SERVER_REF_PATTERN.fullmatch(value):
            raise ValueError("server_ref has invalid format.")
        return value

    @field_validator("tool_name")
    @classmethod
    def validate_tool_name(cls, value: str) -> str:
        return _validate_capability_like(value, "tool_name")

    @field_validator("operation")
    @classmethod
    def validate_operation(cls, value: str) -> str:
        if value not in SUPPORTED_OPERATIONS:
            raise ValueError("unsupported operation.")
        return value

    @field_validator("required_capability")
    @classmethod
    def validate_required_capability(cls, value: str) -> str:
        return _validate_capability_like(value, "required_capability")


class ToolSecurityProfileDocument(BaseModel):
    revision: str = Field(min_length=1)
    bindings: list[ToolSecurityProfileBinding] = Field(default_factory=list)

    model_config = ConfigDict(extra="forbid", frozen=True)

    @model_validator(mode="after")
    def validate_document(self) -> "ToolSecurityProfileDocument":
        if len(self.bindings) > MAX_TOOL_PROFILE_BINDINGS:
            raise ValueError("too many tool security profiles.")
        seen = set()
        for binding in self.bindings:
            key = (binding.server_ref, binding.tool_name)
            if key in seen:
                raise ValueError("duplicate server_ref/tool_name profile.")
            seen.add(key)
        return self


@dataclass(frozen=True)
class ResolvedToolSecurityProfile:
    revision: str
    server_ref: str
    tool_name: str
    operation: str
    required_capability: str
    resource: ToolResourceProfile
    profile_status: str = "resolved"


class ToolSecurityProfileResolver:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or ToolSecurityProfilesConfig.from_env().path
        self._cache_key: tuple[str, int, int] | None = None
        self._cache_document: ToolSecurityProfileDocument | None = None

    def resolve(
        self,
        *,
        server_ref: str,
        tool_name: str,
    ) -> ResolvedToolSecurityProfile:
        document = self._load_document()
        for binding in document.bindings:
            if binding.server_ref == server_ref and binding.tool_name == tool_name:
                return ResolvedToolSecurityProfile(
                    revision=document.revision,
                    server_ref=binding.server_ref,
                    tool_name=binding.tool_name,
                    operation=binding.operation,
                    required_capability=binding.required_capability,
                    resource=binding.resource,
                )
        raise ToolSecurityProfileError("unknown_tool_security_profile")

    def _load_document(self) -> ToolSecurityProfileDocument:
        try:
            stat = self.path.stat()
        except OSError as exc:
            raise ToolSecurityProfileError("tool_security_profile_unavailable") from exc

        cache_key = (str(self.path), stat.st_mtime_ns, stat.st_size)
        if self._cache_key == cache_key and self._cache_document is not None:
            return self._cache_document

        try:
            with self.path.open("r", encoding="utf-8") as file:
                data: Any = yaml.safe_load(file)
        except (OSError, yaml.YAMLError) as exc:
            raise ToolSecurityProfileError("tool_security_profile_unavailable") from exc

        if not isinstance(data, dict):
            raise ToolSecurityProfileError("tool_security_profile_unavailable")

        try:
            document = ToolSecurityProfileDocument.model_validate(data)
        except Exception as exc:
            raise ToolSecurityProfileError("tool_security_profile_unavailable") from exc

        self._cache_key = cache_key
        self._cache_document = document
        return document


def server_ref_for_server(server: dict[str, Any]) -> str:
    explicit = server.get("server_ref")
    if isinstance(explicit, str) and explicit.strip():
        return explicit
    transport = str(server.get("transport") or "streamable_http")
    endpoint = str(server.get("endpoint") or "")
    return f"{transport}:{endpoint}"


def _validate_identifier(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must not be empty.")
    if not IDENTIFIER_PATTERN.fullmatch(value):
        raise ValueError(f"{field_name} has invalid format.")
    return value


def _validate_capability_like(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must not be empty.")
    if not CAPABILITY_PATTERN.fullmatch(value):
        raise ValueError(f"{field_name} has invalid format.")
    return value
