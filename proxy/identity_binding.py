from dataclasses import dataclass
from pathlib import Path
import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
import yaml

from proxy.identity_config import IdentityBindingConfig


IDENTIFIER_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
MAX_BINDINGS = 1000


class IdentityBindingError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class IdentityBinding(BaseModel):
    issuer: str = Field(min_length=1)
    subject: str = Field(min_length=1)
    agent_id: str = Field(min_length=1)

    model_config = ConfigDict(extra="forbid", frozen=True)

    @field_validator("issuer", "subject", "agent_id")
    @classmethod
    def non_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("identity binding fields must not be empty.")
        if value in {"*", "any", "all"}:
            raise ValueError("wildcard identity bindings are not allowed.")
        return value

    @field_validator("agent_id")
    @classmethod
    def validate_agent_id(cls, value: str) -> str:
        if not IDENTIFIER_PATTERN.fullmatch(value):
            raise ValueError("agent_id has invalid format.")
        return value


class IdentityBindingDocument(BaseModel):
    revision: str = Field(min_length=1)
    bindings: list[IdentityBinding] = Field(default_factory=list)

    model_config = ConfigDict(extra="forbid", frozen=True)

    @model_validator(mode="after")
    def validate_document(self) -> "IdentityBindingDocument":
        if len(self.bindings) > MAX_BINDINGS:
            raise ValueError("too many identity bindings.")
        seen = set()
        for binding in self.bindings:
            key = (binding.issuer, binding.subject)
            if key in seen:
                raise ValueError("duplicate identity binding.")
            seen.add(key)
        return self


@dataclass(frozen=True)
class ResolvedIdentityBinding:
    agent_id: str
    revision: str


class IdentityBindingResolver:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or IdentityBindingConfig.from_env().path
        self._cache_key: tuple[str, int, int] | None = None
        self._cache_document: IdentityBindingDocument | None = None

    def resolve(self, *, issuer: str, subject: str) -> ResolvedIdentityBinding:
        document = self._load_document()
        for binding in document.bindings:
            if binding.issuer == issuer and binding.subject == subject:
                return ResolvedIdentityBinding(
                    agent_id=binding.agent_id,
                    revision=document.revision,
                )
        raise IdentityBindingError("agent_identity_binding_not_found")

    def _load_document(self) -> IdentityBindingDocument:
        try:
            stat = self.path.stat()
        except FileNotFoundError as exc:
            raise IdentityBindingError("agent_identity_binding_unavailable") from exc
        except OSError as exc:
            raise IdentityBindingError("agent_identity_binding_unavailable") from exc

        cache_key = (str(self.path), stat.st_mtime_ns, stat.st_size)
        if self._cache_key == cache_key and self._cache_document is not None:
            return self._cache_document

        try:
            with self.path.open("r", encoding="utf-8") as file:
                data: Any = yaml.safe_load(file)
        except yaml.YAMLError as exc:
            raise IdentityBindingError("agent_identity_binding_unavailable") from exc
        except OSError as exc:
            raise IdentityBindingError("agent_identity_binding_unavailable") from exc

        if not isinstance(data, dict):
            raise IdentityBindingError("agent_identity_binding_unavailable")

        try:
            document = IdentityBindingDocument.model_validate(data)
        except Exception as exc:
            raise IdentityBindingError("agent_identity_binding_unavailable") from exc

        self._cache_key = cache_key
        self._cache_document = document
        return document
