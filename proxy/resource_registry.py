from dataclasses import dataclass
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
import yaml

from proxy.identity_config import ResourceScopesConfig


SCOPE_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
ENV_NAME_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
SUPPORTED_OPERATIONS = {"read", "list"}
SUPPORTED_SENSITIVITIES = {"public", "internal", "private", "confidential", "secret"}
SUPPORTED_SYMLINK_POLICIES = {"deny", "internal-only"}
MAX_FILESYSTEM_SCOPES = 1000


class ResourceRegistryError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class FilesystemScopeConfig(BaseModel):
    root_env: str = Field(min_length=1)
    allowed_operations: list[str] = Field(default_factory=list)
    sensitivity: str = "internal"
    symlink_policy: str = "internal-only"
    denied_patterns: list[str] = Field(default_factory=list)

    model_config = ConfigDict(extra="forbid", frozen=True)

    @field_validator("root_env")
    @classmethod
    def validate_root_env(cls, value: str) -> str:
        if not ENV_NAME_PATTERN.fullmatch(value):
            raise ValueError("root_env has invalid format.")
        return value

    @field_validator("allowed_operations")
    @classmethod
    def validate_allowed_operations(cls, value: list[str]) -> list[str]:
        seen = set()
        for operation in value:
            if operation not in SUPPORTED_OPERATIONS:
                raise ValueError("unsupported filesystem operation.")
            if operation in seen:
                raise ValueError("duplicate operation.")
            seen.add(operation)
        return value

    @field_validator("sensitivity")
    @classmethod
    def validate_sensitivity(cls, value: str) -> str:
        if value not in SUPPORTED_SENSITIVITIES:
            raise ValueError("unsupported sensitivity.")
        return value

    @field_validator("symlink_policy")
    @classmethod
    def validate_symlink_policy(cls, value: str) -> str:
        if value not in SUPPORTED_SYMLINK_POLICIES:
            raise ValueError("unsupported symlink policy.")
        return value

    @field_validator("denied_patterns")
    @classmethod
    def validate_denied_patterns(cls, value: list[str]) -> list[str]:
        seen = set()
        for pattern in value:
            if not isinstance(pattern, str) or not pattern.strip():
                raise ValueError("denied patterns must not be empty.")
            normalized = pattern.strip()
            if normalized in seen:
                raise ValueError("duplicate denied pattern.")
            seen.add(normalized)
        return value


class ResourceScopeDocument(BaseModel):
    revision: str = Field(min_length=1)
    filesystem_scopes: dict[str, FilesystemScopeConfig] = Field(default_factory=dict)

    model_config = ConfigDict(extra="forbid", frozen=True)

    @model_validator(mode="after")
    def validate_document(self) -> "ResourceScopeDocument":
        if len(self.filesystem_scopes) > MAX_FILESYSTEM_SCOPES:
            raise ValueError("too many filesystem scopes.")
        for scope_id in self.filesystem_scopes:
            _validate_scope_id(scope_id)
        return self


@dataclass(frozen=True)
class ResolvedFilesystemScope:
    scope_id: str
    root: Path
    root_resolved: Path
    allowed_operations: tuple[str, ...]
    sensitivity: str
    symlink_policy: str
    denied_patterns: tuple[str, ...]


@dataclass(frozen=True)
class ResourceRegistry:
    revision: str
    filesystem_scopes: dict[str, ResolvedFilesystemScope]


class ResourceRegistryResolver:
    def __init__(self, config: ResourceScopesConfig | None = None) -> None:
        self.config = config or ResourceScopesConfig.from_env()
        self.path = self.config.path
        self._cache_key: tuple[str, int, int, tuple[tuple[str, str | None], ...]] | None = None
        self._cache_registry: ResourceRegistry | None = None

    def load(self) -> ResourceRegistry:
        try:
            stat = self.path.stat()
        except OSError as exc:
            raise ResourceRegistryError("resource_registry_unavailable") from exc

        root_env_names = self._root_env_names()
        env_snapshot = tuple((name, os.getenv(name)) for name in sorted(root_env_names))
        cache_key = (str(self.path), stat.st_mtime_ns, stat.st_size, env_snapshot)
        if self._cache_key == cache_key and self._cache_registry is not None:
            return self._cache_registry

        try:
            with self.path.open("r", encoding="utf-8") as file:
                data: Any = yaml.safe_load(file)
        except (OSError, yaml.YAMLError) as exc:
            raise ResourceRegistryError("resource_registry_unavailable") from exc

        if not isinstance(data, dict):
            raise ResourceRegistryError("resource_registry_unavailable")

        try:
            document = ResourceScopeDocument.model_validate(data)
            registry = self._resolve_document(document)
        except Exception as exc:
            raise ResourceRegistryError("resource_registry_unavailable") from exc

        self._cache_key = cache_key
        self._cache_registry = registry
        return registry

    def _root_env_names(self) -> set[str]:
        try:
            with self.path.open("r", encoding="utf-8") as file:
                data = yaml.safe_load(file) or {}
        except Exception:
            return set()
        scopes = data.get("filesystem_scopes") if isinstance(data, dict) else None
        if not isinstance(scopes, dict):
            return set()
        names = set()
        for scope in scopes.values():
            if isinstance(scope, dict) and isinstance(scope.get("root_env"), str):
                names.add(scope["root_env"])
        return names

    def _resolve_document(self, document: ResourceScopeDocument) -> ResourceRegistry:
        resolved_scopes: dict[str, ResolvedFilesystemScope] = {}
        resolved_roots: list[tuple[str, Path]] = []

        for scope_id, scope in document.filesystem_scopes.items():
            raw_root = os.getenv(scope.root_env)
            if not isinstance(raw_root, str) or not raw_root.strip():
                raise ResourceRegistryError("resource_registry_unavailable")
            root = Path(raw_root)
            if not _is_absolute_path(raw_root, root):
                raise ResourceRegistryError("resource_registry_unavailable")
            try:
                root_resolved = root.resolve(strict=True)
            except OSError as exc:
                raise ResourceRegistryError("resource_registry_unavailable") from exc
            if not root_resolved.is_dir():
                raise ResourceRegistryError("resource_registry_unavailable")
            for existing_scope, existing_root in resolved_roots:
                if _same_path(root_resolved, existing_root):
                    raise ResourceRegistryError("resource_registry_unavailable")
                if _is_relative_to(root_resolved, existing_root) or _is_relative_to(
                    existing_root,
                    root_resolved,
                ):
                    # Nested roots are allowed; selection uses most specific root.
                    pass
                _ = existing_scope
            resolved_roots.append((scope_id, root_resolved))
            resolved_scopes[scope_id] = ResolvedFilesystemScope(
                scope_id=scope_id,
                root=root,
                root_resolved=root_resolved,
                allowed_operations=tuple(scope.allowed_operations),
                sensitivity=scope.sensitivity,
                symlink_policy=scope.symlink_policy,
                denied_patterns=tuple(scope.denied_patterns),
            )

        return ResourceRegistry(
            revision=document.revision,
            filesystem_scopes=resolved_scopes,
        )


def _validate_scope_id(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("scope id must not be empty.")
    if not SCOPE_PATTERN.fullmatch(value):
        raise ValueError("scope id has invalid format.")
    return value


def _is_absolute_path(raw_value: str, path: Path) -> bool:
    if path.is_absolute():
        return True
    return PureWindowsPath(raw_value).is_absolute() or PurePosixPath(raw_value).is_absolute()


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _same_path(left: Path, right: Path) -> bool:
    return str(left).casefold() == str(right).casefold()
