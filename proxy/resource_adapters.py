from dataclasses import dataclass, replace
import fnmatch
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
from typing import Any

from proxy.identity_config import ResourceScopesConfig
from proxy.resource_registry import (
    ResourceRegistry,
    ResolvedFilesystemScope,
)
from proxy.tool_security_profiles import ResolvedToolSecurityProfile


SECRET_NAME_PATTERNS = (
    ".env",
    ".env.",
    ".ssh",
    ".aws",
    "id_rsa",
    "id_ed25519",
    "credentials",
    "tokens",
    "secrets",
    "private.key",
)
WINDOWS_DRIVE_PATTERN = re.compile(r"^[A-Za-z]:[\\/]")
WINDOWS_DEVICE_PREFIXES = ("\\\\.\\", "\\\\.\\", "\\\\?\\", "//?/", "//./")
WINDOWS_RESERVED_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}


@dataclass(frozen=True)
class ResourceResolution:
    operation: str
    required_capability: str
    resource_adapter: str
    resource_type: str
    resource_scope: str
    canonical_resource: str | None
    resource_sensitivity: str
    resource_resolution_status: str
    resource_flags: tuple[str, ...]
    resource_registry_revision: str
    tool_profile_revision: str
    operation_allowed_on_scope: bool
    execution_arguments: dict[str, Any]
    physical_resource: Path | None = None
    requested_resource: Path | None = None
    scope_lexical_root: Path | None = None
    scope_root: Path | None = None
    symlink_policy: str | None = None
    expected_type: str | None = None


class ResourceAdapterError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class FilesystemResourceAdapter:
    def __init__(self, config: ResourceScopesConfig | None = None) -> None:
        self.config = config or ResourceScopesConfig.from_env()

    def resolve(
        self,
        *,
        profile: ResolvedToolSecurityProfile,
        arguments: dict[str, Any],
        registry: ResourceRegistry,
    ) -> ResourceResolution:
        resource_profile = profile.resource
        raw_path = arguments.get(resource_profile.argument_name)
        if raw_path is None and profile.operation == "list":
            raw_path = "."
        syntax_error = self._validate_raw_path(raw_path)
        if syntax_error:
            return self._failure(profile, registry, syntax_error)
        assert isinstance(raw_path, str)

        normalized_parts = self._normalized_parts(raw_path)
        if normalized_parts is None:
            return self._failure(profile, registry, "path_traversal_outside_root")

        candidate_path, base_status = self._candidate_path(
            raw_path=raw_path,
            normalized_parts=normalized_parts,
            profile=profile,
            registry=registry,
        )
        if base_status is not None:
            return self._failure(profile, registry, base_status)

        origin_scope, origin_scope_status = self._select_origin_scope(
            candidate_path,
            profile=profile,
            registry=registry,
        )
        if origin_scope_status is not None:
            return self._failure(profile, registry, origin_scope_status)
        assert origin_scope is not None

        try:
            physical_resolved = candidate_path.resolve(strict=True)
        except OSError:
            return self._failure(profile, registry, "resource_not_found")

        origin_link_status = self._validate_link_policy(
            candidate_path,
            physical_resolved,
            origin_scope,
        )
        if origin_link_status:
            return self._failure(profile, registry, origin_link_status)

        scope, scope_status = self._select_scope(
            physical_resolved,
            profile=profile,
            registry=registry,
        )
        if scope_status is not None:
            return self._failure(profile, registry, scope_status)
        assert scope is not None

        scope_link_status = self._validate_link_policy(
            candidate_path,
            physical_resolved,
            scope,
        )
        if scope_link_status:
            return self._failure(profile, registry, scope_link_status)

        type_status = self._validate_expected_type(
            physical_resolved,
            resource_profile.expected_type,
        )
        if type_status:
            return self._failure(profile, registry, type_status)

        relative_logical_path = physical_resolved.relative_to(scope.root_resolved)
        logical_path = "/".join(relative_logical_path.parts)
        if logical_path == "":
            logical_path = "."
        canonical_resource = f"{scope.scope_id}:/{logical_path}"
        flags, sensitivity = self._classify_sensitivity(
            canonical_resource,
            scope,
            physical_resolved,
        )
        operation_allowed = profile.operation in scope.allowed_operations
        execution_arguments = dict(arguments)
        execution_arguments[resource_profile.argument_name] = (
            self._execution_logical_path(
                physical_resolved,
                profile=profile,
                registry=registry,
            )
            or logical_path
        )

        return ResourceResolution(
            operation=profile.operation,
            required_capability=profile.required_capability,
            resource_adapter=resource_profile.adapter,
            resource_type=f"filesystem.{resource_profile.expected_type}",
            resource_scope=scope.scope_id,
            canonical_resource=canonical_resource,
            resource_sensitivity=sensitivity,
            resource_resolution_status="resolved",
            resource_flags=tuple(flags),
            resource_registry_revision=registry.revision,
            tool_profile_revision=profile.revision,
            operation_allowed_on_scope=operation_allowed,
            execution_arguments=execution_arguments,
            physical_resource=physical_resolved,
            requested_resource=candidate_path,
            scope_lexical_root=_absolute_lexical_path(scope.root),
            scope_root=scope.root_resolved,
            symlink_policy=scope.symlink_policy,
            expected_type=resource_profile.expected_type,
        )

    def _execution_logical_path(
        self,
        physical_resolved: Path,
        *,
        profile: ResolvedToolSecurityProfile,
        registry: ResourceRegistry,
    ) -> str | None:
        base_scope_id = profile.resource.relative_base_scope
        if not base_scope_id:
            return None
        base_scope = registry.filesystem_scopes.get(base_scope_id)
        if base_scope is None or not _is_relative_to(
            physical_resolved,
            base_scope.root_resolved,
        ):
            return None

        execution_relative_path = physical_resolved.relative_to(
            base_scope.root_resolved
        )
        execution_path = "/".join(execution_relative_path.parts)
        return execution_path or "."

    def revalidate(self, resolution: ResourceResolution) -> tuple[bool, str | None]:
        physical = resolution.physical_resource
        requested = resolution.requested_resource
        if physical is None or requested is None:
            return False, "resource_resolution_failed"
        try:
            current = requested.resolve(strict=True)
        except OSError:
            return False, "resource_changed_before_execution"
        if str(current).casefold() != str(physical).casefold():
            return False, "resource_changed_before_execution"
        if resolution.scope_root is not None and not _is_relative_to(
            current,
            resolution.scope_root,
        ):
            return False, "resource_changed_before_execution"
        if (
            resolution.scope_root is not None
            and resolution.symlink_policy is not None
            and self._validate_link_policy_for_root(
                requested,
                current,
                resolution.scope_lexical_root or resolution.scope_root,
                resolution.scope_root,
                resolution.symlink_policy,
            )
        ):
            return False, "resource_changed_before_execution"
        if resolution.expected_type == "file" and not current.is_file():
            return False, "resource_changed_before_execution"
        if resolution.expected_type == "directory" and not current.is_dir():
            return False, "resource_changed_before_execution"
        return True, None

    def _validate_raw_path(self, raw_path: Any) -> str | None:
        if not isinstance(raw_path, str):
            return "invalid_type:path"
        if raw_path == "" or raw_path.strip() == "":
            return "path_empty"
        if raw_path != raw_path.strip():
            return "path_surrounding_whitespace"
        raw_bytes = raw_path.encode("utf-8", errors="ignore")
        if len(raw_bytes) > self.config.max_path_bytes:
            return "path_too_long"
        if "\x00" in raw_path:
            return "path_null_byte"
        if any(ord(character) < 32 for character in raw_path):
            return "path_control_character"
        normalized = raw_path.replace("\\", "/")
        if len([part for part in normalized.split("/") if part]) > self.config.max_path_segments:
            return "path_too_many_segments"
        if not self.config.allow_unc and (
            raw_path.startswith("\\\\") or raw_path.startswith("//")
        ):
            return "path_unc"
        if not self.config.allow_device_paths and raw_path.startswith(WINDOWS_DEVICE_PREFIXES):
            return "path_device"
        if not self.config.allow_ntfs_ads and self._contains_ntfs_ads(raw_path):
            return "path_ntfs_ads"
        for segment in normalized.split("/"):
            if not segment or segment in {".", ".."}:
                continue
            bare = segment.split(".")[0].upper()
            if bare in WINDOWS_RESERVED_NAMES:
                return "path_reserved_name"
        return None

    def _normalized_parts(self, raw_path: str) -> tuple[str, ...] | None:
        normalized = raw_path.replace("\\", "/")
        parts: list[str] = []
        for segment in normalized.split("/"):
            if segment in {"", "."}:
                continue
            if segment == "..":
                if not parts:
                    return None
                parts.pop()
                continue
            parts.append(segment)
        return tuple(parts)

    def _candidate_path(
        self,
        *,
        raw_path: str,
        normalized_parts: tuple[str, ...],
        profile: ResolvedToolSecurityProfile,
        registry: ResourceRegistry,
    ) -> tuple[Path, str | None]:
        if _is_absolute_runtime_path(raw_path):
            return _absolute_lexical_path(Path(raw_path)), None

        base_scope_id = profile.resource.relative_base_scope
        if not base_scope_id:
            return Path(), "ambiguous_resource_scope"
        base_scope = registry.filesystem_scopes.get(base_scope_id)
        if base_scope is None:
            return Path(), "resource_registry_unavailable"
        return base_scope.root_resolved.joinpath(*normalized_parts), None

    def _select_origin_scope(
        self,
        candidate_path: Path,
        *,
        profile: ResolvedToolSecurityProfile,
        registry: ResourceRegistry,
    ) -> tuple[ResolvedFilesystemScope | None, str | None]:
        candidates = set(profile.resource.allowed_scope_candidates)
        matches: list[ResolvedFilesystemScope] = []
        for scope_id, scope in registry.filesystem_scopes.items():
            if candidates and scope_id not in candidates:
                continue
            if _is_relative_to_lexical(
                candidate_path,
                scope.root,
            ) or _is_relative_to_lexical(candidate_path, scope.root_resolved):
                matches.append(scope)
        if not matches:
            return None, "resource_outside_registered_scope"

        matches.sort(key=lambda scope: len(scope.root_resolved.parts), reverse=True)
        if len(matches) > 1 and len(matches[0].root_resolved.parts) == len(
            matches[1].root_resolved.parts
        ):
            return None, "ambiguous_resource_scope"
        return matches[0], None

    def _select_scope(
        self,
        physical_resolved: Path,
        *,
        profile: ResolvedToolSecurityProfile,
        registry: ResourceRegistry,
    ) -> tuple[ResolvedFilesystemScope | None, str | None]:
        candidates = set(profile.resource.allowed_scope_candidates)
        matches: list[ResolvedFilesystemScope] = []
        for scope_id, scope in registry.filesystem_scopes.items():
            if candidates and scope_id not in candidates:
                continue
            if _is_relative_to(physical_resolved, scope.root_resolved):
                matches.append(scope)
        if not matches:
            return None, "resource_outside_registered_scope"

        matches.sort(key=lambda scope: len(scope.root_resolved.parts), reverse=True)
        if len(matches) > 1 and len(matches[0].root_resolved.parts) == len(
            matches[1].root_resolved.parts
        ):
            return None, "ambiguous_resource_scope"
        return matches[0], None

    def _validate_expected_type(self, path: Path, expected_type: str) -> str | None:
        if expected_type == "file" and not path.is_file():
            return "resource_type_mismatch"
        if expected_type == "directory" and not path.is_dir():
            return "resource_type_mismatch"
        return None

    def _validate_link_policy(
        self,
        candidate_path: Path,
        physical_resolved: Path,
        scope: ResolvedFilesystemScope,
    ) -> str | None:
        return self._validate_link_policy_for_root(
            candidate_path,
            physical_resolved,
            scope.root,
            scope.root_resolved,
            scope.symlink_policy,
        )

    def _validate_link_policy_for_root(
        self,
        candidate_path: Path,
        physical_resolved: Path,
        root_lexical: Path,
        root_resolved: Path,
        symlink_policy: str,
    ) -> str | None:
        if not (
            _is_relative_to_lexical(candidate_path, root_lexical)
            or _is_relative_to_lexical(candidate_path, root_resolved)
        ):
            return None

        link_paths = _link_paths_between(root_lexical, candidate_path)
        if not link_paths and root_lexical != root_resolved:
            link_paths = _link_paths_between(root_resolved, candidate_path)
        if not link_paths:
            return None

        if symlink_policy == "deny":
            return "resource_link_forbidden"

        if symlink_policy == "internal-only":
            if not _is_relative_to(physical_resolved, root_resolved):
                return "resource_link_outside_scope"
            for link_path in link_paths:
                try:
                    link_target = link_path.resolve(strict=True)
                except OSError:
                    return "resource_link_unavailable"
                if not _is_relative_to(link_target, root_resolved):
                    return "resource_link_outside_scope"
            return None

        return "resource_link_policy_unknown"

    def _classify_sensitivity(
        self,
        canonical_resource: str,
        scope: ResolvedFilesystemScope,
        physical_resolved: Path,
    ) -> tuple[list[str], str]:
        flags: list[str] = []
        sensitivity = scope.sensitivity
        comparison = canonical_resource.lower()
        parts = [part.lower() for part in physical_resolved.parts]
        if any(pattern in comparison for pattern in SECRET_NAME_PATTERNS):
            sensitivity = "secret"
            flags.append("sensitive_name")
        for pattern in scope.denied_patterns:
            if fnmatch.fnmatch(comparison, pattern.lower()):
                sensitivity = "secret"
                flags.append("denied_pattern")
        if any(part in {".ssh", ".aws", "secrets"} for part in parts):
            sensitivity = "secret"
            flags.append("sensitive_directory")
        return sorted(set(flags)), sensitivity

    def _failure(
        self,
        profile: ResolvedToolSecurityProfile,
        registry: ResourceRegistry,
        status: str,
    ) -> ResourceResolution:
        return ResourceResolution(
            operation=profile.operation,
            required_capability=profile.required_capability,
            resource_adapter=profile.resource.adapter,
            resource_type=f"filesystem.{profile.resource.expected_type}",
            resource_scope="invalid",
            canonical_resource=None,
            resource_sensitivity="unknown",
            resource_resolution_status=status,
            resource_flags=(),
            resource_registry_revision=registry.revision,
            tool_profile_revision=profile.revision,
            operation_allowed_on_scope=False,
            execution_arguments={},
            physical_resource=None,
            requested_resource=None,
            scope_lexical_root=None,
            scope_root=None,
            symlink_policy=None,
            expected_type=profile.resource.expected_type,
        )

    def _contains_ntfs_ads(self, raw_path: str) -> bool:
        if not WINDOWS_DRIVE_PATTERN.match(raw_path):
            return ":" in raw_path
        drive, rest = raw_path[:2], raw_path[2:]
        _ = drive
        return ":" in rest


def resolve_resource(
    *,
    profile: ResolvedToolSecurityProfile,
    arguments: dict[str, Any],
    registry: ResourceRegistry,
    config: ResourceScopesConfig | None = None,
) -> ResourceResolution:
    if profile.resource.adapter != "filesystem":
        raise ResourceAdapterError("resource_adapter_unknown")
    return FilesystemResourceAdapter(config).resolve(
        profile=profile,
        arguments=arguments,
        registry=registry,
    )


def revalidate_resource(
    resolution: ResourceResolution,
    config: ResourceScopesConfig | None = None,
) -> tuple[bool, str | None]:
    if resolution.resource_adapter != "filesystem":
        return False, "resource_adapter_unknown"
    return FilesystemResourceAdapter(config).revalidate(resolution)


def with_execution_arguments(
    resolution: ResourceResolution,
    arguments: dict[str, Any],
) -> ResourceResolution:
    return replace(resolution, execution_arguments=dict(arguments))


def _is_absolute_runtime_path(raw_path: str) -> bool:
    return (
        Path(raw_path).is_absolute()
        or PureWindowsPath(raw_path).is_absolute()
        or PurePosixPath(raw_path).is_absolute()
    )


def _absolute_lexical_path(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        if os.name == "nt":
            return str(path).casefold().startswith(str(root).casefold() + os.sep)
        return False


def _is_relative_to_lexical(path: Path, root: Path) -> bool:
    path = _absolute_lexical_path(path)
    root = _absolute_lexical_path(root)
    try:
        path.relative_to(root)
        return True
    except ValueError:
        if os.name == "nt":
            path_value = str(path).casefold()
            root_value = str(root).rstrip("\\/").casefold()
            return path_value == root_value or path_value.startswith(
                root_value + os.sep
            )
        return False


def _relative_parts_lexical(path: Path, root: Path) -> tuple[str, ...] | None:
    path = _absolute_lexical_path(path)
    root = _absolute_lexical_path(root)
    try:
        return path.relative_to(root).parts
    except ValueError:
        if os.name != "nt":
            return None
        path_value = str(path)
        path_folded = path_value.casefold()
        root_value = str(root).rstrip("\\/")
        root_folded = root_value.casefold()
        if path_folded == root_folded:
            return ()
        prefix = root_folded + os.sep
        if not path_folded.startswith(prefix):
            return None
        relative = path_value[len(root_value) + 1 :]
        return Path(relative).parts


def _link_paths_between(root: Path, candidate_path: Path) -> list[Path]:
    relative_parts = _relative_parts_lexical(candidate_path, root)
    if relative_parts is None:
        return []

    links: list[Path] = []
    current = _absolute_lexical_path(root)
    for part in relative_parts:
        current = current / part
        if _is_link(current):
            links.append(current)
    return links


def _is_link(path: Path) -> bool:
    try:
        if path.is_symlink():
            return True
        is_junction = getattr(path, "is_junction", None)
        return bool(is_junction and is_junction())
    except OSError:
        return False
