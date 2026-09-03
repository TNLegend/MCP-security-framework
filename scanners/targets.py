from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from hashlib import sha256
import os
from pathlib import Path
import shutil
import stat
from typing import Iterator, Sequence
from uuid import uuid4

from common.canonical_json import sha256_canonical_json
from common.project_paths import is_path_within
from scanners.contracts import BuildTargetSnapshot, BuildTargetType, ValidatedWorkspace


DEFAULT_IGNORED_DIRECTORY_NAMES = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".runtime",
        ".venv",
        "venv",
        "node_modules",
        "__pycache__",
    }
)


class BuildTargetValidationError(ValueError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class LocalTargetPolicy:
    allowed_roots: tuple[Path, ...]
    denied_roots: tuple[Path, ...] = ()
    max_files: int = 20_000
    max_total_bytes: int = 1_000_000_000
    max_file_bytes: int = 100_000_000
    ignored_directory_names: frozenset[str] = DEFAULT_IGNORED_DIRECTORY_NAMES

    def __post_init__(self) -> None:
        if not self.allowed_roots:
            raise ValueError("at_least_one_allowed_scan_root_required")
        if self.max_files < 1:
            raise ValueError("max_files_must_be_positive")
        if self.max_total_bytes < 1:
            raise ValueError("max_total_bytes_must_be_positive")
        if self.max_file_bytes < 1:
            raise ValueError("max_file_bytes_must_be_positive")


@dataclass(frozen=True, slots=True)
class SourceFileEntry:
    relative_path: str
    size: int
    sha256: str


@dataclass(frozen=True, slots=True)
class LocalDirectoryManifest:
    root: Path
    entries: tuple[SourceFileEntry, ...]
    total_bytes: int
    source_fingerprint: str


def _is_reparse_or_link(path: Path) -> bool:
    if path.is_symlink():
        return True
    is_junction = getattr(path, "is_junction", None)
    if callable(is_junction) and is_junction():
        return True
    try:
        details = path.lstat()
    except OSError as exc:
        raise BuildTargetValidationError("target_path_unreadable") from exc
    attributes = getattr(details, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(reparse_flag and attributes & reparse_flag)


def _resolved_existing_directory(path: Path) -> Path:
    candidate = path.expanduser()
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise BuildTargetValidationError("target_directory_not_found") from exc
    if not resolved.is_dir():
        raise BuildTargetValidationError("target_not_directory")
    if _is_reparse_or_link(candidate):
        raise BuildTargetValidationError("target_reparse_point_not_allowed")
    return resolved


def _normalized_roots(values: Sequence[Path]) -> tuple[Path, ...]:
    roots: list[Path] = []
    for value in values:
        try:
            resolved = value.expanduser().resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise BuildTargetValidationError("configured_scan_root_unavailable") from exc
        if not resolved.is_dir():
            raise BuildTargetValidationError("configured_scan_root_not_directory")
        roots.append(resolved)
    return tuple(roots)


def _validate_target_boundaries(root: Path, policy: LocalTargetPolicy) -> None:
    allowed = _normalized_roots(policy.allowed_roots)
    denied = _normalized_roots(policy.denied_roots) if policy.denied_roots else ()
    if not any(is_path_within(root, allowed_root) for allowed_root in allowed):
        raise BuildTargetValidationError("target_outside_allowed_roots")
    if any(is_path_within(root, denied_root) for denied_root in denied):
        raise BuildTargetValidationError("target_inside_denied_root")


def _hash_regular_file(path: Path, expected_stat: os.stat_result) -> tuple[int, str]:
    digest = sha256()
    bytes_read = 0
    try:
        with path.open("rb") as source:
            while True:
                block = source.read(1024 * 1024)
                if not block:
                    break
                bytes_read += len(block)
                digest.update(block)
        after = path.stat()
    except OSError as exc:
        raise BuildTargetValidationError("target_file_unreadable") from exc

    if (
        bytes_read != expected_stat.st_size
        or after.st_size != expected_stat.st_size
        or after.st_mtime_ns != expected_stat.st_mtime_ns
    ):
        raise BuildTargetValidationError("source_changed_during_validation")
    return bytes_read, digest.hexdigest()


def list_local_subdirectories(
    source: str | Path,
    *,
    policy: LocalTargetPolicy,
) -> tuple[Path, tuple[Path, ...]]:
    root = _resolved_existing_directory(Path(source))
    _validate_target_boundaries(root, policy)
    denied = _normalized_roots(policy.denied_roots) if policy.denied_roots else ()

    directories: list[Path] = []
    try:
        with os.scandir(root) as iterator:
            children = sorted(iterator, key=lambda item: item.name.casefold())
    except OSError as exc:
        raise BuildTargetValidationError("target_directory_unreadable") from exc

    for child in children:
        child_path = Path(child.path)
        if child.name in policy.ignored_directory_names:
            continue
        if _is_reparse_or_link(child_path):
            continue
        if not child.is_dir(follow_symlinks=False):
            continue
        try:
            resolved = child_path.resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        if not is_path_within(resolved, root):
            continue
        if any(is_path_within(resolved, denied_root) for denied_root in denied):
            continue
        directories.append(resolved)

    return root, tuple(directories)


def validate_local_directory(
    source: str | Path,
    *,
    policy: LocalTargetPolicy,
) -> LocalDirectoryManifest:
    root = _resolved_existing_directory(Path(source))
    _validate_target_boundaries(root, policy)

    entries: list[SourceFileEntry] = []
    total_bytes = 0
    stack = [root]

    while stack:
        directory = stack.pop()
        try:
            with os.scandir(directory) as iterator:
                children = sorted(iterator, key=lambda item: item.name.casefold())
        except OSError as exc:
            raise BuildTargetValidationError("target_directory_unreadable") from exc

        for child in children:
            child_path = Path(child.path)
            if _is_reparse_or_link(child_path):
                raise BuildTargetValidationError("target_reparse_point_not_allowed")

            if child.is_dir(follow_symlinks=False):
                if child.name in policy.ignored_directory_names:
                    continue
                stack.append(child_path)
                continue

            if not child.is_file(follow_symlinks=False):
                raise BuildTargetValidationError("target_special_file_not_allowed")

            try:
                before = child.stat(follow_symlinks=False)
            except OSError as exc:
                raise BuildTargetValidationError("target_file_unreadable") from exc

            if before.st_size > policy.max_file_bytes:
                raise BuildTargetValidationError("target_file_too_large")
            if len(entries) + 1 > policy.max_files:
                raise BuildTargetValidationError("target_file_count_exceeded")
            if total_bytes + before.st_size > policy.max_total_bytes:
                raise BuildTargetValidationError("target_total_size_exceeded")

            resolved_child = child_path.resolve(strict=True)
            if not is_path_within(resolved_child, root):
                raise BuildTargetValidationError("target_path_escape_detected")

            bytes_read, digest = _hash_regular_file(child_path, before)
            total_bytes += bytes_read
            relative = child_path.relative_to(root).as_posix()
            entries.append(
                SourceFileEntry(
                    relative_path=relative,
                    size=bytes_read,
                    sha256=digest,
                )
            )

    entries.sort(key=lambda item: item.relative_path)
    fingerprint = sha256_canonical_json(
        {
            "version": 1,
            "files": [
                {
                    "path": entry.relative_path,
                    "size": entry.size,
                    "sha256": entry.sha256,
                }
                for entry in entries
            ],
        }
    )
    return LocalDirectoryManifest(
        root=root,
        entries=tuple(entries),
        total_bytes=total_bytes,
        source_fingerprint=fingerprint,
    )


def _copy_manifest_file(source: Path, destination: Path, entry: SourceFileEntry) -> None:
    if _is_reparse_or_link(source):
        raise BuildTargetValidationError("source_changed_during_materialization")
    try:
        before = source.stat()
    except OSError as exc:
        raise BuildTargetValidationError("source_changed_during_materialization") from exc
    if before.st_size != entry.size:
        raise BuildTargetValidationError("source_changed_during_materialization")

    destination.parent.mkdir(parents=True, exist_ok=True)
    digest = sha256()
    copied = 0
    try:
        with source.open("rb") as reader, destination.open("xb") as writer:
            while True:
                block = reader.read(1024 * 1024)
                if not block:
                    break
                copied += len(block)
                digest.update(block)
                writer.write(block)
    except OSError as exc:
        raise BuildTargetValidationError("workspace_materialization_failed") from exc

    if copied != entry.size or digest.hexdigest() != entry.sha256:
        raise BuildTargetValidationError("source_changed_during_materialization")


def materialize_validated_manifest(
    manifest: LocalDirectoryManifest,
    *,
    target: BuildTargetSnapshot,
    workspace_parent: Path,
) -> ValidatedWorkspace:
    workspace_parent = workspace_parent.resolve(strict=False)
    workspace_parent.mkdir(parents=True, exist_ok=True)
    workspace_container = workspace_parent / str(uuid4())
    workspace_root = workspace_container / "source"
    workspace_root.mkdir(parents=True, exist_ok=False)

    try:
        for entry in manifest.entries:
            source = manifest.root / Path(entry.relative_path)
            destination = workspace_root / Path(entry.relative_path)
            if not is_path_within(destination, workspace_root):
                raise BuildTargetValidationError("workspace_path_escape_detected")
            _copy_manifest_file(source, destination, entry)
    except Exception:
        shutil.rmtree(workspace_container, ignore_errors=True)
        raise

    bound_target = BuildTargetSnapshot(
        target_type=target.target_type,
        display_name=target.display_name,
        source_locator=target.source_locator,
        source_revision=target.source_revision,
        source_fingerprint=manifest.source_fingerprint,
        linked_server_id=target.linked_server_id,
    )
    return ValidatedWorkspace(
        root=workspace_root.resolve(strict=True),
        target=bound_target,
        file_count=len(manifest.entries),
        total_bytes=manifest.total_bytes,
    )


def materialize_local_workspace(
    manifest: LocalDirectoryManifest,
    *,
    target: BuildTargetSnapshot,
    workspace_parent: Path,
) -> ValidatedWorkspace:
    if target.target_type != BuildTargetType.LOCAL_DIRECTORY:
        raise BuildTargetValidationError("local_workspace_requires_local_target")
    try:
        locator = Path(target.source_locator).expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise BuildTargetValidationError("target_directory_not_found") from exc
    if locator != manifest.root:
        raise BuildTargetValidationError("target_manifest_locator_mismatch")
    return materialize_validated_manifest(
        manifest,
        target=target,
        workspace_parent=workspace_parent,
    )


@contextmanager
def local_workspace(
    source: str | Path,
    *,
    target: BuildTargetSnapshot,
    policy: LocalTargetPolicy,
    workspace_parent: Path,
) -> Iterator[ValidatedWorkspace]:
    manifest = validate_local_directory(source, policy=policy)
    workspace = materialize_local_workspace(
        manifest,
        target=target,
        workspace_parent=workspace_parent,
    )
    container = workspace.root.parent
    try:
        yield workspace
    finally:
        shutil.rmtree(container, ignore_errors=True)
