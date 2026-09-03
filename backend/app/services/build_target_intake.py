from __future__ import annotations

from contextlib import contextmanager
from dataclasses import replace
import os
from pathlib import Path
from typing import Iterator

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import REPO_ROOT, settings
from app.core.runtime_paths import RUNTIME_TMP_DIR
from app.models.build_security import BuildSourceBinding
from app.models.mcp_server import MCPServer
from scanners.contracts import BuildTargetSnapshot, BuildTargetType, ValidatedWorkspace
from scanners.git_targets import (
    GitTargetPolicy,
    git_workspace,
    validate_git_ref,
    validate_git_repository_url,
)
from scanners.targets import (
    LocalDirectoryManifest,
    LocalTargetPolicy,
    local_workspace,
    validate_local_directory,
)


class BuildInventoryLinkError(ValueError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def configured_git_target_policy() -> GitTargetPolicy:
    return GitTargetPolicy(
        allowed_hosts=tuple(settings.build_scan_git_allowed_hosts),
        timeout_seconds=settings.build_scan_git_timeout_seconds,
        max_output_bytes=settings.build_scan_git_max_output_bytes,
        max_files=settings.build_scan_max_files,
        max_total_bytes=settings.build_scan_max_total_bytes,
        max_file_bytes=settings.build_scan_max_file_bytes,
    )


def bind_target_to_inventory_server(
    db: Session,
    *,
    target: BuildTargetSnapshot,
    server_id: int,
) -> BuildTargetSnapshot:
    server = db.get(MCPServer, server_id)
    if server is None:
        raise BuildInventoryLinkError("mcp_server_not_found")
    if server.status == "archived":
        raise BuildInventoryLinkError("archived_mcp_server_not_build_scannable")
    return replace(target, linked_server_id=server.id)


def upsert_build_source_binding(
    db: Session,
    *,
    server_id: int,
    target_type: BuildTargetType,
    source_locator: str,
    source_ref: str | None,
    actor_user_id: str | None,
) -> BuildSourceBinding:
    server = db.get(MCPServer, server_id)
    if server is None:
        raise BuildInventoryLinkError("mcp_server_not_found")
    if server.status == "archived":
        raise BuildInventoryLinkError("archived_mcp_server_not_build_scannable")

    if target_type == BuildTargetType.LOCAL_DIRECTORY:
        if source_ref is not None:
            raise BuildInventoryLinkError("local_source_ref_not_allowed")
        manifest = validate_configured_local_target(source_locator)
        normalized_locator = str(manifest.root)
        normalized_ref = None
    elif target_type == BuildTargetType.GIT_REPOSITORY:
        git_policy = configured_git_target_policy()
        normalized_locator = validate_git_repository_url(source_locator, policy=git_policy)
        normalized_ref = validate_git_ref(source_ref)
    else:  # defensive: enum currently has only source-backed target types
        raise BuildInventoryLinkError("unsupported_build_source_type")

    binding = db.scalar(
        select(BuildSourceBinding).where(BuildSourceBinding.server_id == server_id)
    )
    if binding is None:
        binding = BuildSourceBinding(
            server_id=server_id,
            target_type=target_type.value,
            source_locator=normalized_locator,
            source_ref=normalized_ref,
            created_by=actor_user_id,
            updated_by=actor_user_id,
        )
        db.add(binding)
    else:
        binding.target_type = target_type.value
        binding.source_locator = normalized_locator
        binding.source_ref = normalized_ref
        binding.updated_by = actor_user_id
    db.flush()
    return binding


def get_build_source_binding(
    db: Session,
    *,
    server_id: int,
) -> BuildSourceBinding:
    server = db.get(MCPServer, server_id)
    if server is None:
        raise BuildInventoryLinkError("mcp_server_not_found")
    if server.status == "archived":
        raise BuildInventoryLinkError("archived_mcp_server_not_build_scannable")
    binding = db.scalar(
        select(BuildSourceBinding).where(BuildSourceBinding.server_id == server_id)
    )
    if binding is None:
        raise BuildInventoryLinkError("build_source_binding_not_configured")
    return binding


@contextmanager
def configured_inventory_workspace(
    db: Session,
    *,
    server_id: int,
) -> Iterator[ValidatedWorkspace]:
    server = db.get(MCPServer, server_id)
    if server is None:
        raise BuildInventoryLinkError("mcp_server_not_found")
    if server.status == "archived":
        raise BuildInventoryLinkError("archived_mcp_server_not_build_scannable")
    binding = get_build_source_binding(db, server_id=server_id)

    if binding.target_type == BuildTargetType.LOCAL_DIRECTORY.value:
        with configured_local_workspace(
            binding.source_locator,
            display_name=server.name,
            linked_server_id=server.id,
        ) as workspace:
            yield workspace
        return

    if binding.target_type == BuildTargetType.GIT_REPOSITORY.value:
        with configured_git_workspace(
            binding.source_locator,
            requested_ref=binding.source_ref,
            display_name=server.name,
            linked_server_id=server.id,
        ) as workspace:
            yield workspace
        return

    raise BuildInventoryLinkError("unsupported_build_source_type")


def available_local_scan_roots() -> tuple[Path, ...]:
    configured = tuple(settings.build_scan_allowed_roots)
    if configured:
        return configured

    if os.name == "nt":
        listdrives = getattr(os, "listdrives", None)
        raw_drives = listdrives() if callable(listdrives) else ()
        roots: list[Path] = []
        for raw in raw_drives:
            candidate = Path(raw)
            try:
                resolved = candidate.resolve(strict=True)
            except (OSError, RuntimeError):
                continue
            if resolved.is_dir():
                roots.append(resolved)
        if roots:
            return tuple(roots)

        # Defensive fallback for older/unusual Windows runtimes.
        for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            candidate = Path(f"{letter}:/")
            try:
                resolved = candidate.resolve(strict=True)
            except (OSError, RuntimeError):
                continue
            if resolved.is_dir():
                roots.append(resolved)
        if roots:
            return tuple(roots)
        raise BuildInventoryLinkError("no_local_filesystem_root_available")

    root = Path("/")
    try:
        return (root.resolve(strict=True),)
    except (OSError, RuntimeError) as exc:
        raise BuildInventoryLinkError("no_local_filesystem_root_available") from exc


def configured_local_target_policy() -> LocalTargetPolicy:
    denied_candidates = (
        REPO_ROOT / ".runtime",
        REPO_ROOT / ".git",
        REPO_ROOT / "backend" / ".venv",
        REPO_ROOT / "frontend" / "node_modules",
        REPO_ROOT / "frontend" / "dist",
    )
    return LocalTargetPolicy(
        allowed_roots=available_local_scan_roots(),
        denied_roots=tuple(path for path in denied_candidates if path.exists()),
        max_files=settings.build_scan_max_files,
        max_total_bytes=settings.build_scan_max_total_bytes,
        max_file_bytes=settings.build_scan_max_file_bytes,
    )


def validate_configured_local_target(source: str | Path) -> LocalDirectoryManifest:
    return validate_local_directory(
        source,
        policy=configured_local_target_policy(),
    )


def configured_local_workspace(
    source: str | Path,
    *,
    display_name: str,
    linked_server_id: int | None = None,
    source_revision: str | None = None,
):
    target = BuildTargetSnapshot(
        target_type=BuildTargetType.LOCAL_DIRECTORY,
        display_name=display_name,
        source_locator=str(Path(source).expanduser().resolve(strict=False)),
        source_revision=source_revision,
        linked_server_id=linked_server_id,
    )
    return local_workspace(
        source,
        target=target,
        policy=configured_local_target_policy(),
        workspace_parent=RUNTIME_TMP_DIR / "build-security",
    )


def configured_git_workspace(
    repository_url: str,
    *,
    requested_ref: str | None,
    display_name: str,
    linked_server_id: int | None = None,
):
    return git_workspace(
        repository_url,
        requested_ref=requested_ref,
        display_name=display_name,
        linked_server_id=linked_server_id,
        policy=configured_git_target_policy(),
        workspace_parent=RUNTIME_TMP_DIR / "build-security",
    )
