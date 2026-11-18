"""Optional immutable-deployment gate for SHA-free runtime analyzer fencing.

Never a replacement for startup SHA-256 verification or PostgreSQL authority.
The fast path is available ONLY when Windows ACLs deny file/directory writes
to the unprivileged worker and kernel read-sharing leases pin all declared
model, source, dependency and interpreter files until process shutdown.
Mutable developer installs continue to rehash on every runtime decision.
"""
from __future__ import annotations

import os
from pathlib import Path
from threading import RLock
from typing import Any

from app.services.tda_application._integrity import PipelineIntegrityError

_RUNTIME_GATE_ENV = "ANALYZER_RUNTIME_IMMUTABLE_FAST_PATH"
_guard = RLock()
_lease: tuple[int, Any, tuple[int, ...]] | None = None


def _declared_artifact_paths(pipeline: Any) -> set[Path]:
    """Build from manifests already fully hashed, never a guessed directory."""
    try:
        identity = pipeline._m4_identity
        manifest = pipeline._manifest
        execution = manifest["execution"]
        model_root = Path(identity.model_root)
        repo_root = Path(identity.repo_root)
        m6_snapshot = Path(manifest["m6_embedding"]["snapshot"])
        files: set[Path] = set()
        files.update(model_root / name for name in identity.manifest["model_artifacts"])
        files.update(repo_root / name for name in identity.manifest["source_artifacts"])
        files.update(Path(name) for name in execution["source_sha256"])
        files.update(
            m6_snapshot / row["path"] for row in manifest["m6_embedding"]["files"]
        )
        deps = execution["dependency_artifacts"]
        files.update(Path(name) for name in deps["interpreter"]["files"])
        for distribution in deps["distributions"].values():
            files.update(Path(name) for name in distribution["files"])
        gliner = execution["dependencies"]["gliner2"]
        files.update(
            Path(gliner["import_root"]) / name for name in gliner["sha256"]
        )
    except (KeyError, AttributeError, TypeError, ValueError) as exc:
        raise PipelineIntegrityError("runtime_immutable_source_manifest_incomplete") from exc
    if not files or not all(p.is_absolute() for p in files):
        raise PipelineIntegrityError("runtime_immutable_paths_invalid")
    return files


def _declared_directory_closure(pipeline: Any) -> set[Path]:
    """Include empty and importable directories, not just known file parents.

    Otherwise a worker could add a previously absent Python module in an
    existing empty package directory after boot, without changing any
    already-verified file. Never enumerate a generic filesystem/drive root.
    """
    import site
    import sys
    from app.services.tda_application.m4_pipeline_integrity import SOURCE_ROOTS

    model = pipeline._m4_identity
    roots = [
        Path(model.repo_root) / rel for rel in SOURCE_ROOTS
    ] + [
        Path(model.model_root),
        Path(pipeline._manifest["m6_embedding"]["snapshot"]),
        Path(pipeline._manifest["execution"]["dependencies"]["gliner2"]["import_root"]),
        Path(sys.base_prefix) / "Lib",
        Path(sys.prefix) / "Lib",
    ] + [Path(p) for p in site.getsitepackages()]
    # Avoid scanning the same site-packages tree twice: Python can list
    # both the virtualenv root AND its nested Lib/site-packages.
    unique = sorted(set(roots), key=lambda p: (len(p.parts), str(p)))
    minimal: list[Path] = []
    for root in unique:
        if not any(root == parent or root.is_relative_to(parent) for parent in minimal):
            minimal.append(root)
    directories: set[Path] = set()
    for root in minimal:
        if not root.exists():
            raise PipelineIntegrityError("runtime_immutable_declared_root_missing")
        if root.is_symlink() or getattr(root, "is_junction", lambda: False)():
            raise PipelineIntegrityError("runtime_immutable_linked_root")
        if root.is_file():
            continue
        if not root.is_dir() or root == root.parent:
            raise PipelineIntegrityError("runtime_immutable_invalid_directory_root")
        # Scandir/os.walk is much faster on Windows than Path.rglob followed
        # by a separate stat on every regular file. Never follow reparse
        # points; a linked source/import path invalidates the entire lease.
        for current, names, filenames in os.walk(root, topdown=True, followlinks=False):
            directory = Path(current)
            directories.add(directory)
            for name in names + filenames:
                candidate = directory / name
                if candidate.is_symlink() or getattr(candidate, "is_junction", lambda: False)():
                    raise PipelineIntegrityError("runtime_immutable_linked_directory_tree")
    return directories


def _windows_lock_verified_artifacts(
    files: set[Path], *, additional_directories: set[Path] | None = None,
) -> tuple[int, ...]:
    """Fail closed unless OS access rights prove the complete closure unwritable.

    Refuse mutable *directories*, not just mutable existing files: otherwise
    a new unverified Python module or a replacement model can be planted.
    Directory handles also block renaming the verified deployment roots.
    The OS administrator/SYSTEM remains outside this local trust boundary.
    """
    if os.name != "nt":
        raise PipelineIntegrityError("runtime_immutable_windows_only")
    import ctypes

    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    if shell32.IsUserAnAdmin():
        raise PipelineIntegrityError("runtime_immutable_elevated_worker_refused")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create = kernel32.CreateFileW
    create.argtypes = [
        ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32,
        ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p,
    ]
    create.restype = ctypes.c_void_p
    close = kernel32.CloseHandle
    close.argtypes = [ctypes.c_void_p]
    close.restype = ctypes.c_int

    INVALID = ctypes.c_void_p(-1).value
    SHARE_ALL = 0x00000007
    SHARE_READ = 0x00000001
    OPEN_EXISTING = 3
    BACKUP_SEMANTICS = 0x02000000
    GENERIC_READ = 0x80000000
    # Individual access probes are necessary: failing to request a combined
    # mask does NOT prove all individual write rights are denied.
    FILE_WRITE_DATA = 0x0002
    FILE_APPEND_DATA = 0x0004
    FILE_WRITE_EA = 0x0010
    FILE_DELETE_CHILD = 0x0040
    FILE_WRITE_ATTRIBUTES = 0x0100
    DELETE = 0x00010000
    WRITE_DAC = 0x00040000
    WRITE_OWNER = 0x00080000
    file_write_rights = (
        FILE_WRITE_DATA, FILE_APPEND_DATA, FILE_WRITE_EA,
        FILE_WRITE_ATTRIBUTES, DELETE, WRITE_DAC, WRITE_OWNER,
    )
    directory_write_rights = (
        FILE_WRITE_DATA, FILE_APPEND_DATA, FILE_WRITE_EA, FILE_DELETE_CHILD,
        FILE_WRITE_ATTRIBUTES, DELETE, WRITE_DAC, WRITE_OWNER,
    )

    def _open(path: Path, access: int, share: int, is_dir: bool) -> int:
        handle = create(
            str(path), access, share, None, OPEN_EXISTING,
            BACKUP_SEMANTICS if is_dir else 0, None,
        )
        if handle == INVALID or handle is None:
            return -int(ctypes.get_last_error())
        return int(handle)

    directories: set[Path] = set(additional_directories or ())
    for directory in tuple(directories):
        if not directory.is_dir() or directory.is_symlink() or getattr(directory,"is_junction",lambda:False)():
            raise PipelineIntegrityError("runtime_immutable_declared_directory_invalid")
        for ancestor in directory.parents:
            if ancestor == ancestor.parent:
                continue
            if ancestor.is_symlink() or getattr(ancestor,"is_junction",lambda:False)():
                raise PipelineIntegrityError("runtime_immutable_linked_ancestor")
            directories.add(ancestor)
    for path in files:
        if not path.is_file() or path.is_symlink() or getattr(path,"is_junction",lambda:False)():
            raise PipelineIntegrityError("runtime_immutable_artifact_missing_or_linked")
        for ancestor in path.parents:
            # Drive roots cannot be renamed; check write privileges there
            # anyway but do not hold open a long-lived volume-root handle.
            if ancestor == ancestor.parent:
                continue
            if ancestor.is_symlink() or getattr(ancestor,"is_junction",lambda:False)():
                raise PipelineIntegrityError("runtime_immutable_linked_ancestor")
            directories.add(ancestor)
    # Non-destructive access tests on every file, directory and ancestor:
    # all rights must fail specifically with ACCESS_DENIED; a sharing
    # violation or unexpected error is not evidence of immutability.
    for path, is_dir in (
        [(p, True) for p in sorted(directories, key=str)]
        + [(p, False) for p in sorted(files, key=str)]
    ):
        for right in directory_write_rights if is_dir else file_write_rights:
            h = _open(path, right, SHARE_ALL, is_dir)
            if h > 0:
                close(h)
                raise PipelineIntegrityError("runtime_immutable_write_permission_present")
            if h != -5:
                raise PipelineIntegrityError("runtime_immutable_acl_proof_unavailable")

    held: list[int] = []
    try:
        # All verified files remain open with a kernel sharing restriction
        # forbidding subsequent writes/deletes. Directories likewise reject
        # rename/replace; ACL preflight above prevents adding source files.
        for path, is_dir in (
            [(p, True) for p in sorted(directories, key=str)]
            + [(p, False) for p in sorted(files, key=str)]
        ):
            handle = _open(path, GENERIC_READ, SHARE_READ, is_dir)
            if handle <= 0:
                raise PipelineIntegrityError("runtime_immutable_lock_unavailable")
            held.append(handle)
        return tuple(held)
    except BaseException:
        for handle in reversed(held):
            close(handle)
        raise


def enable_immutable_runtime_pipeline(pipeline: Any) -> None:
    """Call only at worker startup, after generation setup, before accepting HTTP.

    The requested fast mode must fail startup on mutable or unprovable paths.
    Lock first, then rehash the whole pipeline under the held OS handles to
    close the verification/lock time-of-check vs time-of-use window.
    """
    global _lease
    if os.environ.get(_RUNTIME_GATE_ENV, "0") != "1":
        return
    with _guard:
        if _lease is not None:
            raise PipelineIntegrityError("runtime_immutable_double_initialization")
        files = _declared_artifact_paths(pipeline)
        directories = _declared_directory_closure(pipeline)
        handles = _windows_lock_verified_artifacts(
            files, additional_directories=directories
        )
        try:
            pipeline.verify()  # Complete SHA-256 while all source/model bytes are pinned.
        except BaseException:
            _close_windows_handles(handles)
            raise
        _lease = (os.getpid(), pipeline, handles)


def _close_windows_handles(handles: tuple[int, ...]) -> None:
    import ctypes
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    for handle in reversed(handles):
        kernel.CloseHandle(ctypes.c_void_p(handle))


def runtime_immutable_pipeline() -> Any | None:
    """O(1) identity lookup; never trusts env vars without the OS lease."""
    if os.environ.get(_RUNTIME_GATE_ENV, "0") != "1":
        return None
    entry = _lease
    if entry is None or entry[0] != os.getpid():
        raise PipelineIntegrityError("runtime_immutable_startup_attestation_required")
    return entry[1]
