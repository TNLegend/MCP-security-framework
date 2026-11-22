"""UX-01: loaded build identity for a running component.

The identity is captured once, when the process starts serving, and is then
reported unchanged. It never re-reads the repository on request, so a later
checkout, edit or branch switch on disk cannot make an old process look new.

Fields
- ``revision``: from ``MCP_BUILD_REVISION`` (set by a release pipeline) or,
  failing that, ``git rev-parse HEAD`` *at process start*. ``revision_source``
  says which; ``unknown`` when neither is available.
- ``worktree_dirty``: whether tracked files differed from that revision at
  start (``None`` when unknown). A dirty start means the revision alone does
  not describe the loaded code.
- ``source_digest``: SHA-256 over the bytes of the Python modules actually
  imported from this component's source roots at capture time.
- ``started_at``: UTC capture time.

No file paths, environment values or secrets are included.
"""
from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_REVISION_ENV = "MCP_BUILD_REVISION"
_HEX = set("0123456789abcdef")


def _git(*args: str) -> str | None:
    try:
        completed = subprocess.run(
            ["git", *args], cwd=REPOSITORY_ROOT, capture_output=True,
            text=True, timeout=3, check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout.strip()


def _valid_revision(value: str | None) -> str | None:
    value = (value or "").strip().lower()
    if 7 <= len(value) <= 64 and set(value) <= _HEX:
        return value
    return None


def _loaded_source_digest(source_roots: Iterable[Path]) -> tuple[str | None, int]:
    roots = [Path(root).resolve() for root in source_roots]
    entries: list[tuple[str, str]] = []
    for module in list(sys.modules.values()):
        filename = getattr(module, "__file__", None)
        if not filename or not filename.endswith(".py"):
            continue
        path = Path(filename).resolve()
        root = next((r for r in roots if path.is_relative_to(r)), None)
        if root is None:
            continue
        try:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError:
            continue
        entries.append((path.relative_to(REPOSITORY_ROOT).as_posix()
                        if path.is_relative_to(REPOSITORY_ROOT) else path.name, digest))
    if not entries:
        return None, 0
    hasher = hashlib.sha256()
    for relative, digest in sorted(set(entries)):
        hasher.update(relative.encode("utf-8") + b"\0" + digest.encode("ascii") + b"\n")
    return hasher.hexdigest(), len(set(entries))


def capture_build_identity(component: str, source_roots: Iterable[Path]) -> dict:
    revision = _valid_revision(os.environ.get(_REVISION_ENV))
    revision_source = "release_environment" if revision else None
    dirty: bool | None = None
    if revision is None:
        revision = _valid_revision(_git("rev-parse", "HEAD"))
        revision_source = "git_head_at_process_start" if revision else "unknown"
        if revision:
            status = _git("status", "--porcelain", "--untracked-files=no")
            dirty = None if status is None else bool(status)
    digest, module_count = _loaded_source_digest(source_roots)
    return {
        "schema": "mcp.build_identity.v1",
        "component": component,
        "revision": revision,
        "revision_source": revision_source,
        "worktree_dirty": dirty,
        "source_digest": digest,
        "source_module_count": module_count,
        "started_at": datetime.now(timezone.utc).isoformat(),
    }


_CAPTURED: dict[str, dict] = {}
COMPONENT_SOURCE_ROOTS = {
    "api": (REPOSITORY_ROOT / "backend" / "app", REPOSITORY_ROOT / "common", REPOSITORY_ROOT / "proxy"),
    "gateway": (REPOSITORY_ROOT / "proxy", REPOSITORY_ROOT / "common"),
}
POLICY_DIRECTORY = REPOSITORY_ROOT / "policies" / "opa"


def get_build_identity(component: str) -> dict:
    """Return the identity captured at process start (capturing once if needed)."""
    if component not in _CAPTURED:
        identity = capture_build_identity(component, COMPONENT_SOURCE_ROOTS.get(component, ()))
        if component == "api":
            digest, count = on_disk_policy_digest(POLICY_DIRECTORY)
            identity["policy_bundle_digest_at_start"] = digest
            identity["policy_module_count_at_start"] = count
        _CAPTURED[component] = identity
    return dict(_CAPTURED[component])


def policy_bundle_digest(raw_modules: Iterable[str | bytes]) -> str | None:
    """Content-only digest of OPA policy modules, independent of load paths.

    Line endings are normalized so a CRLF checkout and the LF text OPA reports
    for the same policy compare equal.
    """
    digests = []
    for raw in raw_modules:
        data = raw.encode("utf-8") if isinstance(raw, str) else bytes(raw)
        digests.append(hashlib.sha256(data.replace(b"\r\n", b"\n")).hexdigest())
    if not digests:
        return None
    return hashlib.sha256("\n".join(sorted(digests)).encode("ascii")).hexdigest()


def on_disk_policy_digest(policy_dir: Path) -> tuple[str | None, int]:
    files = sorted(Path(policy_dir).glob("*.rego"))
    files = [path for path in files if not path.name.endswith("_test.rego")]
    try:
        return policy_bundle_digest(path.read_bytes() for path in files), len(files)
    except OSError:
        return None, 0
