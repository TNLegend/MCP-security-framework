from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import ipaddress
import os
from pathlib import Path
import re
import shutil
import subprocess
from typing import Callable, Iterator, Sequence
from urllib.parse import unquote, urlsplit, urlunsplit
from uuid import uuid4

from scanners.contracts import BuildTargetSnapshot, BuildTargetType, ValidatedWorkspace
from scanners.targets import (
    BuildTargetValidationError,
    LocalTargetPolicy,
    materialize_validated_manifest,
    validate_local_directory,
)


_GIT_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$")
_FULL_COMMIT_RE = re.compile(r"^[0-9a-fA-F]{40}$")


@dataclass(frozen=True, slots=True)
class GitTargetPolicy:
    allowed_hosts: tuple[str, ...]
    timeout_seconds: int = 300
    max_output_bytes: int = 1_000_000
    max_files: int = 20_000
    max_total_bytes: int = 1_000_000_000
    max_file_bytes: int = 100_000_000

    def __post_init__(self) -> None:
        normalized = tuple(host.strip().lower() for host in self.allowed_hosts if host.strip())
        if not normalized:
            raise ValueError("at_least_one_allowed_git_host_required")
        object.__setattr__(self, "allowed_hosts", normalized)
        if self.timeout_seconds < 1:
            raise ValueError("git_timeout_must_be_positive")
        if self.max_output_bytes < 1024:
            raise ValueError("git_max_output_too_small")


@dataclass(frozen=True, slots=True)
class GitCommandResult:
    stdout: bytes
    stderr: bytes = b""


GitRunner = Callable[[Sequence[str], Path, GitTargetPolicy, dict[str, str]], GitCommandResult]


def validate_git_repository_url(value: str, *, policy: GitTargetPolicy) -> str:
    raw = value.strip()
    if not raw or len(raw) > 2048 or any(ord(ch) < 32 for ch in raw):
        raise BuildTargetValidationError("git_url_invalid")
    try:
        parsed = urlsplit(raw)
    except ValueError as exc:
        raise BuildTargetValidationError("git_url_invalid") from exc

    if parsed.scheme.lower() != "https":
        raise BuildTargetValidationError("git_url_https_required")
    if parsed.username is not None or parsed.password is not None:
        raise BuildTargetValidationError("git_url_embedded_credentials_forbidden")
    if not parsed.hostname:
        raise BuildTargetValidationError("git_url_host_required")
    if parsed.query or parsed.fragment:
        raise BuildTargetValidationError("git_url_query_or_fragment_forbidden")
    if parsed.port not in (None, 443):
        raise BuildTargetValidationError("git_url_nonstandard_port_forbidden")

    try:
        host = parsed.hostname.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise BuildTargetValidationError("git_url_host_invalid") from exc

    if host not in policy.allowed_hosts:
        raise BuildTargetValidationError("git_host_not_allowed")

    try:
        literal = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        literal = None
    if literal is not None and (
        literal.is_private
        or literal.is_loopback
        or literal.is_link_local
        or literal.is_reserved
        or literal.is_multicast
        or literal.is_unspecified
    ):
        raise BuildTargetValidationError("git_private_network_target_forbidden")

    decoded_path = unquote(parsed.path)
    if (
        not decoded_path.startswith("/")
        or decoded_path in {"", "/"}
        or "\\" in decoded_path
        or any(part in {"", ".", ".."} for part in decoded_path.split("/")[1:])
    ):
        raise BuildTargetValidationError("git_url_path_invalid")

    netloc = host if parsed.port is None else f"{host}:{parsed.port}"
    return urlunsplit(("https", netloc, parsed.path, "", ""))


def validate_git_ref(value: str | None) -> str:
    ref = (value or "HEAD").strip()
    if not ref or len(ref) > 255 or any(ch.isspace() or ord(ch) < 32 for ch in ref):
        raise BuildTargetValidationError("git_ref_invalid")
    if ref == "HEAD" or _FULL_COMMIT_RE.fullmatch(ref):
        return ref
    if not _GIT_REF_RE.fullmatch(ref):
        raise BuildTargetValidationError("git_ref_invalid")
    if (
        ref.startswith("-")
        or ref.endswith(("/", ".", ".lock"))
        or ".." in ref
        or "//" in ref
        or "@{" in ref
        or any(ch in ref for ch in ("^", "~", ":", "?", "*", "[", "\\"))
    ):
        raise BuildTargetValidationError("git_ref_invalid")
    return ref


def _git_environment() -> dict[str, str]:
    env = dict(os.environ)
    env.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "GCM_INTERACTIVE": "Never",
            "GIT_LFS_SKIP_SMUDGE": "1",
        }
    )
    return env


def run_git_command(
    args: Sequence[str],
    cwd: Path,
    policy: GitTargetPolicy,
    env: dict[str, str],
) -> GitCommandResult:
    try:
        completed = subprocess.run(
            list(args),
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            timeout=policy.timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise BuildTargetValidationError("git_command_timed_out") from exc
    except OSError as exc:
        raise BuildTargetValidationError("git_unavailable") from exc

    stdout = completed.stdout or b""
    stderr = completed.stderr or b""
    if len(stdout) > policy.max_output_bytes or len(stderr) > policy.max_output_bytes:
        raise BuildTargetValidationError("git_output_limit_exceeded")
    if completed.returncode != 0:
        raise BuildTargetValidationError("git_command_failed")
    return GitCommandResult(stdout=stdout, stderr=stderr)


def _safe_git_prefix(repository_dir: Path, hooks_dir: Path) -> list[str]:
    return [
        "git",
        "-C",
        str(repository_dir),
        "-c",
        "credential.helper=",
        "-c",
        "protocol.file.allow=never",
        "-c",
        "protocol.ext.allow=never",
        "-c",
        "http.followRedirects=false",
        "-c",
        "http.sslVerify=true",
        "-c",
        f"core.hooksPath={hooks_dir}",
    ]


def _parse_tree_preflight(
    raw: bytes,
    *,
    policy: GitTargetPolicy,
) -> tuple[int, int]:
    file_count = 0
    total_bytes = 0
    for record in raw.split(b"\x00"):
        if not record:
            continue
        try:
            metadata, raw_path = record.split(b"\t", 1)
            mode, object_type, _object_id, size_text = metadata.split(b" ", 3)
            relative = raw_path.decode("utf-8", errors="strict")
        except (ValueError, UnicodeDecodeError) as exc:
            raise BuildTargetValidationError("git_tree_output_invalid") from exc

        if object_type != b"blob" or mode == b"120000":
            raise BuildTargetValidationError("git_special_tree_entry_forbidden")
        try:
            size = int(size_text)
        except ValueError as exc:
            raise BuildTargetValidationError("git_tree_output_invalid") from exc
        if size < 0:
            raise BuildTargetValidationError("git_tree_output_invalid")
        if size > policy.max_file_bytes:
            raise BuildTargetValidationError("target_file_too_large")
        file_count += 1
        total_bytes += size
        if file_count > policy.max_files:
            raise BuildTargetValidationError("target_file_count_exceeded")
        if total_bytes > policy.max_total_bytes:
            raise BuildTargetValidationError("target_total_size_exceeded")
    return file_count, total_bytes


def materialize_git_workspace(
    repository_url: str,
    *,
    requested_ref: str | None,
    display_name: str,
    workspace_parent: Path,
    policy: GitTargetPolicy,
    linked_server_id: int | None = None,
    runner: GitRunner = run_git_command,
) -> ValidatedWorkspace:
    normalized_url = validate_git_repository_url(repository_url, policy=policy)
    ref = validate_git_ref(requested_ref)
    workspace_parent = workspace_parent.resolve(strict=False)
    workspace_parent.mkdir(parents=True, exist_ok=True)

    fetch_container = workspace_parent / f"git-fetch-{uuid4()}"
    repository_dir = fetch_container / "repository"
    hooks_dir = fetch_container / "disabled-hooks"
    final_parent = workspace_parent / "validated"
    hooks_dir.mkdir(parents=True, exist_ok=False)
    repository_dir.mkdir(parents=True, exist_ok=False)
    env = _git_environment()

    try:
        runner(["git", "init", "--quiet", str(repository_dir)], fetch_container, policy, env)
        prefix = _safe_git_prefix(repository_dir, hooks_dir)
        runner([*prefix, "remote", "add", "origin", normalized_url], fetch_container, policy, env)
        runner(
            [
                *prefix,
                "fetch",
                "--quiet",
                "--no-tags",
                "--depth=1",
                "--filter=blob:none",
                "origin",
                ref,
            ],
            fetch_container,
            policy,
            env,
        )
        resolved = runner(
            [*prefix, "rev-parse", "--verify", "FETCH_HEAD^{commit}"],
            fetch_container,
            policy,
            env,
        ).stdout.decode("ascii", errors="strict").strip().lower()
        if not _FULL_COMMIT_RE.fullmatch(resolved):
            raise BuildTargetValidationError("git_resolved_revision_invalid")

        tree = runner(
            [*prefix, "ls-tree", "-r", "-l", "--full-tree", "-z", "FETCH_HEAD"],
            fetch_container,
            policy,
            env,
        )
        _parse_tree_preflight(
            tree.stdout,
            policy=policy,
        )
        runner(
            [*prefix, "checkout", "--quiet", "--detach", "--force", "FETCH_HEAD", "--"],
            fetch_container,
            policy,
            env,
        )

        manifest = validate_local_directory(
            repository_dir,
            policy=LocalTargetPolicy(
                allowed_roots=(repository_dir,),
                denied_roots=(),
                max_files=policy.max_files,
                max_total_bytes=policy.max_total_bytes,
                max_file_bytes=policy.max_file_bytes,
            ),
        )
        target = BuildTargetSnapshot(
            target_type=BuildTargetType.GIT_REPOSITORY,
            display_name=display_name.strip(),
            source_locator=normalized_url,
            source_revision=resolved,
            source_fingerprint=manifest.source_fingerprint,
            linked_server_id=linked_server_id,
        )
        return materialize_validated_manifest(
            manifest,
            target=target,
            workspace_parent=final_parent,
        )
    finally:
        shutil.rmtree(fetch_container, ignore_errors=True)


@contextmanager
def git_workspace(
    repository_url: str,
    *,
    requested_ref: str | None,
    display_name: str,
    workspace_parent: Path,
    policy: GitTargetPolicy,
    linked_server_id: int | None = None,
    runner: GitRunner = run_git_command,
) -> Iterator[ValidatedWorkspace]:
    workspace = materialize_git_workspace(
        repository_url,
        requested_ref=requested_ref,
        display_name=display_name,
        workspace_parent=workspace_parent,
        policy=policy,
        linked_server_id=linked_server_id,
        runner=runner,
    )
    container = workspace.root.parent
    try:
        yield workspace
    finally:
        shutil.rmtree(container, ignore_errors=True)
