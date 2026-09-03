from __future__ import annotations

import json
from pathlib import Path
import subprocess

import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.models  # noqa: F401
from app.core.config import REPO_ROOT, Settings, settings
from app.db.database import Base
from app.models.build_security import BuildSourceBinding
from app.models.mcp_server import MCPServer
from app.services.build_target_intake import (
    BuildInventoryLinkError,
    available_local_scan_roots,
    bind_target_to_inventory_server,
    get_build_source_binding,
    upsert_build_source_binding,
    configured_git_target_policy,
    configured_inventory_workspace,
    configured_local_target_policy,
)
from scanners.contracts import BuildTargetSnapshot, BuildTargetType
import scanners.git_targets as git_target_module
import scanners.targets as target_module
from scanners.git_targets import (
    GitCommandResult,
    GitTargetPolicy,
    materialize_git_workspace,
    run_git_command,
    validate_git_ref,
    validate_git_repository_url,
)
from scanners.targets import (
    BuildTargetValidationError,
    LocalTargetPolicy,
    local_workspace,
    materialize_local_workspace,
    validate_local_directory,
)


def _policy(root: Path, **overrides) -> LocalTargetPolicy:
    values = {
        "allowed_roots": (root,),
        "max_files": 100,
        "max_total_bytes": 10_000,
        "max_file_bytes": 5_000,
    }
    values.update(overrides)
    return LocalTargetPolicy(**values)


def _target(source: Path) -> BuildTargetSnapshot:
    return BuildTargetSnapshot(
        target_type=BuildTargetType.LOCAL_DIRECTORY,
        display_name="fixture-mcp",
        source_locator=str(source),
    )


def test_local_target_manifest_is_stable_and_ignores_generated_dependency_trees(
    tmp_path: Path,
) -> None:
    source = tmp_path / "mcp"
    source.mkdir()
    (source / "b.py").write_text("print('b')\n", encoding="utf-8")
    (source / "a.py").write_text("print('a')\n", encoding="utf-8")
    node_modules = source / "node_modules"
    node_modules.mkdir()
    (node_modules / "ignored.js").write_text("huge vendor tree", encoding="utf-8")
    git_dir = source / ".git"
    git_dir.mkdir()
    (git_dir / "config").write_text("ignored", encoding="utf-8")

    first = validate_local_directory(source, policy=_policy(tmp_path))
    second = validate_local_directory(source, policy=_policy(tmp_path))

    assert [entry.relative_path for entry in first.entries] == ["a.py", "b.py"]
    assert first.source_fingerprint == second.source_fingerprint
    assert len(first.source_fingerprint) == 64
    assert first.total_bytes == sum(entry.size for entry in first.entries)


def test_local_target_fingerprint_changes_with_source_content(tmp_path: Path) -> None:
    source = tmp_path / "mcp"
    source.mkdir()
    file_path = source / "server.py"
    file_path.write_text("value = 1\n", encoding="utf-8")

    before = validate_local_directory(source, policy=_policy(tmp_path))
    file_path.write_text("value = 2\n", encoding="utf-8")
    after = validate_local_directory(source, policy=_policy(tmp_path))

    assert before.source_fingerprint != after.source_fingerprint


def test_local_target_must_be_inside_an_allowed_root(tmp_path: Path) -> None:
    allowed = tmp_path / "allowed"
    outside = tmp_path / "outside"
    allowed.mkdir()
    outside.mkdir()

    with pytest.raises(BuildTargetValidationError, match="target_outside_allowed_roots"):
        validate_local_directory(outside, policy=_policy(allowed))


def test_local_target_cannot_be_inside_a_denied_root(tmp_path: Path) -> None:
    source = tmp_path / "allowed" / "sensitive" / "mcp"
    source.mkdir(parents=True)

    policy = _policy(
        tmp_path / "allowed",
        denied_roots=(tmp_path / "allowed" / "sensitive",),
    )
    with pytest.raises(BuildTargetValidationError, match="target_inside_denied_root"):
        validate_local_directory(source, policy=policy)


def test_local_target_rejects_reparse_or_link_entries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "mcp"
    source.mkdir()
    (source / "safe.py").write_text("x = 1", encoding="utf-8")
    suspicious = source / "escape"
    suspicious.mkdir()

    original = target_module._is_reparse_or_link
    monkeypatch.setattr(
        target_module,
        "_is_reparse_or_link",
        lambda path: path.name == "escape" or original(path),
    )

    with pytest.raises(
        BuildTargetValidationError,
        match="target_reparse_point_not_allowed",
    ):
        validate_local_directory(source, policy=_policy(tmp_path))


@pytest.mark.parametrize(
    ("policy_overrides", "files", "error"),
    [
        ({"max_files": 1}, {"a.py": "a", "b.py": "b"}, "target_file_count_exceeded"),
        ({"max_file_bytes": 2}, {"a.py": "abc"}, "target_file_too_large"),
        (
            {"max_total_bytes": 3},
            {"a.py": "ab", "b.py": "cd"},
            "target_total_size_exceeded",
        ),
    ],
)
def test_local_target_enforces_scan_bounds(
    tmp_path: Path,
    policy_overrides: dict,
    files: dict[str, str],
    error: str,
) -> None:
    source = tmp_path / "mcp"
    source.mkdir()
    for name, content in files.items():
        (source / name).write_text(content, encoding="utf-8")

    with pytest.raises(BuildTargetValidationError, match=error):
        validate_local_directory(
            source,
            policy=_policy(tmp_path, **policy_overrides),
        )


def test_materialized_workspace_is_isolated_and_bound_to_manifest(tmp_path: Path) -> None:
    source = tmp_path / "mcp"
    source.mkdir()
    original = source / "server.py"
    original.write_text("SAFE = True\n", encoding="utf-8")

    manifest = validate_local_directory(source, policy=_policy(tmp_path))
    workspace = materialize_local_workspace(
        manifest,
        target=_target(source),
        workspace_parent=tmp_path / "runtime-tmp",
    )
    copied = workspace.root / "server.py"

    assert copied.read_text(encoding="utf-8") == "SAFE = True\n"
    assert workspace.target.source_fingerprint == manifest.source_fingerprint
    assert workspace.file_count == 1

    original.write_text("SAFE = False\n", encoding="utf-8")
    assert copied.read_text(encoding="utf-8") == "SAFE = True\n"


def test_materialization_fails_if_source_changed_after_validation(tmp_path: Path) -> None:
    source = tmp_path / "mcp"
    source.mkdir()
    original = source / "server.py"
    original.write_text("AAAA", encoding="utf-8")

    manifest = validate_local_directory(source, policy=_policy(tmp_path))
    original.write_text("BBBB", encoding="utf-8")

    with pytest.raises(
        BuildTargetValidationError,
        match="source_changed_during_materialization",
    ):
        materialize_local_workspace(
            manifest,
            target=_target(source),
            workspace_parent=tmp_path / "runtime-tmp",
        )


def test_workspace_context_removes_temporary_copy(tmp_path: Path) -> None:
    source = tmp_path / "mcp"
    source.mkdir()
    (source / "server.py").write_text("x = 1", encoding="utf-8")
    workspace_parent = tmp_path / "runtime-tmp"

    with local_workspace(
        source,
        target=_target(source),
        policy=_policy(tmp_path),
        workspace_parent=workspace_parent,
    ) as workspace:
        container = workspace.root.parent
        assert workspace.root.is_dir()
        assert (workspace.root / "server.py").is_file()

    assert not container.exists()


def test_materialization_rejects_non_local_target_contract(tmp_path: Path) -> None:
    source = tmp_path / "mcp"
    source.mkdir()
    manifest = validate_local_directory(source, policy=_policy(tmp_path))
    git_target = BuildTargetSnapshot(
        target_type=BuildTargetType.GIT_REPOSITORY,
        display_name="git-target",
        source_locator=str(source),
    )

    with pytest.raises(
        BuildTargetValidationError,
        match="local_workspace_requires_local_target",
    ):
        materialize_local_workspace(
            manifest,
            target=git_target,
            workspace_parent=tmp_path / "runtime-tmp",
        )


def test_local_target_policy_rejects_empty_allowed_roots() -> None:
    with pytest.raises(ValueError, match="at_least_one_allowed_scan_root_required"):
        LocalTargetPolicy(allowed_roots=())


def test_build_scan_settings_default_to_all_local_filesystem_roots() -> None:
    configured = Settings(_env_file=None)
    assert configured.build_scan_allowed_roots == []
    roots = available_local_scan_roots()
    assert roots
    assert all(root.is_absolute() and root.is_dir() for root in roots)


def test_build_scan_settings_accept_explicit_root_restrictions() -> None:
    configured = Settings(
        _env_file=None,
        build_scan_allowed_roots_json=json.dumps([str(REPO_ROOT)]),
    )
    assert configured.build_scan_allowed_roots == [REPO_ROOT.resolve()]


def test_build_scan_settings_reject_invalid_allowed_roots_json() -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, build_scan_allowed_roots_json="{}")


def test_configured_policy_denies_framework_runtime() -> None:
    policy = configured_local_target_policy()
    denied = {path.resolve() for path in policy.denied_roots}
    runtime = REPO_ROOT / ".runtime"
    if runtime.exists():
        assert runtime.resolve() in denied


def test_git_settings_are_clone_ready_and_host_allowlist_is_configurable() -> None:
    configured = Settings(_env_file=None)
    assert configured.build_scan_git_allowed_hosts == [
        "github.com",
        "gitlab.com",
        "bitbucket.org",
    ]
    policy = configured_git_target_policy()
    assert tuple(configured.build_scan_git_allowed_hosts) == policy.allowed_hosts
    assert configured.build_scan_git_timeout_seconds == 300
    assert policy.timeout_seconds == 300

    with pytest.raises(ValidationError):
        Settings(_env_file=None, build_scan_git_allowed_hosts_json="[]")


@pytest.mark.parametrize(
    ("url", "error"),
    [
        ("http://github.com/org/repo.git", "git_url_https_required"),
        ("file:///tmp/repo", "git_url_https_required"),
        ("https://user:pass@github.com/org/repo.git", "git_url_embedded_credentials_forbidden"),
        ("https://localhost/org/repo.git", "git_host_not_allowed"),
        ("https://github.com:8443/org/repo.git", "git_url_nonstandard_port_forbidden"),
        ("https://github.com/org/../repo.git", "git_url_path_invalid"),
        ("https://github.com/org/repo.git?x=1", "git_url_query_or_fragment_forbidden"),
    ],
)
def test_git_url_validation_fails_closed(url: str, error: str) -> None:
    policy = GitTargetPolicy(allowed_hosts=("github.com",))
    with pytest.raises(BuildTargetValidationError, match=error):
        validate_git_repository_url(url, policy=policy)


def test_git_url_validation_returns_normalized_https_locator() -> None:
    policy = GitTargetPolicy(allowed_hosts=("github.com",))
    assert (
        validate_git_repository_url("  HTTPS://GitHub.com/org/repo.git  ", policy=policy)
        == "https://github.com/org/repo.git"
    )


@pytest.mark.parametrize(
    "ref",
    [
        "-main",
        "feature branch",
        "refs/heads/main..evil",
        "refs/heads/main@{1}",
        "refs/heads/main^",
        "refs/heads/main:evil",
        "refs/heads/main.lock",
        "refs/heads/main/",
    ],
)
def test_git_ref_validation_rejects_option_and_revision_injection(ref: str) -> None:
    with pytest.raises(BuildTargetValidationError, match="git_ref_invalid"):
        validate_git_ref(ref)


def test_git_ref_validation_accepts_head_branch_tag_and_commit() -> None:
    assert validate_git_ref(None) == "HEAD"
    assert validate_git_ref("main") == "main"
    assert validate_git_ref("refs/tags/v1.2.3") == "refs/tags/v1.2.3"
    commit = "a" * 40
    assert validate_git_ref(commit) == commit


def test_git_command_runner_never_uses_shell_or_interactive_input(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured = {}

    def fake_run(args, **kwargs):
        captured["args"] = list(args)
        captured.update(kwargs)
        return subprocess.CompletedProcess(args=args, returncode=0, stdout=b"ok", stderr=b"")

    monkeypatch.setattr(git_target_module.subprocess, "run", fake_run)
    policy = GitTargetPolicy(allowed_hosts=("github.com",))
    result = run_git_command(
        ["git", "--version"],
        tmp_path,
        policy,
        {"GIT_TERMINAL_PROMPT": "0"},
    )

    assert result.stdout == b"ok"
    assert captured["shell"] is False
    assert captured["stdin"] is subprocess.DEVNULL
    assert captured["timeout"] == policy.timeout_seconds


def test_git_command_runner_fails_closed_on_timeout_and_output_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = GitTargetPolicy(
        allowed_hosts=("github.com",),
        timeout_seconds=5,
        max_output_bytes=1024,
    )

    def timeout_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=["git"], timeout=5)

    monkeypatch.setattr(git_target_module.subprocess, "run", timeout_run)
    with pytest.raises(BuildTargetValidationError, match="git_command_timed_out"):
        run_git_command(["git", "--version"], tmp_path, policy, {})

    def oversized_run(args, **kwargs):
        return subprocess.CompletedProcess(
            args=args,
            returncode=0,
            stdout=b"x" * 1025,
            stderr=b"",
        )

    monkeypatch.setattr(git_target_module.subprocess, "run", oversized_run)
    with pytest.raises(BuildTargetValidationError, match="git_output_limit_exceeded"):
        run_git_command(["git", "--version"], tmp_path, policy, {})


class _FakeGitRunner:
    def __init__(self, *, tree: bytes | None = None):
        self.calls: list[list[str]] = []
        self.tree = tree or b"100644 blob abcdef 8\tserver.py\x00"

    def __call__(self, args, cwd, policy, env):
        command = list(args)
        self.calls.append(command)
        if "rev-parse" in command:
            return GitCommandResult(stdout=(b"a" * 40) + b"\n")
        if "ls-tree" in command:
            return GitCommandResult(stdout=self.tree)
        if "checkout" in command:
            repo_index = command.index("-C") + 1
            repository = Path(command[repo_index])
            (repository / "server.py").write_bytes(b"print(1)")
        return GitCommandResult(stdout=b"")


def test_git_workspace_binds_immutable_revision_and_copies_only_source(tmp_path: Path) -> None:
    runner = _FakeGitRunner()
    policy = GitTargetPolicy(
        allowed_hosts=("github.com",),
        max_files=10,
        max_total_bytes=1000,
        max_file_bytes=1000,
    )
    workspace = materialize_git_workspace(
        "https://github.com/org/repo.git",
        requested_ref="main",
        display_name="repo-mcp",
        workspace_parent=tmp_path / "build",
        policy=policy,
        linked_server_id=7,
        runner=runner,
    )

    assert workspace.target.target_type == BuildTargetType.GIT_REPOSITORY
    assert workspace.target.source_locator == "https://github.com/org/repo.git"
    assert workspace.target.source_revision == "a" * 40
    assert workspace.target.linked_server_id == 7
    assert len(workspace.target.source_fingerprint or "") == 64
    assert (workspace.root / "server.py").read_bytes() == b"print(1)"
    assert not (workspace.root / ".git").exists()
    flattened = [" ".join(call) for call in runner.calls]
    assert any("protocol.file.allow=never" in call for call in flattened)
    assert any("protocol.ext.allow=never" in call for call in flattened)
    assert any("credential.helper=" in call for call in flattened)
    assert any("fetch" in call and "main" in call for call in flattened)


def test_git_tree_preflight_rejects_symlinks_before_checkout(tmp_path: Path) -> None:
    runner = _FakeGitRunner(tree=b"120000 blob abcdef 6\tlink\x00")
    policy = GitTargetPolicy(allowed_hosts=("github.com",))

    with pytest.raises(BuildTargetValidationError, match="git_special_tree_entry_forbidden"):
        materialize_git_workspace(
            "https://github.com/org/repo.git",
            requested_ref="main",
            display_name="repo-mcp",
            workspace_parent=tmp_path / "build",
            policy=policy,
            runner=runner,
        )

    assert not any("checkout" in call for call in runner.calls)


def test_inventory_source_binding_is_one_per_server_and_normalized() -> None:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    with Session() as db:
        server = MCPServer(
            name="inventory-mcp",
            server_type="mcp",
            endpoint="http://127.0.0.1:9010/mcp",
            status="active",
        )
        db.add(server)
        db.flush()

        first = upsert_build_source_binding(
            db,
            server_id=server.id,
            target_type=BuildTargetType.GIT_REPOSITORY,
            source_locator=" HTTPS://GitHub.com/org/repo.git ",
            source_ref="main",
            actor_user_id="admin-1",
        )
        second = upsert_build_source_binding(
            db,
            server_id=server.id,
            target_type=BuildTargetType.GIT_REPOSITORY,
            source_locator="https://github.com/org/repo.git",
            source_ref="refs/tags/v1.0.0",
            actor_user_id="admin-2",
        )

        assert first.id == second.id
        assert second.source_locator == "https://github.com/org/repo.git"
        assert second.source_ref == "refs/tags/v1.0.0"
        assert second.created_by == "admin-1"
        assert second.updated_by == "admin-2"
        assert db.query(BuildSourceBinding).count() == 1
        assert get_build_source_binding(db, server_id=server.id).id == first.id


def test_inventory_local_binding_opens_validated_workspace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "inventory-source"
    source.mkdir()
    (source / "server.py").write_text("print('ok')\n", encoding="utf-8")
    monkeypatch.setattr(settings, "build_scan_allowed_roots_json", json.dumps([str(tmp_path)]))

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    with Session() as db:
        server = MCPServer(
            name="inventory-local",
            server_type="mcp",
            endpoint="http://127.0.0.1:9012/mcp",
            status="active",
        )
        db.add(server)
        db.flush()
        upsert_build_source_binding(
            db,
            server_id=server.id,
            target_type=BuildTargetType.LOCAL_DIRECTORY,
            source_locator=str(source),
            source_ref=None,
            actor_user_id="admin",
        )

        with configured_inventory_workspace(db, server_id=server.id) as workspace:
            container = workspace.root.parent
            assert workspace.target.linked_server_id == server.id
            assert workspace.target.target_type == BuildTargetType.LOCAL_DIRECTORY
            assert workspace.target.display_name == "inventory-local"
            assert len(workspace.target.source_fingerprint or "") == 64
            assert (workspace.root / "server.py").is_file()

        assert not container.exists()


def test_inventory_source_binding_rejects_local_ref_and_missing_binding(tmp_path: Path) -> None:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    with Session() as db:
        server = MCPServer(
            name="inventory-mcp",
            server_type="mcp",
            endpoint="http://127.0.0.1:9011/mcp",
            status="active",
        )
        db.add(server)
        db.flush()

        with pytest.raises(BuildInventoryLinkError, match="local_source_ref_not_allowed"):
            upsert_build_source_binding(
                db,
                server_id=server.id,
                target_type=BuildTargetType.LOCAL_DIRECTORY,
                source_locator=str(tmp_path),
                source_ref="main",
                actor_user_id="admin",
            )

        with pytest.raises(BuildInventoryLinkError, match="build_source_binding_not_configured"):
            get_build_source_binding(db, server_id=server.id)


def test_inventory_link_requires_existing_non_archived_server() -> None:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    with Session() as db:
        active = MCPServer(
            name="active",
            server_type="mcp",
            endpoint="http://127.0.0.1:9000/mcp",
            status="active",
        )
        archived = MCPServer(
            name="archived",
            server_type="mcp",
            endpoint="http://127.0.0.1:9002/mcp",
            status="archived",
        )
        db.add_all([active, archived])
        db.flush()

        target = BuildTargetSnapshot(
            target_type=BuildTargetType.GIT_REPOSITORY,
            display_name="repo-mcp",
            source_locator="https://github.com/org/repo.git",
        )
        linked = bind_target_to_inventory_server(db, target=target, server_id=active.id)
        assert linked.linked_server_id == active.id

        with pytest.raises(BuildInventoryLinkError, match="archived_mcp_server_not_build_scannable"):
            bind_target_to_inventory_server(db, target=target, server_id=archived.id)

        with pytest.raises(BuildInventoryLinkError, match="mcp_server_not_found"):
            bind_target_to_inventory_server(db, target=target, server_id=999999)
