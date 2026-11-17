from __future__ import annotations

import argparse
import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


REPO_ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = REPO_ROOT / "backend"
FRONTEND_DIR = REPO_ROOT / "frontend"
VENV_DIR = BACKEND_DIR / ".venv"
ENV_EXAMPLE = REPO_ROOT / ".env.example"
ENV_FILE = REPO_ROOT / ".env"

for import_path in (REPO_ROOT, BACKEND_DIR):
    if str(import_path) not in sys.path:
        sys.path.insert(0, str(import_path))

from app.core.runtime_paths import (  # noqa: E402
    MODEL_CACHE_DIR,
    OPA_EXE,
    SEMGREP_EXE,
    SEMGREP_VERSION,
    GITLEAKS_EXE,
    GITLEAKS_VERSION,
    TRIVY_CACHE_DIR,
    TRIVY_EXE,
    TRIVY_VERSION,
    RUNTIME_POSTGRES_DIR,
    RUNTIME_SECRETS_DIR,
    RUNTIME_TMP_DIR,
    configure_runtime_environment,
    ensure_runtime_directories,
    runtime_directories,
    runtime_environment,
)
from scripts.check_dependencies import assert_system_prerequisites, find_postgres_tool  # noqa: E402


EMBEDDING_MODEL_REPOSITORY = "intfloat/multilingual-e5-small"
PLACEHOLDER_VALUES = {"", "change_me", "<configure>", "<required>"}
REQUIRED_BUILD_SECURITY_TABLES = {
    "build_source_bindings",
    "build_scan_runs",
    "build_scanner_runs",
    "build_findings",
    "build_assessments",
}

REQUIRED_RUNTIME_CALL_COLUMNS = {
    "control_plane_revision_id",
    "control_plane_revision_number",
    "control_plane_content_hash",
    "client_protocol_profile_id",
    "client_protocol_era",
    "client_protocol_version",
    "client_transport_kind",
    "upstream_protocol_profile_id",
    "upstream_protocol_era",
    "upstream_protocol_version",
    "upstream_transport_kind",
    "total_duration_ms",
    "policy_duration_ms",
    "upstream_duration_ms",
    "result_guard_duration_ms",
}


@dataclass(frozen=True)
class SetupOptions:
    post_deps: bool = False
    non_interactive: bool = False
    skip_venv: bool = False
    skip_python_deps: bool = False
    skip_frontend: bool = False
    skip_models: bool = False
    skip_opa: bool = False
    skip_semgrep: bool = False
    skip_gitleaks: bool = False
    skip_trivy: bool = False
    skip_service_identities: bool = False
    skip_local_idp: bool = False
    skip_database: bool = False
    skip_config: bool = False
    skip_admin: bool = False
    skip_self_check: bool = False


def venv_python(venv_dir: Path = VENV_DIR) -> Path:
    if os.name == "nt":
        return venv_dir / "Scripts" / "python.exe"
    return venv_dir / "bin" / "python"


def ensure_environment_file(
    *,
    env_file: Path = ENV_FILE,
    env_example: Path = ENV_EXAMPLE,
) -> bool:
    if env_file.exists():
        return False
    if not env_example.is_file():
        raise RuntimeError(f"Environment template is missing: {env_example}")
    env_file.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(env_example, env_file)
    try:
        os.chmod(env_file, 0o600)
    except OSError:
        pass
    return True


def ensure_trusted_session_pepper(*, env_file: Path = ENV_FILE) -> bool:
    lines = env_file.read_text(encoding="utf-8").splitlines()
    generated = secrets.token_urlsafe(48)
    changed = False
    found = False
    updated: list[str] = []
    for line in lines:
        if line.lstrip().startswith("TRUSTED_SESSION_TOKEN_PEPPER="):
            found = True
            _, current = line.split("=", 1)
            if _is_placeholder(current):
                updated.append(f"TRUSTED_SESSION_TOKEN_PEPPER={generated}")
                changed = True
            else:
                updated.append(line)
            continue
        updated.append(line)
    if not found:
        updated.append(f"TRUSTED_SESSION_TOKEN_PEPPER={generated}")
        changed = True
    if changed:
        env_file.write_text("\n".join(updated) + "\n", encoding="utf-8")
        try:
            os.chmod(env_file, 0o600)
        except OSError:
            pass
    return changed


LOCAL_POSTGRES_HOSTS = {"127.0.0.1", "localhost", "::1"}


def _set_env_value(env_file: Path, name: str, value: str) -> None:
    lines = env_file.read_text(encoding="utf-8").splitlines()
    updated: list[str] = []
    found = False
    for line in lines:
        if line.lstrip().startswith(f"{name}="):
            updated.append(f"{name}={value}")
            found = True
        else:
            updated.append(line)
    if not found:
        updated.append(f"{name}={value}")
    env_file.write_text("\n".join(updated) + "\n", encoding="utf-8")
    try:
        os.chmod(env_file, 0o600)
    except OSError:
        pass


def _setup_value(env_file: Path, values: dict[str, str], name: str, default: str = "") -> str:
    if env_file.resolve(strict=False) == ENV_FILE.resolve(strict=False):
        explicit = os.environ.get(name)
        if explicit is not None and not _is_placeholder(explicit):
            return explicit
    return values.get(name, default)


def ensure_postgres_password(*, env_file: Path = ENV_FILE) -> bool:
    values = _read_env_file(env_file)
    host = _setup_value(env_file, values, "POSTGRES_HOST", "127.0.0.1").strip()
    password = _setup_value(env_file, values, "POSTGRES_PASSWORD")
    if not _is_placeholder(password):
        return False
    if host not in LOCAL_POSTGRES_HOSTS:
        return False
    _set_env_value(env_file, "POSTGRES_PASSWORD", secrets.token_urlsafe(32))
    return True


def missing_external_configuration(*, env_file: Path = ENV_FILE) -> list[str]:
    file_values = _read_env_file(env_file)
    host = _setup_value(env_file, file_values, "POSTGRES_HOST", "127.0.0.1").strip()
    password = _setup_value(env_file, file_values, "POSTGRES_PASSWORD")
    if host not in LOCAL_POSTGRES_HOSTS and _is_placeholder(password):
        return ["POSTGRES_PASSWORD"]
    return []


def prepare_source_only_environment(
    *,
    env_file: Path = ENV_FILE,
    env_example: Path = ENV_EXAMPLE,
    project_root: Path = REPO_ROOT,
) -> dict[str, bool]:
    created = ensure_environment_file(env_file=env_file, env_example=env_example)
    pepper_generated = ensure_trusted_session_pepper(env_file=env_file)
    postgres_password_generated = ensure_postgres_password(env_file=env_file)
    if project_root.resolve(strict=False) == REPO_ROOT.resolve(strict=False):
        configure_runtime_environment()
    else:
        ensure_runtime_directories(project_root)
    return {
        "env_created": created,
        "trusted_session_pepper_generated": pepper_generated,
        "postgres_password_generated": postgres_password_generated,
    }


def _database_connectable(
    *,
    host: str,
    port: int,
    database: str,
    user: str,
    password: str,
) -> bool:
    try:
        import psycopg

        with psycopg.connect(
            host=host,
            port=port,
            dbname=database,
            user=user,
            password=password,
            connect_timeout=2,
        ):
            return True
    except Exception:
        return False


def _tcp_port_open(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except OSError:
        return False


def _initialize_postgres_cluster(
    *,
    data_dir: Path,
    user: str,
    password: str,
    env: dict[str, str],
) -> None:
    if (data_dir / "PG_VERSION").is_file():
        return
    initdb = find_postgres_tool("initdb")
    if not initdb:
        raise RuntimeError(
            "PostgreSQL initdb is unavailable. Install PostgreSQL 15+ server binaries."
        )
    data_dir.parent.mkdir(parents=True, exist_ok=True)
    password_file = RUNTIME_TMP_DIR / "postgres-init-password.txt"
    password_file.write_text(password, encoding="utf-8")
    try:
        os.chmod(password_file, 0o600)
    except OSError:
        pass
    try:
        _run(
            [
                initdb,
                "-D",
                data_dir,
                "-U",
                user,
                f"--pwfile={password_file}",
                "--encoding=UTF8",
                "--auth-host=scram-sha-256",
                "--auth-local=trust",
            ],
            env=env,
        )
    finally:
        password_file.unlink(missing_ok=True)


def _managed_postgres_command(*, data_dir: Path, host: str, port: int) -> list[str]:
    postgres = find_postgres_tool("postgres")
    if not postgres:
        raise RuntimeError(
            "PostgreSQL server binary is unavailable. Install PostgreSQL 15+."
        )
    bind_host = "127.0.0.1" if host in LOCAL_POSTGRES_HOSTS else host
    return [
        postgres,
        "-D",
        str(data_dir),
        "-h",
        bind_host,
        "-p",
        str(port),
    ]


def _configure_managed_postgres_launcher(
    command: list[str],
    *,
    env_file: Path = ENV_FILE,
) -> None:
    encoded = json.dumps(command, separators=(",", ":"))
    _set_env_value(env_file, "LOCAL_RUNTIME_MANAGED_POSTGRES_COMMAND_JSON", encoded)
    os.environ["LOCAL_RUNTIME_MANAGED_POSTGRES_COMMAND_JSON"] = encoded


def _start_project_postgres(
    command: list[str],
    *,
    env: dict[str, str],
    host: str,
    port: int,
    user: str,
    password: str,
) -> None:
    log_path = RUNTIME_POSTGRES_DIR / "postgres.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_handle = log_path.open("ab")
    try:
        process = subprocess.Popen(
            command,
            cwd=REPO_ROOT,
            env=env,
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            shell=False,
        )
    finally:
        log_handle.close()

    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(
                "Project-local PostgreSQL exited during startup. "
                f"See {log_path} for details."
            )
        if _database_connectable(
            host=host,
            port=port,
            database="postgres",
            user=user,
            password=password,
        ):
            return
        time.sleep(0.5)
    raise RuntimeError(
        "Project-local PostgreSQL did not become ready within 20 seconds. "
        f"See {log_path} for details."
    )


def _ensure_database_exists(
    *,
    host: str,
    port: int,
    database: str,
    user: str,
    password: str,
) -> None:
    import psycopg
    from psycopg import sql

    with psycopg.connect(
        host=host,
        port=port,
        dbname="postgres",
        user=user,
        password=password,
        connect_timeout=3,
        autocommit=True,
    ) as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1 FROM pg_database WHERE datname = %s", (database,))
            if cursor.fetchone() is None:
                cursor.execute(
                    sql.SQL("CREATE DATABASE {}").format(sql.Identifier(database))
                )


def ensure_database_ready_for_clone(*, env_file: Path = ENV_FILE) -> str:
    values = _read_env_file(env_file)
    host = os.environ.get("POSTGRES_HOST", values.get("POSTGRES_HOST", "127.0.0.1")).strip()
    raw_port = os.environ.get("POSTGRES_PORT", values.get("POSTGRES_PORT", "55432"))
    try:
        port = int(raw_port)
    except ValueError as exc:
        raise RuntimeError("POSTGRES_PORT must be an integer.") from exc
    database = os.environ.get("POSTGRES_DB", values.get("POSTGRES_DB", "mcp_security")).strip()
    user = os.environ.get("POSTGRES_USER", values.get("POSTGRES_USER", "mcp_user")).strip()
    password = os.environ.get("POSTGRES_PASSWORD", values.get("POSTGRES_PASSWORD", ""))

    if not host or not database or not user:
        raise RuntimeError("POSTGRES_HOST, POSTGRES_DB and POSTGRES_USER must not be empty.")
    if not 1 <= port <= 65535:
        raise RuntimeError("POSTGRES_PORT must be between 1 and 65535.")
    if _is_placeholder(password):
        raise RuntimeError("POSTGRES_PASSWORD is not configured.")

    if _database_connectable(
        host=host,
        port=port,
        database=database,
        user=user,
        password=password,
    ):
        return "existing"

    if host not in LOCAL_POSTGRES_HOSTS:
        raise RuntimeError(
            "Configured PostgreSQL is unavailable. Verify POSTGRES_HOST/PORT/DB/USER/PASSWORD."
        )

    if _tcp_port_open(host, port):
        try:
            _ensure_database_exists(
                host=host,
                port=port,
                database=database,
                user=user,
                password=password,
            )
        except Exception as exc:
            raise RuntimeError(
                "A service is already listening on the configured PostgreSQL port, "
                "but the configured credentials cannot bootstrap the database. "
                "Use valid external PostgreSQL credentials or choose another local port."
            ) from exc
        if _database_connectable(
            host=host,
            port=port,
            database=database,
            user=user,
            password=password,
        ):
            return "existing"
        raise RuntimeError("PostgreSQL database bootstrap did not become usable.")

    data_dir = RUNTIME_POSTGRES_DIR / "data"
    runtime_env = {**os.environ, **runtime_environment()}
    _initialize_postgres_cluster(
        data_dir=data_dir,
        user=user,
        password=password,
        env=runtime_env,
    )
    command = _managed_postgres_command(data_dir=data_dir, host=host, port=port)
    _configure_managed_postgres_launcher(command, env_file=env_file)
    _start_project_postgres(
        command,
        env=runtime_env,
        host=host,
        port=port,
        user=user,
        password=password,
    )
    _ensure_database_exists(
        host=host,
        port=port,
        database=database,
        user=user,
        password=password,
    )
    if not _database_connectable(
        host=host,
        port=port,
        database=database,
        user=user,
        password=password,
    ):
        raise RuntimeError("Project-local PostgreSQL database is still unavailable.")
    return "project_local"


def run_post_dependency_setup(
    options: SetupOptions,
    *,
    python: Path,
) -> list[str]:
    from common.project_environment import load_project_environment

    load_project_environment()
    configure_runtime_environment()
    env = {**os.environ, **runtime_environment()}
    completed: list[str] = []

    if not options.skip_database:
        database_mode = ensure_database_ready_for_clone()
        completed.append(f"database_ready:{database_mode}")

    if not options.skip_frontend:
        npm = _required_npm_command()
        _run([npm, "ci"], env=env, cwd=FRONTEND_DIR)
        completed.append("frontend_dependencies")

    if not options.skip_opa:
        _run([python, REPO_ROOT / "scripts" / "download_opa.py"], env=env)
        completed.append("opa")

    if not options.skip_semgrep:
        _run([python, REPO_ROOT / "scripts" / "provision_semgrep.py"], env=env)
        completed.append("semgrep")

    if not options.skip_gitleaks:
        _run([python, REPO_ROOT / "scripts" / "provision_gitleaks.py"], env=env)
        completed.append("gitleaks")

    if not options.skip_trivy:
        _run([python, REPO_ROOT / "scripts" / "provision_trivy.py"], env=env)
        completed.append("trivy")

    if not options.skip_models:
        _run(
            [python, REPO_ROOT / "scripts" / "download_tool_analyzer_models.py"],
            env=env,
        )
        _run([python, REPO_ROOT / "scripts" / "install_m4_models.py"], env=env)
        completed.append("analyzer_models_m6_e5_and_frozen_m4")
        # M3 V3 research SHADOW: existing startup downloads an immutable
        # PUBLIC release anonymously (or uses an explicit verified local
        # source). No moving ref, unpinned model, or policy authority.
        from scripts.install_m3_pg2_v3 import HF_FROZEN_REVISION
        source = os.environ.get("M3_PG2_V3_SOURCE_DIR", "").strip()
        revision = os.environ.get("M3_PG2_V3_HF_REVISION", "").strip() or HF_FROZEN_REVISION
        if source:
            _run([python, REPO_ROOT / "scripts" / "install_m3_pg2_v3.py",
                  "--source", source], env=env)
            completed.append("m3_pg2_v3_research_shadow_assets_local")
        elif revision:
            _run([python, REPO_ROOT / "scripts" / "install_m3_pg2_v3.py",
                  "--from-public-hf"], env=env)
            completed.append("m3_pg2_v3_research_shadow_assets_public_hf")

    if not options.skip_service_identities:
        _run(
            [python, REPO_ROOT / "scripts" / "provision_service_identities.py"],
            env=env,
        )
        completed.append("service_identities")

    if not options.skip_local_idp:
        _run(
            [
                python,
                REPO_ROOT / "scripts" / "local_identity_provider.py",
                "ensure-material",
            ],
            env=env,
        )
        completed.append("local_identity_provider")

    validate_internal_artifacts()

    if not options.skip_database:
        initialize_database_schema()
        completed.append("database_schema")

    if not options.skip_database and not options.skip_config:
        ensure_published_configuration()
        completed.append("published_configuration")

    if not options.skip_admin:
        bootstrap_initial_admin(interactive=not options.non_interactive)
        completed.append("initial_admin")

    if not options.skip_self_check:
        checks = installation_self_check(check_database=not options.skip_database)
        _print_checks(checks)
        failed = [check.name for check in checks if not check.ok]
        if failed:
            raise RuntimeError("Installation self-check failed: " + ", ".join(failed))
        completed.append("self_check")
    return completed


def initialize_database_schema() -> None:
    from app.db.init_db import init_db
    from app.services.local_runtime_manager import LocalRuntimeManager

    manager = LocalRuntimeManager(python_executable=venv_python())
    try:
        database = manager.ensure_database(auto_start=True)
        if database.status != "healthy":
            raise RuntimeError(
                "PostgreSQL is unavailable. Configure POSTGRES_* or the explicitly "
                "trusted LOCAL_RUNTIME_MANAGED_POSTGRES_COMMAND_JSON launcher."
            )
        init_db()
    finally:
        manager.shutdown()


def ensure_published_configuration() -> None:
    from scripts.import_control_plane_config import (
        ConfigurationBootstrapError,
        bootstrap_initial_published_configuration,
    )

    try:
        bootstrap_initial_published_configuration()
    except ConfigurationBootstrapError as exc:
        detail = (
            "Published Control Plane configuration is unavailable and automatic "
            "bootstrap was refused. "
            f"reason={exc.code}; revision_count={exc.revision_count}"
        )
        if exc.revisions:
            safe_revisions = [
                {
                    "revision_number": revision["revision_number"],
                    "status": revision["status"],
                    "schema_version": revision["schema_version"],
                }
                for revision in exc.revisions
            ]
            detail += f"; revisions={safe_revisions}"
        raise RuntimeError(detail) from exc


def bootstrap_initial_admin(*, interactive: bool) -> None:
    from scripts.create_control_plane_user import (
        BootstrapAdminRequired,
        ensure_initial_admin,
    )

    try:
        ensure_initial_admin(interactive=interactive)
    except BootstrapAdminRequired as exc:
        raise RuntimeError(str(exc)) from exc


@dataclass(frozen=True)
class InstallationCheck:
    name: str
    ok: bool
    detail: str | None = None


def installation_self_check(*, check_database: bool = True) -> list[InstallationCheck]:
    checks = [
        InstallationCheck("Environment", ENV_FILE.is_file()),
        InstallationCheck("Python venv", venv_python().is_file()),
        InstallationCheck("Python dependencies", _python_dependencies_healthy()),
        InstallationCheck("Frontend lockfile", (FRONTEND_DIR / "package-lock.json").is_file()),
        InstallationCheck("Frontend dependencies", (FRONTEND_DIR / "node_modules").is_dir()),
        InstallationCheck("OPA", OPA_EXE.is_file()),
        InstallationCheck("Semgrep", _semgrep_available()),
        InstallationCheck("Gitleaks", _gitleaks_available()),
        InstallationCheck("Trivy", _trivy_available()),
        InstallationCheck("Analyzer models", _analyzer_models_available()),
        InstallationCheck("Runtime directories", all(path.is_dir() for path in runtime_directories())),
    ]
    artifact_error = None
    try:
        validate_internal_artifacts()
        artifacts_ok = True
    except RuntimeError as exc:
        artifacts_ok = False
        artifact_error = str(exc)
    checks.append(InstallationCheck("Internal identities", artifacts_ok, artifact_error))

    if check_database:
        from sqlalchemy import func, inspect, select, text

        from app.db.database import SessionLocal, engine
        from app.models.control_plane import ControlPlaneUser
        from app.services.control_plane_auth import ROLE_ADMIN

        try:
            with engine.connect() as connection:
                connection.execute(text("SELECT 1"))
            database_ok = True
        except Exception:
            database_ok = False
        checks.append(
            InstallationCheck(
                "PostgreSQL",
                database_ok,
                None if database_ok else "unavailable",
            )
        )

        schema_ok = False
        admin_ok = False
        published_configuration_check = InstallationCheck(
            "Published configuration",
            False,
            "database_unavailable",
        )
        if database_ok:
            try:
                inspector = inspect(engine)
                tables = set(inspector.get_table_names())
                schema_ok = (
                    {"control_plane_users", "mcp_servers", "mcp_tools"}.issubset(tables)
                    and _runtime_calls_schema_ok(inspector)
                    and _build_security_schema_ok(inspector)
                )
            except Exception:
                schema_ok = False
            if schema_ok:
                published_configuration_check = published_configuration_installation_check()
                try:
                    with SessionLocal() as db:
                        admin_count = int(
                            db.scalar(
                                select(func.count()).select_from(ControlPlaneUser).where(
                                    ControlPlaneUser.role == ROLE_ADMIN,
                                    ControlPlaneUser.enabled.is_(True),
                                )
                            )
                            or 0
                        )
                    admin_ok = admin_count >= 1
                except Exception:
                    admin_ok = False
            else:
                published_configuration_check = InstallationCheck(
                    "Published configuration",
                    False,
                    "schema_unavailable",
                )
        checks.extend(
            [
                InstallationCheck("DB schema", schema_ok),
                published_configuration_check,
                InstallationCheck("Initial ADMIN", admin_ok),
            ]
        )
    return checks


def published_configuration_installation_check(
    session_factory=None,  # noqa: ANN001
) -> InstallationCheck:
    from app.db.database import SessionLocal
    from app.services.published_configuration import (
        PublishedConfigurationError,
        PublishedConfigurationProvider,
    )

    factory = session_factory or SessionLocal
    try:
        with factory() as db:
            PublishedConfigurationProvider(db).load_active_snapshot()
    except PublishedConfigurationError as exc:
        return InstallationCheck("Published configuration", False, exc.code)
    except Exception:
        return InstallationCheck("Published configuration", False, "unavailable")
    return InstallationCheck("Published configuration", True)


def _runtime_calls_schema_ok(inspector) -> bool:  # noqa: ANN001
    if "runtime_calls" not in set(inspector.get_table_names()):
        return False
    columns = {column["name"] for column in inspector.get_columns("runtime_calls")}
    return REQUIRED_RUNTIME_CALL_COLUMNS.issubset(columns)


def _build_security_schema_ok(inspector) -> bool:  # noqa: ANN001
    return REQUIRED_BUILD_SECURITY_TABLES.issubset(set(inspector.get_table_names()))


def validate_internal_artifacts(*, secret_dir: Path = RUNTIME_SECRETS_DIR) -> None:
    required = (
        "mcp-proxy-service-ed25519.pem",
        "mcp-discovery-service-ed25519.pem",
        "internal-service-public-keys.json",
        "control-plane-revision-ed25519.pem",
        "control-plane-revision-ed25519.pub.pem",
        "proxy-assertion-private.pem",
        "proxy-assertion-public-jwks.json",
        "local-idp-private.pem",
        "local-idp-public-jwks.json",
    )
    missing = [name for name in required if not (secret_dir / name).is_file()]
    if missing:
        raise RuntimeError("Missing internal runtime artifacts: " + ", ".join(missing))


def main(argv: Sequence[str] | None = None) -> int:
    options = _parse_options(argv)
    if not options.post_deps:
        assert_system_prerequisites()
    source_state = prepare_source_only_environment()
    missing = missing_external_configuration()
    if missing:
        print(
            "Configuration required before setup can continue: " + ", ".join(missing),
            file=sys.stderr,
        )
        if source_state["env_created"]:
            print("A local .env was created from .env.example.", file=sys.stderr)
        return 2

    python = venv_python()
    env = {**os.environ, **runtime_environment()}
    if not options.post_deps:
        if not options.skip_venv and not python.exists():
            _run([Path(sys.executable), "-m", "venv", VENV_DIR], env=env)
        selected_python = python if python.exists() else Path(sys.executable)
        if not options.skip_python_deps:
            _run(
                [
                    selected_python,
                    "-m",
                    "pip",
                    "install",
                    "--cache-dir",
                    env["PIP_CACHE_DIR"],
                    "-r",
                    BACKEND_DIR / "requirements.txt",
                ],
                env=env,
            )
        if selected_python.resolve() != Path(sys.executable).resolve():
            _run(
                [
                    selected_python,
                    Path(__file__).resolve(),
                    "--post-deps",
                    *_forwarded_option_flags(options),
                ],
                env=env,
            )
            return 0
        python = selected_python

    completed = run_post_dependency_setup(options, python=python)
    print(
        json.dumps(
            {
                "ready": True,
                "completed": completed,
                "env_created": source_state["env_created"],
                "trusted_session_pepper_generated": source_state[
                    "trusted_session_pepper_generated"
                ],
                "postgres_password_generated": source_state[
                    "postgres_password_generated"
                ],
                "python": str(python),
                "opa": str(OPA_EXE),
                "semgrep": str(SEMGREP_EXE),
                "gitleaks": str(GITLEAKS_EXE),
                "trivy": str(TRIVY_EXE),
            },
            indent=2,
        )
    )
    return 0


def _parse_options(argv: Sequence[str] | None) -> SetupOptions:
    parser = argparse.ArgumentParser(
        description="Provision a complete project-local MCP Security Framework installation."
    )
    parser.add_argument("--post-deps", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--non-interactive", action="store_true")
    for name in (
        "venv",
        "python-deps",
        "frontend",
        "models",
        "opa",
        "semgrep",
        "gitleaks",
        "trivy",
        "service-identities",
        "local-idp",
        "database",
        "config",
        "admin",
        "self-check",
    ):
        parser.add_argument(f"--skip-{name}", action="store_true")
    return SetupOptions(**vars(parser.parse_args(argv)))


def _forwarded_option_flags(options: SetupOptions) -> list[str]:
    flags = []
    for field_name, value in vars(options).items():
        if field_name == "post_deps" or not value:
            continue
        flags.append("--" + field_name.replace("_", "-"))
    return flags


def _run(
    command: Sequence[str | Path],
    *,
    env: dict[str, str],
    cwd: Path = REPO_ROOT,
) -> None:
    subprocess.run(
        [str(part) for part in command],
        cwd=cwd,
        env=env,
        check=True,
        shell=False,
    )


def _required_npm_command() -> str:
    command = "npm.cmd" if os.name == "nt" else "npm"
    located = shutil.which(command)
    if located is None:
        raise RuntimeError("Node.js/npm is required before frontend provisioning.")
    return located


def _read_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        name, value = stripped.split("=", 1)
        values[name.strip()] = value.strip().strip('"').strip("'")
    return values


def _is_placeholder(value: str) -> bool:
    stripped = value.strip()
    return stripped in PLACEHOLDER_VALUES or (
        stripped.startswith("<") and stripped.endswith(">")
    )


def _python_dependencies_healthy() -> bool:
    python = venv_python()
    if not python.is_file():
        return False
    try:
        result = subprocess.run(
            [str(python), "-m", "pip", "check"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except Exception:
        return False
    return result.returncode == 0


def _semgrep_available() -> bool:
    if not SEMGREP_EXE.is_file():
        return False
    try:
        result = subprocess.run(
            [str(SEMGREP_EXE), "--version"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
            shell=False,
            env={
                **os.environ,
                "SEMGREP_SEND_METRICS": "off",
                "SEMGREP_ENABLE_VERSION_CHECK": "0",
            },
        )
    except Exception:
        return False
    return result.returncode == 0 and result.stdout.strip().splitlines()[-1:] == [SEMGREP_VERSION]


def _gitleaks_available() -> bool:
    if not GITLEAKS_EXE.is_file():
        return False
    try:
        result = subprocess.run(
            [str(GITLEAKS_EXE), "version"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
            shell=False,
        )
    except Exception:
        return False
    lines = result.stdout.strip().splitlines()
    return result.returncode == 0 and lines[-1:] == [GITLEAKS_VERSION]


def _trivy_available() -> bool:
    if not TRIVY_EXE.is_file():
        return False
    try:
        result = subprocess.run(
            [str(TRIVY_EXE), "--version"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
            shell=False,
        )
    except Exception:
        return False
    version_ok = result.returncode == 0 and any(
        line.strip() == f"Version: {TRIVY_VERSION}"
        for line in result.stdout.splitlines()
    )
    database = TRIVY_CACHE_DIR / "db" / "trivy.db"
    metadata = TRIVY_CACHE_DIR / "db" / "metadata.json"
    return (
        version_ok
        and database.is_file()
        and database.stat().st_size >= 1_000_000
        and metadata.is_file()
    )


def _analyzer_models_available() -> bool:
    """The only M4 is the signed local bundle; E5 belongs to M6."""
    model_dir = MODEL_CACHE_DIR / (
        "models--" + EMBEDDING_MODEL_REPOSITORY.replace("/", "--")
    )
    e5_snapshots = model_dir / "snapshots"
    if not e5_snapshots.is_dir() or not any(
        p.is_dir() for p in e5_snapshots.iterdir()
    ):
        return False
    m4_bundle = Path(os.environ.get(
        "M4_SEMANTICS_MODEL_ROOT",
        str(REPO_ROOT / ".runtime/models/m4_semantics"),
    ))
    try:
        from scripts.install_m4_models import validate_bundle
        validate_bundle(m4_bundle)
    except (RuntimeError, ValueError, OSError, json.JSONDecodeError):
        return False
    return True


def _print_checks(checks: list[InstallationCheck]) -> None:
    for check in checks:
        status = "OK" if check.ok else "FAILED"
        suffix = f" ({check.detail})" if check.detail else ""
        print(f"{check.name:<24} {status}{suffix}")
    if all(check.ok for check in checks):
        print("Installation ready.")


if __name__ == "__main__":
    raise SystemExit(main())
