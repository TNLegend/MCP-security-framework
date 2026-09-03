from __future__ import annotations

import base64
import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
import uuid
from pathlib import Path
from unittest.mock import Mock, patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import ValidationError
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, inspect, select, text
from sqlalchemy.orm import sessionmaker


ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend"
for import_path in (ROOT, BACKEND):
    if str(import_path) not in sys.path:
        sys.path.insert(0, str(import_path))

import app.models  # noqa: E402,F401
from app.models.control_plane import ControlPlaneUser  # noqa: E402
from app.core.config import Settings  # noqa: E402
from app.db.database import Base, engine as configured_engine  # noqa: E402
from app.db import init_db as init_db_module  # noqa: E402
from app.models.control_plane import ControlPlaneConfigRevision, ControlPlaneState  # noqa: E402
from app.models.runtime_call import RuntimeCall  # noqa: E402
from app.services.control_plane_config import create_revision  # noqa: E402
from app.services.published_configuration import (  # noqa: E402
    PublishedConfigurationError,
    PublishedConfigurationProvider,
)
from common.file_permissions import restrict_private_file  # noqa: E402
from common.project_environment import load_project_environment  # noqa: E402
from common.project_paths import resolve_project_path  # noqa: E402
from proxy.backend_client import BackendClient, configured_backend_base_url  # noqa: E402
from proxy.internal_identity_assertion import (  # noqa: E402
    InternalIdentityAssertionError,
    validate_private_key_path,
)
from scripts import create_control_plane_user, local_identity_provider  # noqa: E402
from scripts.check_dependencies import node_supported, postgres_supported  # noqa: E402
from scripts.provision_service_identities import (  # noqa: E402
    provision_service_identities,
)
from scripts.setup_local_environment import (  # noqa: E402
    InstallationCheck,
    REQUIRED_BUILD_SECURITY_TABLES,
    REQUIRED_RUNTIME_CALL_COLUMNS,
    SetupOptions,
    ensure_environment_file,
    ensure_postgres_password,
    ensure_trusted_session_pepper,
    missing_external_configuration,
    _build_security_schema_ok,
    _runtime_calls_schema_ok,
    published_configuration_installation_check,
    prepare_source_only_environment,
    run_post_dependency_setup,
)
from scripts.import_control_plane_config import (  # noqa: E402
    ConfigurationBootstrapError,
    ensure_initial_published_configuration,
    load_latest_config,
)


class ProjectPortabilityTests(unittest.TestCase):
    def _config_session(self):
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        return sessionmaker(bind=engine)

    def test_project_relative_paths_resolve_against_supplied_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project_root = Path(temporary) / "portable-clone"
            project_root.mkdir()

            resolved = resolve_project_path(
                ".runtime/secrets/example.pem",
                project_root=project_root,
            )

            self.assertEqual(
                resolved,
                (project_root / ".runtime" / "secrets" / "example.pem").resolve(),
            )

    def test_backend_settings_normalize_project_relative_secret_paths(self) -> None:
        configured = Settings(
            _env_file=None,
            backend_assertion_jwks_path=".runtime/secrets/assertion-jwks.json",
        )

        self.assertEqual(
            Path(configured.backend_assertion_jwks_path),
            (ROOT / ".runtime" / "secrets" / "assertion-jwks.json").resolve(),
        )

    def test_dotenv_paths_are_normalized_and_os_environment_wins(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project_root = Path(temporary)
            env_file = project_root / ".env"
            env_file.write_text(
                "POSTGRES_HOST=from-file\n"
                "FRONTEND_PORT=5173\n"
                "PROXY_ASSERTION_PRIVATE_KEY_PATH=.runtime/secrets/assertion.pem\n",
                encoding="utf-8",
            )
            with patch.dict(
                os.environ,
                {
                    "POSTGRES_HOST": "from-explicit-environment",
                    "FRONTEND_PORT": "5321",
                    "PROXY_ASSERTION_PRIVATE_KEY_PATH": ".runtime/secrets/explicit.pem",
                },
                clear=True,
            ):
                load_project_environment(env_file, project_root=project_root)

                self.assertEqual(os.environ["POSTGRES_HOST"], "from-explicit-environment")
                self.assertEqual(os.environ["FRONTEND_PORT"], "5321")
                self.assertEqual(
                    Path(os.environ["PROXY_ASSERTION_PRIVATE_KEY_PATH"]),
                    (project_root / ".runtime" / "secrets" / "explicit.pem").resolve(),
                )

    def test_default_local_ports_match_env_example(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            configured = Settings(_env_file=None)

        self.assertEqual(configured.backend_port, 8000)
        self.assertEqual(configured.mcp_gateway_port, 9001)
        self.assertEqual(configured.frontend_port, 5173)
        self.assertEqual(configured.postgres_host, "127.0.0.1")
        self.assertEqual(configured.postgres_port, 55432)
        self.assertIn("http://127.0.0.1:5173", configured.control_center_cors_origins)

    def test_non_default_local_ports_are_configurable_from_environment(self) -> None:
        with patch.dict(
            os.environ,
            {
                "BACKEND_HOST": "127.0.0.1",
                "BACKEND_PORT": "8123",
                "MCP_GATEWAY_HOST": "127.0.0.1",
                "MCP_GATEWAY_PORT": "9234",
                "FRONTEND_HOST": "127.0.0.1",
                "FRONTEND_PORT": "5321",
            },
            clear=True,
        ):
            configured = Settings(_env_file=None)

            self.assertEqual(configured.backend_port, 8123)
            self.assertEqual(configured.mcp_gateway_port, 9234)
            self.assertEqual(configured.frontend_port, 5321)
            self.assertEqual(configured.control_center_cors_origins[0], "http://127.0.0.1:5321")
            self.assertEqual(configured_backend_base_url(), "http://127.0.0.1:8123")
            self.assertEqual(BackendClient().api_base_url, "http://127.0.0.1:8123/api/v1")

    def test_backend_control_center_cors_uses_configured_frontend_port(self) -> None:
        configured = Settings(_env_file=None, frontend_host="127.0.0.1", frontend_port=5321)
        self.assertEqual(
            configured.control_center_cors_origins,
            ["http://127.0.0.1:5321", "http://localhost:5321"],
        )
        self.assertNotIn("*", configured.control_center_cors_origins)
        self.assertNotIn("http://127.0.0.1:5173", configured.control_center_cors_origins)

        app = FastAPI()
        app.add_middleware(
            CORSMiddleware,
            allow_origins=configured.control_center_cors_origins,
            allow_credentials=True,
            allow_methods=["GET"],
            allow_headers=["*"],
        )

        @app.get("/probe")
        def probe() -> dict[str, bool]:
            return {"ok": True}

        client = TestClient(app)
        allowed = client.options(
            "/probe",
            headers={
                "Origin": "http://127.0.0.1:5321",
                "Access-Control-Request-Method": "GET",
            },
        )
        rejected = client.options(
            "/probe",
            headers={
                "Origin": "http://attacker.example:5321",
                "Access-Control-Request-Method": "GET",
            },
        )

        self.assertEqual(allowed.headers.get("access-control-allow-origin"), "http://127.0.0.1:5321")
        self.assertNotEqual(rejected.headers.get("access-control-allow-origin"), "http://attacker.example:5321")

    def test_invalid_frontend_port_fails_configuration(self) -> None:
        with self.assertRaises(ValidationError):
            Settings(_env_file=None, frontend_port=70000)

    def test_invalid_postgres_port_fails_configuration(self) -> None:
        with self.assertRaises(ValidationError):
            Settings(_env_file=None, postgres_port=70000)

    def test_runtime_calls_self_check_requires_current_runtime_columns(self) -> None:
        engine = create_engine("sqlite:///:memory:")
        with engine.begin() as connection:
            connection.execute(
                text(
                    "CREATE TABLE runtime_calls ("
                    "id INTEGER PRIMARY KEY, "
                    "agent_id VARCHAR(255) NOT NULL, "
                    "session_id VARCHAR(255) NOT NULL, "
                    "server_id INTEGER, "
                    "tool_name VARCHAR(255) NOT NULL, "
                    "arguments_summary JSON, "
                    "status VARCHAR(50) NOT NULL, "
                    "created_at TIMESTAMP"
                    ")"
                )
            )

        self.assertFalse(_runtime_calls_schema_ok(inspect(engine)))

        with engine.begin() as connection:
            for column_name in sorted(REQUIRED_RUNTIME_CALL_COLUMNS):
                connection.execute(text(f"ALTER TABLE runtime_calls ADD COLUMN {column_name} VARCHAR(100)"))

        self.assertTrue(_runtime_calls_schema_ok(inspect(engine)))

    def test_build_security_self_check_requires_all_phase6_tables(self) -> None:
        engine = create_engine("sqlite:///:memory:")
        self.assertFalse(_build_security_schema_ok(inspect(engine)))

        Base.metadata.create_all(engine)
        self.assertTrue(_build_security_schema_ok(inspect(engine)))
        self.assertTrue(
            REQUIRED_BUILD_SECURITY_TABLES.issubset(set(inspect(engine).get_table_names()))
        )

    def test_runtime_calls_upgrade_adds_control_plane_columns_idempotently(self) -> None:
        if configured_engine.dialect.name != "postgresql":
            self.skipTest("runtime_calls compatibility ALTER syntax is PostgreSQL-specific")

        schema = f"runtime_upgrade_{uuid.uuid4().hex}"
        try:
            with configured_engine.begin() as connection:
                connection.execute(text(f'CREATE SCHEMA "{schema}"'))
        except Exception as exc:
            self.skipTest(f"PostgreSQL schema creation unavailable: {type(exc).__name__}")

        scoped_engine = create_engine(
            configured_engine.url,
            connect_args={"options": f"-csearch_path={schema}"},
        )
        try:
            self._create_legacy_runtime_upgrade_tables(scoped_engine)
            with patch.object(init_db_module, "engine", scoped_engine):
                init_db_module.ensure_phase2_inventory_columns()
                init_db_module.ensure_phase2_inventory_columns()

            columns = {
                column["name"]
                for column in inspect(scoped_engine).get_columns("runtime_calls")
            }
            self.assertTrue(REQUIRED_RUNTIME_CALL_COLUMNS.issubset(columns))
            self.assertIn("control_plane_revision_id", columns)
            self.assertIn("control_plane_revision_number", columns)
            self.assertIn("control_plane_content_hash", columns)

            with scoped_engine.connect() as connection:
                connection.execute(select(RuntimeCall).limit(0))
        finally:
            scoped_engine.dispose()
            with configured_engine.begin() as connection:
                connection.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))

    def test_fresh_config_bootstrap_creates_valid_published_snapshot_once(self) -> None:
        Session = self._config_session()
        with Session() as db:
            first = ensure_initial_published_configuration(db)
            db.commit()
            first_id = first.revision_id

        with Session() as db:
            snapshot = PublishedConfigurationProvider(db).load_active_snapshot()
            self.assertEqual(snapshot.revision_id, first_id)
            self.assertEqual(snapshot.schema_version, 2)
            self.assertEqual(db.query(ControlPlaneConfigRevision).count(), 1)

            second = ensure_initial_published_configuration(db)
            db.commit()

        self.assertEqual(second.status, "READY")
        self.assertEqual(second.revision_id, first_id)
        with Session() as db:
            self.assertEqual(db.query(ControlPlaneConfigRevision).count(), 1)
            self.assertEqual(db.get(ControlPlaneState, 1).active_revision_id, first_id)

    def test_concurrent_pristine_bootstrap_creates_one_initial_revision(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            engine = create_engine(
                f"sqlite:///{Path(temporary) / 'bootstrap.db'}",
                connect_args={"check_same_thread": False},
            )
            Base.metadata.create_all(engine)
            Session = sessionmaker(bind=engine)
            barrier = threading.Barrier(2)
            results = []
            errors = []

            def bootstrap() -> None:
                try:
                    barrier.wait()
                    with Session() as db:
                        results.append(ensure_initial_published_configuration(db).status)
                        db.commit()
                except Exception as exc:  # pragma: no cover - asserted below
                    errors.append(exc)

            workers = [threading.Thread(target=bootstrap) for _ in range(2)]
            for worker in workers:
                worker.start()
            for worker in workers:
                worker.join(timeout=10)

            self.assertFalse(errors)
            self.assertFalse(any(worker.is_alive() for worker in workers))
            self.assertCountEqual(results, ["IMPORTED", "READY"])
            with Session() as db:
                self.assertEqual(db.query(ControlPlaneConfigRevision).count(), 1)
                self.assertIsNotNone(db.get(ControlPlaneState, 1).active_revision_id)
            engine.dispose()

    def test_unexpected_snapshot_error_does_not_trigger_bootstrap(self) -> None:
        Session = self._config_session()
        with Session() as db:
            with patch(
                "scripts.import_control_plane_config.PublishedConfigurationProvider.load_active_snapshot",
                side_effect=RuntimeError("unexpected provider failure"),
            ):
                with self.assertRaises(ConfigurationBootstrapError) as ctx:
                    ensure_initial_published_configuration(db)
            db.rollback()
            self.assertEqual(ctx.exception.code, "active_config_validation_failed")
            self.assertEqual(db.query(ControlPlaneConfigRevision).count(), 0)
            self.assertIsNone(db.get(ControlPlaneState, 1))

    def test_only_active_config_missing_allows_pristine_bootstrap(self) -> None:
        Session = self._config_session()
        with Session() as db:
            with patch(
                "scripts.import_control_plane_config.PublishedConfigurationProvider.load_active_snapshot",
                side_effect=PublishedConfigurationError("config_hash_mismatch"),
            ):
                with self.assertRaises(ConfigurationBootstrapError) as ctx:
                    ensure_initial_published_configuration(db)
            db.rollback()
            self.assertEqual(ctx.exception.code, "config_hash_mismatch")
            self.assertEqual(db.query(ControlPlaneConfigRevision).count(), 0)
            self.assertIsNone(db.get(ControlPlaneState, 1))

    def test_valid_existing_config_is_preserved_by_bootstrap(self) -> None:
        Session = self._config_session()
        with Session() as db:
            content = load_latest_config()
            revision = create_revision(
                db,
                content=content,
                status="PUBLISHED",
                actor=None,
                change_summary="existing",
            )
            db.add(ControlPlaneState(id=1, active_revision_id=revision.id))
            db.commit()
            revision_id = revision.id

        with Session() as db:
            result = ensure_initial_published_configuration(db)
            db.commit()

        self.assertEqual(result.status, "READY")
        self.assertEqual(result.revision_id, revision_id)
        with Session() as db:
            self.assertEqual(db.query(ControlPlaneConfigRevision).count(), 1)

    def test_revisions_without_active_config_are_not_auto_selected(self) -> None:
        Session = self._config_session()
        with Session() as db:
            create_revision(
                db,
                content=load_latest_config(),
                status="DRAFT",
                actor=None,
                change_summary="ambiguous draft",
            )
            db.commit()

        with Session() as db:
            with self.assertRaises(ConfigurationBootstrapError) as ctx:
                ensure_initial_published_configuration(db)
            db.rollback()
            self.assertEqual(ctx.exception.code, "active_config_missing")
            self.assertEqual(ctx.exception.revision_count, 1)
            self.assertIsNone(db.get(ControlPlaneState, 1))
            self.assertEqual(db.query(ControlPlaneConfigRevision).count(), 1)

    def test_broken_active_pointer_is_not_auto_repaired(self) -> None:
        Session = self._config_session()
        with Session() as db:
            db.add(ControlPlaneState(id=1, active_revision_id=str(uuid.uuid4())))
            db.commit()

        with Session() as db:
            with self.assertRaises(ConfigurationBootstrapError) as ctx:
                ensure_initial_published_configuration(db)
            db.rollback()
            self.assertEqual(ctx.exception.code, "active_config_revision_missing")
            self.assertEqual(db.query(ControlPlaneConfigRevision).count(), 0)

    def test_invalid_active_snapshot_fails_bootstrap_and_self_check(self) -> None:
        Session = self._config_session()
        with Session() as db:
            revision = create_revision(
                db,
                content=load_latest_config(),
                status="PUBLISHED",
                actor=None,
                change_summary="corrupt me",
            )
            db.add(ControlPlaneState(id=1, active_revision_id=revision.id))
            db.flush()
            revision.content_hash = "0" * 64
            db.commit()

        with Session() as db:
            with self.assertRaises(ConfigurationBootstrapError) as ctx:
                ensure_initial_published_configuration(db)
            self.assertEqual(ctx.exception.code, "config_hash_mismatch")

        check = published_configuration_installation_check(Session)
        self.assertFalse(check.ok)
        self.assertEqual(check.detail, "config_hash_mismatch")

    def test_published_configuration_self_check_uses_runtime_snapshot_validation(self) -> None:
        Session = self._config_session()
        self.assertFalse(published_configuration_installation_check(Session).ok)

        with Session() as db:
            ensure_initial_published_configuration(db)
            db.commit()

        check = published_configuration_installation_check(Session)
        self.assertTrue(check.ok)

    def _create_legacy_runtime_upgrade_tables(self, engine) -> None:  # noqa: ANN001
        with engine.begin() as connection:
            connection.execute(text("CREATE TABLE mcp_servers (id INTEGER PRIMARY KEY)"))
            connection.execute(text("CREATE TABLE mcp_tools (id INTEGER PRIMARY KEY)"))
            connection.execute(
                text(
                    "CREATE TABLE runtime_calls ("
                    "id INTEGER PRIMARY KEY, "
                    "agent_id VARCHAR(255) NOT NULL, "
                    "session_id VARCHAR(255) NOT NULL, "
                    "server_id INTEGER, "
                    "tool_name VARCHAR(255) NOT NULL, "
                    "arguments_summary JSON, "
                    "status VARCHAR(50) NOT NULL, "
                    "created_at TIMESTAMP"
                    ")"
                )
            )
            connection.execute(
                text("CREATE TABLE control_plane_config_revisions (id INTEGER PRIMARY KEY)")
            )
            connection.execute(text("CREATE TABLE tool_protocol_observations (id INTEGER PRIMARY KEY)"))
            connection.execute(text("CREATE TABLE tool_analyses (id INTEGER PRIMARY KEY)"))
            connection.execute(text("CREATE TABLE tool_approved_baselines (id INTEGER PRIMARY KEY)"))
            connection.execute(
                text(
                    "CREATE TABLE identity_assertion_replays ("
                    "issuer VARCHAR(255), "
                    "jti_hash VARCHAR(64)"
                    ")"
                )
            )
            connection.execute(
                text(
                    "CREATE TABLE trusted_agent_sessions ("
                    "session_reference VARCHAR(255), "
                    "token_hash VARCHAR(64), "
                    "agent_id VARCHAR(255), "
                    "expires_at TIMESTAMP, "
                    "revoked_at TIMESTAMP"
                    ")"
                )
            )

    def test_fresh_source_layout_creates_env_and_runtime_without_copied_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project_root = Path(temporary) / "fresh-clone"
            project_root.mkdir()
            env_example = project_root / ".env.example"
            env_file = project_root / ".env"
            env_example.write_text(
                "POSTGRES_PASSWORD=external-value\n"
                "TRUSTED_SESSION_TOKEN_PEPPER=<configure-secret-pepper>\n",
                encoding="utf-8",
            )
            self.assertFalse((project_root / ".runtime").exists())
            self.assertFalse(env_file.exists())

            state = prepare_source_only_environment(
                env_file=env_file,
                env_example=env_example,
                project_root=project_root,
            )

            self.assertTrue(state["env_created"])
            self.assertTrue(state["trusted_session_pepper_generated"])
            self.assertTrue((project_root / ".runtime" / "secrets").is_dir())
            self.assertEqual(
                [path for path in (project_root / ".runtime" / "secrets").rglob("*") if path.is_file()],
                [],
            )
            self.assertNotIn("<configure-secret-pepper>", env_file.read_text(encoding="utf-8"))

    def test_source_only_simulation_generates_all_internal_identity_material(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project_root = Path(temporary) / "fresh-source"
            project_root.mkdir()
            env_example = project_root / ".env.example"
            env_file = project_root / ".env"
            env_example.write_bytes((ROOT / ".env.example").read_bytes())
            prepare_source_only_environment(
                env_file=env_file,
                env_example=env_example,
                project_root=project_root,
            )
            secret_dir = project_root / ".runtime" / "secrets"
            provision_service_identities(secret_dir=secret_dir)
            with patch.dict(
                os.environ,
                {
                    "AGENT_IDENTITY_SIGNING_PRIVATE_KEY_PATH": str(
                        secret_dir / "local-idp-private.pem"
                    ),
                    "AGENT_IDENTITY_PUBLIC_JWKS_PATH": str(
                        secret_dir / "local-idp-public-jwks.json"
                    ),
                },
            ):
                local_identity_provider.ensure_identity_material()

            expected = {
                "mcp-proxy-service-ed25519.pem",
                "mcp-discovery-service-ed25519.pem",
                "internal-service-public-keys.json",
                "control-plane-revision-ed25519.pem",
                "control-plane-revision-ed25519.pub.pem",
                "proxy-assertion-private.pem",
                "proxy-assertion-public-jwks.json",
                "local-idp-private.pem",
                "local-idp-public-jwks.json",
            }
            self.assertTrue(expected.issubset({path.name for path in secret_dir.iterdir()}))

    def test_local_postgres_password_is_generated_once_and_external_hosts_stay_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            local_env = root / ".env"
            local_env.write_text(
                "POSTGRES_HOST=127.0.0.1\n"
                "POSTGRES_PASSWORD=<generate-local>\n",
                encoding="utf-8",
            )
            self.assertTrue(ensure_postgres_password(env_file=local_env))
            first = local_env.read_text(encoding="utf-8")
            self.assertNotIn("<generate-local>", first)
            self.assertFalse(ensure_postgres_password(env_file=local_env))
            self.assertEqual(first, local_env.read_text(encoding="utf-8"))
            self.assertEqual(missing_external_configuration(env_file=local_env), [])

            external_env = root / ".external.env"
            external_env.write_text(
                "POSTGRES_HOST=db.example.internal\n"
                "POSTGRES_PASSWORD=<required>\n",
                encoding="utf-8",
            )
            self.assertFalse(ensure_postgres_password(env_file=external_env))
            self.assertEqual(
                missing_external_configuration(env_file=external_env),
                ["POSTGRES_PASSWORD"],
            )

    def test_env_and_internal_pepper_are_not_overwritten_on_second_setup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            template = root / ".env.example"
            env_file = root / ".env"
            template.write_text(
                "POSTGRES_PASSWORD=external-value\n"
                "TRUSTED_SESSION_TOKEN_PEPPER=<configure-secret-pepper>\n",
                encoding="utf-8",
            )

            self.assertTrue(ensure_environment_file(env_file=env_file, env_example=template))
            self.assertTrue(ensure_trusted_session_pepper(env_file=env_file))
            first = env_file.read_bytes()
            self.assertFalse(ensure_environment_file(env_file=env_file, env_example=template))
            self.assertFalse(ensure_trusted_session_pepper(env_file=env_file))
            self.assertEqual(first, env_file.read_bytes())

    def test_no_developer_absolute_project_path_is_tracked(self) -> None:
        former_developer_root = "D:" + r"\cours\M2FSI\mon_stage"
        result = subprocess.run(
            ["git", "grep", "-n", former_developer_root],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 1, result.stdout)


class DependencyVersionTests(unittest.TestCase):
    def test_node_version_matches_vite_engine_requirement(self) -> None:
        self.assertFalse(node_supported("v20.18.1"))
        self.assertTrue(node_supported("v20.19.0"))
        self.assertFalse(node_supported("v21.7.3"))
        self.assertFalse(node_supported("v22.11.0"))
        self.assertTrue(node_supported("v22.12.0"))
        self.assertTrue(node_supported("v24.12.0"))

    def test_postgres_minimum_version(self) -> None:
        self.assertFalse(postgres_supported("postgres (PostgreSQL) 14.13"))
        self.assertTrue(postgres_supported("postgres (PostgreSQL) 15.0"))
        self.assertTrue(postgres_supported("postgres (PostgreSQL) 18.4"))


class PrivateKeyLocationTests(unittest.TestCase):
    def test_only_runtime_secret_area_is_allowed_inside_project(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repository"
            runtime_root = root / ".runtime" / "secrets"
            runtime_root.mkdir(parents=True)
            external = Path(temporary) / "external.pem"

            for rejected in (root / "backend" / "private.pem", root / "policies" / "private.pem"):
                with self.subTest(path=rejected):
                    with self.assertRaises(InternalIdentityAssertionError):
                        validate_private_key_path(
                            rejected,
                            project_root=root,
                            runtime_secrets_root=runtime_root,
                        )

            accepted = validate_private_key_path(
                runtime_root / "proxy-assertion-private.pem",
                project_root=root,
                runtime_secrets_root=runtime_root,
            )
            self.assertEqual(accepted, (runtime_root / "proxy-assertion-private.pem").resolve())
            self.assertEqual(
                validate_private_key_path(
                    external,
                    project_root=root,
                    runtime_secrets_root=runtime_root,
                ),
                external.resolve(),
            )


class IdentityProvisioningTests(unittest.TestCase):
    def test_separate_installations_generate_distinct_private_keys(self) -> None:
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            provision_service_identities(secret_dir=Path(first))
            provision_service_identities(secret_dir=Path(second))

            self.assertNotEqual(
                (Path(first) / "mcp-proxy-service-ed25519.pem").read_bytes(),
                (Path(second) / "mcp-proxy-service-ed25519.pem").read_bytes(),
            )

    def test_generated_pairs_match_and_second_run_preserves_private_keys(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            secret_dir = Path(temporary)
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                provision_service_identities(secret_dir=secret_dir)
            self.assertEqual(stdout.getvalue(), "")

            private_names = (
                "mcp-proxy-service-ed25519.pem",
                "mcp-discovery-service-ed25519.pem",
                "control-plane-revision-ed25519.pem",
                "proxy-assertion-private.pem",
            )
            original = {name: (secret_dir / name).read_bytes() for name in private_names}
            proxy_key = _load_ed25519_private(secret_dir / private_names[0])
            discovery_key = _load_ed25519_private(secret_dir / private_names[1])
            self.assertNotEqual(_raw_public(proxy_key), _raw_public(discovery_key))

            registry = json.loads(
                (secret_dir / "internal-service-public-keys.json").read_text(encoding="utf-8")
            )
            registry_proxy = serialization.load_pem_public_key(
                registry["services"]["MCP_PROXY"]["keys"][0]["public_key_pem"].encode("ascii")
            )
            self.assertEqual(_raw_public_key(registry_proxy), _raw_public(proxy_key))

            assertion_key = _load_ed25519_private(secret_dir / "proxy-assertion-private.pem")
            jwk = json.loads(
                (secret_dir / "proxy-assertion-public-jwks.json").read_text(encoding="utf-8")
            )["keys"][0]
            self.assertEqual(_decode_b64url(jwk["x"]), _raw_public(assertion_key))

            revision_key = _load_ed25519_private(secret_dir / "control-plane-revision-ed25519.pem")
            revision_public = serialization.load_pem_public_key(
                (secret_dir / "control-plane-revision-ed25519.pub.pem").read_bytes()
            )
            self.assertEqual(_raw_public_key(revision_public), _raw_public(revision_key))

            provision_service_identities(secret_dir=secret_dir)
            self.assertEqual(
                original,
                {name: (secret_dir / name).read_bytes() for name in private_names},
            )

    def test_invalid_existing_private_key_fails_without_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            secret_dir = Path(temporary)
            invalid_path = secret_dir / "mcp-proxy-service-ed25519.pem"
            invalid_path.write_bytes(b"not-a-private-key")

            with self.assertRaises(RuntimeError):
                provision_service_identities(secret_dir=secret_dir)

            self.assertEqual(invalid_path.read_bytes(), b"not-a-private-key")

    def test_local_idp_jwks_matches_generated_key_and_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            secret_dir = Path(temporary)
            key_path = secret_dir / "local-idp-private.pem"
            jwks_path = secret_dir / "local-idp-public-jwks.json"
            with patch.dict(
                os.environ,
                {
                    "AGENT_IDENTITY_SIGNING_PRIVATE_KEY_PATH": str(key_path),
                    "AGENT_IDENTITY_PUBLIC_JWKS_PATH": str(jwks_path),
                    "AGENT_IDENTITY_KEY_ID": "portable-idp",
                },
            ):
                local_identity_provider.ensure_identity_material()
                original = key_path.read_bytes()
                local_identity_provider.ensure_identity_material()

            self.assertEqual(original, key_path.read_bytes())
            private_key = serialization.load_pem_private_key(original, password=None)
            self.assertIsInstance(private_key, rsa.RSAPrivateKey)
            jwk = json.loads(jwks_path.read_text(encoding="utf-8"))["keys"][0]
            numbers = private_key.public_key().public_numbers()
            self.assertEqual(_decode_b64url_int(jwk["n"]), numbers.n)
            self.assertEqual(_decode_b64url_int(jwk["e"]), numbers.e)

    def test_invalid_existing_local_idp_key_fails_without_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            secret_dir = Path(temporary)
            key_path = secret_dir / "local-idp-private.pem"
            jwks_path = secret_dir / "local-idp-public-jwks.json"
            key_path.write_bytes(b"invalid-local-idp-key")
            with patch.dict(
                os.environ,
                {
                    "AGENT_IDENTITY_SIGNING_PRIVATE_KEY_PATH": str(key_path),
                    "AGENT_IDENTITY_PUBLIC_JWKS_PATH": str(jwks_path),
                },
            ):
                with self.assertRaises(ValueError):
                    local_identity_provider.ensure_identity_material()

            self.assertEqual(key_path.read_bytes(), b"invalid-local-idp-key")
            self.assertFalse(jwks_path.exists())

    def test_private_file_permissions_are_restricted_best_effort(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "private.pem"
            path.write_bytes(b"private")
            with patch("common.file_permissions.os.chmod") as chmod:
                restrict_private_file(path)

            chmod.assert_called_once()
            self.assertEqual(chmod.call_args.args[0], path)


class SetupOrchestrationTests(unittest.TestCase):
    def test_clone_database_reuses_healthy_configured_database(self) -> None:
        from scripts import setup_local_environment

        with tempfile.TemporaryDirectory() as temporary:
            env_file = Path(temporary) / ".env"
            env_file.write_text(
                "POSTGRES_HOST=127.0.0.1\n"
                "POSTGRES_PORT=55432\n"
                "POSTGRES_DB=mcp_security\n"
                "POSTGRES_USER=mcp_user\n"
                "POSTGRES_PASSWORD=already-configured\n",
                encoding="utf-8",
            )
            with patch(
                "scripts.setup_local_environment._database_connectable",
                return_value=True,
            ) as connectable, patch(
                "scripts.setup_local_environment._initialize_postgres_cluster"
            ) as initialize_cluster:
                result = setup_local_environment.ensure_database_ready_for_clone(
                    env_file=env_file
                )

        self.assertEqual(result, "existing")
        connectable.assert_called_once()
        initialize_cluster.assert_not_called()

    def test_clone_database_provisions_project_local_cluster_when_port_is_free(self) -> None:
        from scripts import setup_local_environment

        with tempfile.TemporaryDirectory() as temporary:
            env_file = Path(temporary) / ".env"
            env_file.write_text(
                "POSTGRES_HOST=127.0.0.1\n"
                "POSTGRES_PORT=55432\n"
                "POSTGRES_DB=mcp_security\n"
                "POSTGRES_USER=mcp_user\n"
                "POSTGRES_PASSWORD=generated-secret\n",
                encoding="utf-8",
            )
            with (
                patch(
                    "scripts.setup_local_environment._database_connectable",
                    side_effect=[False, True],
                ),
                patch(
                    "scripts.setup_local_environment._tcp_port_open",
                    return_value=False,
                ),
                patch(
                    "scripts.setup_local_environment._initialize_postgres_cluster"
                ) as initialize_cluster,
                patch(
                    "scripts.setup_local_environment._managed_postgres_command",
                    return_value=["postgres", "-D", "data"],
                ),
                patch(
                    "scripts.setup_local_environment._configure_managed_postgres_launcher"
                ) as configure_launcher,
                patch(
                    "scripts.setup_local_environment._start_project_postgres"
                ) as start_database,
                patch(
                    "scripts.setup_local_environment._ensure_database_exists"
                ) as ensure_database,
            ):
                result = setup_local_environment.ensure_database_ready_for_clone(
                    env_file=env_file
                )

        self.assertEqual(result, "project_local")
        initialize_cluster.assert_called_once()
        configure_launcher.assert_called_once()
        start_database.assert_called_once()
        ensure_database.assert_called_once()

    def test_post_dependency_orchestration_invokes_all_bootstrap_steps(self) -> None:
        commands: list[tuple[list[str], Path]] = []
        options = SetupOptions()
        with (
            patch("common.project_environment.load_project_environment"),
            patch("scripts.setup_local_environment.configure_runtime_environment"),
            patch("scripts.setup_local_environment.runtime_environment", return_value={}),
            patch("scripts.setup_local_environment._required_npm_command", return_value="npm.cmd"),
            patch(
                "scripts.setup_local_environment._run",
                side_effect=lambda command, env, cwd=ROOT: commands.append(
                    ([str(part) for part in command], cwd)
                ),
            ),
            patch("scripts.setup_local_environment.validate_internal_artifacts"),
            patch(
                "scripts.setup_local_environment.ensure_database_ready_for_clone",
                return_value="existing",
            ) as ensure_database,
            patch("scripts.setup_local_environment.initialize_database_schema") as initialize_db,
            patch("scripts.setup_local_environment.ensure_published_configuration") as ensure_config,
            patch("scripts.setup_local_environment.bootstrap_initial_admin") as initial_admin,
            patch(
                "scripts.setup_local_environment.installation_self_check",
                return_value=[InstallationCheck("all", True)],
            ),
            patch("scripts.setup_local_environment._print_checks"),
        ):
            completed = run_post_dependency_setup(options, python=Path("python.exe"))

        self.assertEqual(commands[0][0], ["npm.cmd", "ci"])
        command_text = "\n".join(" ".join(command) for command, _ in commands)
        for script in (
            "provision_service_identities.py",
            "local_identity_provider.py",
            "download_tool_analyzer_models.py",
            "download_opa.py",
            "provision_semgrep.py",
            "provision_gitleaks.py",
            "provision_trivy.py",
        ):
            self.assertIn(script, command_text)
        script_order = [
            next(part for part in command if part.endswith(".py")).replace("\\", "/").rsplit("/", 1)[-1]
            for command, _ in commands[1:]
        ]
        self.assertEqual(
            script_order,
            [
                "download_opa.py",
                "provision_semgrep.py",
                "provision_gitleaks.py",
                "provision_trivy.py",
                "download_tool_analyzer_models.py",
                "provision_service_identities.py",
                "local_identity_provider.py",
            ],
        )
        self.assertEqual(completed[0], "database_ready:existing")
        ensure_database.assert_called_once_with()
        initialize_db.assert_called_once_with()
        ensure_config.assert_called_once_with()
        initial_admin.assert_called_once_with(interactive=True)
        self.assertIn("published_configuration", completed)
        self.assertIn("self_check", completed)

    def test_database_bootstrap_reuses_runtime_manager_and_existing_init_db(self) -> None:
        from app.services.local_runtime_manager import LocalRuntimeComponentStatus
        from scripts import setup_local_environment

        manager = Mock()
        manager.ensure_database.return_value = LocalRuntimeComponentStatus(
            component="database",
            status="healthy",
        )
        with (
            patch("app.services.local_runtime_manager.LocalRuntimeManager", return_value=manager),
            patch("app.db.init_db.init_db") as init_db,
        ):
            setup_local_environment.initialize_database_schema()

        manager.ensure_database.assert_called_once_with(auto_start=True)
        init_db.assert_called_once_with()
        manager.shutdown.assert_called_once_with()

    def test_initial_admin_flow_has_no_default_and_is_idempotent(self) -> None:
        engine = create_engine("sqlite:///:memory:")
        ControlPlaneUser.__table__.create(engine)
        Session = sessionmaker(bind=engine)
        with patch.object(create_control_plane_user, "SessionLocal", Session):
            with self.assertRaises(create_control_plane_user.BootstrapAdminRequired):
                create_control_plane_user.ensure_initial_admin(interactive=False)

            passwords = iter(["portable-password", "portable-password"])
            result = create_control_plane_user.ensure_initial_admin(
                interactive=True,
                input_func=lambda prompt: "first-admin",
                password_func=lambda prompt: next(passwords),
            )
            second = create_control_plane_user.ensure_initial_admin(
                interactive=False,
            )

        self.assertEqual(result, "created")
        self.assertEqual(second, "existing")


def _load_ed25519_private(path: Path) -> ed25519.Ed25519PrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise AssertionError("Expected Ed25519 private key")
    return key


def _raw_public(key: ed25519.Ed25519PrivateKey) -> bytes:
    return _raw_public_key(key.public_key())


def _raw_public_key(key) -> bytes:
    return key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _decode_b64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _decode_b64url_int(value: str) -> int:
    return int.from_bytes(_decode_b64url(value), "big")


if __name__ == "__main__":
    unittest.main()
