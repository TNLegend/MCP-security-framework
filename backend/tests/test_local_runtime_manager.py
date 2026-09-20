import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool


ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend"
for path in (str(ROOT), str(BACKEND)):
    if path not in sys.path:
        sys.path.insert(0, path)

from app.core.config import settings  # noqa: E402
from app.services import local_runtime_manager as runtime_manager  # noqa: E402
from app.services.local_runtime_manager import (  # noqa: E402
    LocalRuntimeComponentStatus,
    LocalRuntimeManager,
    LocalRuntimeStatus,
    ManagedChildProcess,
)
from scripts import start_framework  # noqa: E402


class FakeProcess:
    def __init__(self) -> None:
        self.terminated = False
        self.killed = False
        self._running = True
        self.return_code = 0

    def poll(self):
        return None if self._running else self.return_code

    def exit(self, return_code: int = 1) -> None:
        self.return_code = return_code
        self._running = False

    def terminate(self) -> None:
        self.terminated = True
        self._running = False

    def kill(self) -> None:
        self.killed = True
        self._running = False

    def wait(self, timeout=None):  # noqa: ANN001
        self._running = False
        return 0


class LocalRuntimeManagerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.original_timeout = settings.local_runtime_start_timeout_seconds
        self.original_db_command = settings.local_runtime_managed_postgres_command_json
        self.original_gateway_host = settings.mcp_gateway_host
        self.original_gateway_port = settings.mcp_gateway_port
        self.original_identity_jwks_url = settings.agent_identity_jwks_url
        self.original_restart_attempts = settings.local_runtime_restart_attempts
        self.original_restart_backoff = settings.local_runtime_restart_backoff_seconds
        settings.local_runtime_start_timeout_seconds = 0.01
        settings.local_runtime_restart_attempts = 2
        settings.local_runtime_restart_backoff_seconds = 0
        settings.local_runtime_managed_postgres_command_json = ""
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self) -> None:
        settings.local_runtime_start_timeout_seconds = self.original_timeout
        settings.local_runtime_managed_postgres_command_json = self.original_db_command
        settings.mcp_gateway_host = self.original_gateway_host
        settings.mcp_gateway_port = self.original_gateway_port
        settings.agent_identity_jwks_url = self.original_identity_jwks_url
        settings.local_runtime_restart_attempts = self.original_restart_attempts
        settings.local_runtime_restart_backoff_seconds = self.original_restart_backoff
        self.temp_dir.cleanup()

    def test_existing_healthy_opa_is_reused_without_duplicate_process(self) -> None:
        started = []
        manager = LocalRuntimeManager(
            process_starter=lambda *args, **kwargs: started.append((args, kwargs)) or FakeProcess(),
            readiness_checker=lambda url: url.endswith("/health") and "8181" in url,
        )

        status = manager.ensure_opa(auto_start=True)

        self.assertEqual(status.status, "healthy")
        self.assertFalse(status.managed_by_framework)
        self.assertEqual(started, [])

    def test_missing_opa_starts_trusted_local_binary_and_reaches_readiness(self) -> None:
        started = []
        health = {"ready": False}
        opa_exe = Path(self.temp_dir.name) / "opa.exe"
        opa_exe.write_bytes(b"opa")

        def start(command, **kwargs):  # noqa: ANN001
            started.append((command, kwargs))
            health["ready"] = True
            return FakeProcess()

        manager = LocalRuntimeManager(
            process_starter=start,
            readiness_checker=lambda url: health["ready"] and "8181" in url,
            sleeper=lambda _: None,
        )

        with patch.object(runtime_manager, "OPA_EXE", opa_exe):
            status = manager.ensure_opa(auto_start=True)

        self.assertEqual(status.status, "healthy")
        self.assertTrue(status.managed_by_framework)
        self.assertEqual(started[0][0][0], str(opa_exe))
        self.assertIn("run", started[0][0])
        self.assertFalse(started[0][1]["shell"])
        manager.shutdown()

    def test_opa_startup_failure_marks_framework_not_ready(self) -> None:
        opa_exe = Path(self.temp_dir.name) / "opa.exe"
        opa_exe.write_bytes(b"opa")
        manager = LocalRuntimeManager(
            process_starter=lambda *args, **kwargs: FakeProcess(),
            readiness_checker=lambda url: False,
            sleeper=lambda _: None,
        )

        with patch.object(runtime_manager, "OPA_EXE", opa_exe):
            status = manager.ensure_opa(auto_start=True)

        self.assertEqual(status.status, "unavailable")
        self.assertEqual(status.detail, "opa_startup_timeout")
        manager.shutdown()

    def test_existing_healthy_gateway_is_reused(self) -> None:
        started = []
        manager = LocalRuntimeManager(
            process_starter=lambda *args, **kwargs: started.append(args) or FakeProcess(),
            readiness_checker=lambda url: "9001/health" in url,
        )

        status = manager.ensure_gateway(auto_start=True)

        self.assertEqual(status.status, "healthy")
        self.assertFalse(status.managed_by_framework)
        self.assertEqual(started, [])

    def test_missing_gateway_launches_trusted_entrypoint(self) -> None:
        started = []
        ready = {"gateway": False}

        def start(command, **kwargs):  # noqa: ANN001
            started.append((command, kwargs))
            ready["gateway"] = True
            return FakeProcess()

        manager = LocalRuntimeManager(
            process_starter=start,
            readiness_checker=lambda url: ready["gateway"] and "9001/health" in url,
            sleeper=lambda _: None,
            python_executable=Path("python.exe"),
        )

        status = manager.ensure_gateway(auto_start=True)

        self.assertEqual(status.status, "healthy")
        self.assertEqual(started[0][0][:4], ["python.exe", "-m", "uvicorn", "proxy.gateway_app:app"])
        self.assertFalse(started[0][1]["shell"])
        manager.shutdown()

    def test_existing_healthy_mcp_lab_is_reused(self) -> None:
        started = []
        manager = LocalRuntimeManager(
            process_starter=lambda *args, **kwargs: started.append(args) or FakeProcess(),
            readiness_checker=lambda url: "9000/health" in url,
        )

        status = manager.ensure_mcp_lab(auto_start=True)

        self.assertEqual(status.status, "healthy")
        self.assertFalse(status.managed_by_framework)
        self.assertEqual(started, [])

    def test_missing_mcp_lab_launches_trusted_entrypoint(self) -> None:
        started = []
        ready = {"mcp_lab": False}

        def start(command, **kwargs):  # noqa: ANN001
            started.append((command, kwargs))
            ready["mcp_lab"] = True
            return FakeProcess()

        manager = LocalRuntimeManager(
            process_starter=start,
            readiness_checker=lambda url: ready["mcp_lab"] and "9000/health" in url,
            sleeper=lambda _: None,
            python_executable=Path("python.exe"),
        )

        status = manager.ensure_mcp_lab(auto_start=True)

        self.assertEqual(status.status, "healthy")
        self.assertTrue(status.managed_by_framework)
        self.assertEqual(started[0][0][:4], ["python.exe", "-m", "uvicorn", "server:app"])
        self.assertIn("mcp-lab", started[0][0][5])
        self.assertEqual(started[0][0][-2:], ["--port", "9000"])
        self.assertFalse(started[0][1]["shell"])
        manager.shutdown()

    def test_missing_local_identity_provider_launches_trusted_entrypoint(self) -> None:
        started = []
        ready = {"identity_provider": False}
        settings.agent_identity_jwks_url = "http://127.0.0.1:9100/jwks.json"

        def start(command, **kwargs):  # noqa: ANN001
            started.append((command, kwargs))
            ready["identity_provider"] = True
            return FakeProcess()

        manager = LocalRuntimeManager(
            process_starter=start,
            readiness_checker=lambda url: ready["identity_provider"] and url.endswith("/jwks.json"),
            sleeper=lambda _: None,
            python_executable=Path("python.exe"),
        )

        status = manager.ensure_identity_provider(auto_start=True)

        self.assertEqual(status.status, "healthy")
        self.assertTrue(status.managed_by_framework)
        self.assertEqual(started[0][0][0], "python.exe")
        self.assertTrue(started[0][0][1].endswith("local_identity_provider.py"))
        self.assertEqual(started[0][0][2], "serve")
        self.assertFalse(started[0][1]["shell"])
        manager.shutdown()

    def test_shutdown_does_not_terminate_externally_started_process(self) -> None:
        process = FakeProcess()
        manager = LocalRuntimeManager(
            started_children=[
                ManagedChildProcess(
                    component="opa",
                    process=process,
                    started_by_framework=False,
                )
            ]
        )

        manager.shutdown()

        self.assertFalse(process.terminated)
        self.assertFalse(process.killed)

    def test_shutdown_terminates_framework_started_child(self) -> None:
        process = FakeProcess()
        manager = LocalRuntimeManager(
            started_children=[
                ManagedChildProcess(
                    component="gateway",
                    process=process,
                    started_by_framework=True,
                )
            ]
        )

        manager.shutdown()

        self.assertTrue(process.terminated)

    def test_database_already_reachable_is_reused(self) -> None:
        engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Session = sessionmaker(bind=engine)
        with Session() as db:
            status = LocalRuntimeManager().database_status(db=db)

        self.assertEqual(status.status, "healthy")

    def test_database_unavailable_without_managed_launcher_fails_clearly(self) -> None:
        manager = LocalRuntimeManager()
        with patch.object(
            manager,
            "database_status",
            return_value=LocalRuntimeComponentStatus(
                component="database",
                status="unavailable",
            ),
        ):
            status = manager.ensure_database(auto_start=True)

        self.assertEqual(status.status, "unavailable")
        self.assertEqual(status.detail, "database_unavailable_no_managed_launcher")

    def test_managed_database_launcher_uses_trusted_configured_command(self) -> None:
        settings.local_runtime_managed_postgres_command_json = '["pg_ctl", "start", "-D", "local"]'
        started = []
        checks = {"count": 0}
        manager = LocalRuntimeManager(
            process_starter=lambda command, **kwargs: started.append((command, kwargs)) or FakeProcess(),
            sleeper=lambda _: None,
        )

        def db_status():
            checks["count"] += 1
            return LocalRuntimeComponentStatus(
                component="database",
                status="healthy" if checks["count"] > 1 else "unavailable",
            )

        with patch.object(manager, "database_status", side_effect=db_status):
            status = manager.ensure_database(auto_start=True)

        self.assertEqual(status.status, "healthy")
        self.assertEqual(started[0][0], ["pg_ctl", "start", "-D", "local"])
        self.assertFalse(started[0][1]["shell"])
        self.assertFalse(manager.started_children[0].terminate_on_shutdown)
        manager.shutdown()

    def test_managed_database_is_left_running_on_framework_shutdown(self) -> None:
        process = FakeProcess()
        manager = LocalRuntimeManager(
            started_children=[
                ManagedChildProcess(
                    component="database",
                    process=process,
                    terminate_on_shutdown=False,
                )
            ]
        )

        manager.shutdown()

        self.assertFalse(process.terminated)
        self.assertFalse(process.killed)

    def test_required_framework_child_death_is_detected_and_siblings_are_cleaned(self) -> None:
        for failed_component in ("opa", "gateway", "backend", "mcp_lab"):
            with self.subTest(component=failed_component):
                failed = FakeProcess()
                failed.exit(7)
                sibling = FakeProcess()
                manager = LocalRuntimeManager(
                    started_children=[
                        ManagedChildProcess(component=failed_component, process=failed),
                        ManagedChildProcess(component="sibling", process=sibling),
                    ]
                )

                self.assertEqual(
                    manager.required_child_failure(),
                    {"component": failed_component, "return_code": 7},
                )
                manager.shutdown()
                self.assertTrue(sibling.terminated)

    def test_external_process_is_not_monitored_or_terminated(self) -> None:
        process = FakeProcess()
        process.exit(9)
        manager = LocalRuntimeManager(
            started_children=[
                ManagedChildProcess(
                    component="opa",
                    process=process,
                    started_by_framework=False,
                )
            ]
        )

        self.assertIsNone(manager.required_child_failure())
        manager.shutdown()
        self.assertFalse(process.terminated)

    def test_web_status_can_omit_unverifiable_ownership_claims(self) -> None:
        healthy = LocalRuntimeComponentStatus(component="test", status="healthy")
        payload = LocalRuntimeStatus(
            backend=healthy,
            database=healthy,
            opa=healthy,
            gateway=healthy,
        ).as_dict(include_ownership=False)

        for component in ("backend", "database", "opa", "gateway"):
            self.assertNotIn("managed_by_framework", payload[component])


    def test_failed_child_recovery_is_bounded(self) -> None:
        failed = FakeProcess()
        failed.exit(7)
        manager = LocalRuntimeManager(
            started_children=[
                ManagedChildProcess(component="gateway", process=failed),
            ],
            sleeper=lambda _: None,
        )
        healthy = LocalRuntimeComponentStatus(component="gateway", status="healthy")

        with patch.object(manager, "ensure_gateway", return_value=healthy) as restart:
            self.assertTrue(
                manager.recover_required_child(
                    {"component": "gateway", "return_code": 7}
                )
            )
            self.assertTrue(
                manager.recover_required_child(
                    {"component": "gateway", "return_code": 7}
                )
            )
            self.assertFalse(
                manager.recover_required_child(
                    {"component": "gateway", "return_code": 7}
                )
            )

        self.assertEqual(restart.call_count, 2)
        self.assertEqual(manager.restart_counts["gateway"], 2)
        self.assertNotIn(failed, [child.process for child in manager.started_children])

    def test_unknown_or_disabled_recovery_fails_closed(self) -> None:
        manager = LocalRuntimeManager(sleeper=lambda _: None)
        self.assertFalse(
            manager.recover_required_child(
                {"component": "unknown", "return_code": 1}
            )
        )
        settings.local_runtime_restart_attempts = 0
        self.assertFalse(
            manager.recover_required_child(
                {"component": "backend", "return_code": 1}
            )
        )

    def test_process_log_stream_rotates_actively_and_is_bounded(self) -> None:
        class ChunkStream:
            def __init__(self):
                self.chunks = [b"a" * 8, b"b" * 8, b"c" * 8, b""]
                self.closed = False

            def read1(self, size):
                return self.chunks.pop(0)

            def close(self):
                self.closed = True

        stream = ChunkStream()
        log_path = Path(self.temp_dir.name) / "gateway.log"
        runtime_manager._drain_process_output(
            stream,
            log_path,
            max_bytes=10,
            backup_count=2,
        )

        self.assertTrue(stream.closed)
        self.assertEqual(log_path.read_bytes(), b"c" * 8)
        self.assertEqual(
            log_path.with_name("gateway.log.1").read_bytes(),
            b"b" * 8,
        )
        self.assertEqual(
            log_path.with_name("gateway.log.2").read_bytes(),
            b"a" * 8,
        )
        self.assertFalse(log_path.with_name("gateway.log.3").exists())
        self.assertTrue(
            all(
                path.stat().st_size <= 10
                for path in (
                    log_path,
                    log_path.with_name("gateway.log.1"),
                    log_path.with_name("gateway.log.2"),
                )
            )
        )

    def test_gateway_status_exposes_configured_endpoint(self) -> None:
        settings.mcp_gateway_host = "127.0.0.1"
        settings.mcp_gateway_port = 9100
        manager = LocalRuntimeManager(readiness_checker=lambda url: True)

        status = manager.gateway_status()

        self.assertEqual(status.endpoint, "http://127.0.0.1:9100")

    def test_start_framework_enables_only_trusted_managed_database_autostart(self) -> None:
        healthy = LocalRuntimeComponentStatus(component="test", status="healthy")

        class FakeManager:
            def __init__(self):
                self.database_auto_start = None
                self.shutdown_called = False

            def ensure_database(self, *, auto_start):
                self.database_auto_start = auto_start
                return healthy

            def ensure_opa(self, *, auto_start):
                return healthy

            def ensure_identity_provider(self, *, auto_start):
                return healthy

            def ensure_mcp_lab(self, *, auto_start):
                return healthy

            def start_backend(self):
                return healthy

            def ensure_gateway(self, *, auto_start):
                return healthy

            def status(self):
                return LocalRuntimeStatus(
                    backend=healthy,
                    database=healthy,
                    opa=healthy,
                    gateway=healthy,
                )

            def required_child_failure(self):
                return {"component": "backend", "return_code": 1}

            def shutdown(self):
                self.shutdown_called = True

        fake = FakeManager()
        with (
            patch.object(start_framework, "LocalRuntimeManager", return_value=fake),
            patch.object(start_framework, "configure_runtime_environment"),
            patch("builtins.print"),
        ):
            result = start_framework.main()

        self.assertEqual(result, 1)
        self.assertTrue(fake.database_auto_start)
        self.assertTrue(fake.shutdown_called)

    def test_clean_interrupt_shuts_down_owned_children(self) -> None:
        healthy = LocalRuntimeComponentStatus(component="test", status="healthy")

        class InterruptingManager:
            def __init__(self):
                self.shutdown_called = False

            def ensure_database(self, *, auto_start):
                return healthy

            def ensure_opa(self, *, auto_start):
                return healthy

            def ensure_identity_provider(self, *, auto_start):
                return healthy

            def ensure_mcp_lab(self, *, auto_start):
                return healthy

            def start_backend(self):
                return healthy

            def ensure_gateway(self, *, auto_start):
                return healthy

            def status(self):
                return LocalRuntimeStatus(
                    backend=healthy,
                    database=healthy,
                    opa=healthy,
                    gateway=healthy,
                )

            def required_child_failure(self):
                raise KeyboardInterrupt

            def shutdown(self):
                self.shutdown_called = True

        fake = InterruptingManager()
        with (
            patch.object(start_framework, "LocalRuntimeManager", return_value=fake),
            patch.object(start_framework, "configure_runtime_environment"),
            patch("builtins.print"),
        ):
            result = start_framework.main()

        self.assertEqual(result, 0)
        self.assertTrue(fake.shutdown_called)

    def test_no_user_command_injection_path_accepts_only_argument_lists(self) -> None:
        settings.local_runtime_managed_postgres_command_json = '"pg_ctl start"'

        with self.assertRaises(ValueError):
            runtime_manager.managed_postgres_command()


if __name__ == "__main__":
    unittest.main()
