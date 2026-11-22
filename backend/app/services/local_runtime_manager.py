from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import threading
import time
from typing import Any, BinaryIO, Callable
from urllib.error import URLError
from urllib.parse import urlsplit
from urllib.request import urlopen

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.runtime_paths import OPA_EXE, PROJECT_ROOT, RUNTIME_TMP_DIR, runtime_environment
from app.db.database import engine


ComponentStatusValue = str
ProcessStarter = Callable[..., subprocess.Popen]
ReadinessChecker = Callable[[str], bool]
Sleeper = Callable[[float], None]


@dataclass(frozen=True)
class LocalRuntimeComponentStatus:
    component: str
    status: ComponentStatusValue
    endpoint: str | None = None
    managed_by_framework: bool = False
    detail: str | None = None
    # Captured independently for each component after its status observation;
    # not the frontend fetch time and not proof that an upstream action ran.
    checked_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def as_dict(self) -> dict[str, Any]:
        return {
            "component": self.component,
            "status": self.status,
            "endpoint": self.endpoint,
            "managed_by_framework": self.managed_by_framework,
            "detail": self.detail,
            "checked_at": self.checked_at.isoformat(),
        }


@dataclass
class ManagedChildProcess:
    component: str
    process: subprocess.Popen
    log_handle: Any | None = None
    log_thread: threading.Thread | None = None
    started_by_framework: bool = True
    terminate_on_shutdown: bool = True


@dataclass
class LocalRuntimeStatus:
    backend: LocalRuntimeComponentStatus
    database: LocalRuntimeComponentStatus
    opa: LocalRuntimeComponentStatus
    gateway: LocalRuntimeComponentStatus

    @property
    def ready(self) -> bool:
        return all(
            component.status == "healthy"
            for component in (self.backend, self.database, self.opa, self.gateway)
        )

    def as_dict(self, *, include_ownership: bool = True) -> dict[str, Any]:
        payload = {
            "ready": self.ready,
            "backend": self.backend.as_dict(),
            "database": self.database.as_dict(),
            "opa": self.opa.as_dict(),
            "gateway": self.gateway.as_dict(),
        }
        if not include_ownership:
            for component in ("backend", "database", "opa", "gateway"):
                payload[component].pop("managed_by_framework", None)
        return payload


@dataclass
class LocalRuntimeManager:
    process_starter: ProcessStarter = subprocess.Popen
    readiness_checker: ReadinessChecker | None = None
    sleeper: Sleeper = time.sleep
    python_executable: Path | None = None
    started_children: list[ManagedChildProcess] = field(default_factory=list)
    restart_counts: dict[str, int] = field(default_factory=dict)

    def status(
        self,
        *,
        db: Session | None = None,
        backend_current_process: bool = False,
    ) -> LocalRuntimeStatus:
        return LocalRuntimeStatus(
            backend=(
                LocalRuntimeComponentStatus(
                    component="backend",
                    status="healthy",
                    endpoint=backend_base_url(),
                    managed_by_framework=False,
                )
                if backend_current_process
                else self.backend_status()
            ),
            database=self.database_status(db=db),
            opa=self.opa_status(),
            gateway=self.gateway_status(),
        )

    def ensure_support_services(
        self,
        *,
        auto_start_opa: bool | None = None,
        auto_start_gateway: bool | None = None,
        auto_start_database: bool = False,
    ) -> LocalRuntimeStatus:
        database = self.ensure_database(auto_start=auto_start_database)
        opa = self.ensure_opa(
            auto_start=settings.local_runtime_autostart_opa
            if auto_start_opa is None
            else auto_start_opa
        )
        gateway = self.ensure_gateway(
            auto_start=settings.local_runtime_autostart_gateway
            if auto_start_gateway is None
            else auto_start_gateway
        )
        return LocalRuntimeStatus(
            backend=self.backend_status(),
            database=database,
            opa=opa,
            gateway=gateway,
        )

    def ensure_database(self, *, auto_start: bool = False) -> LocalRuntimeComponentStatus:
        current = self.database_status()
        if current.status == "healthy" or not auto_start:
            return current
        command = managed_postgres_command()
        if command is None:
            return LocalRuntimeComponentStatus(
                component="database",
                status="unavailable",
                detail="database_unavailable_no_managed_launcher",
            )
        self._start_child("database", command, terminate_on_shutdown=False)
        if self._wait_until(lambda: self.database_status().status == "healthy"):
            return LocalRuntimeComponentStatus(
                component="database",
                status="healthy",
                managed_by_framework=True,
            )
        return LocalRuntimeComponentStatus(
            component="database",
            status="unavailable",
            managed_by_framework=True,
            detail="database_startup_timeout",
        )

    def ensure_opa(self, *, auto_start: bool = True) -> LocalRuntimeComponentStatus:
        current = self.opa_status()
        if current.status == "healthy" or not auto_start:
            return current
        command = opa_command()
        if command is None:
            return LocalRuntimeComponentStatus(
                component="opa",
                status="unavailable",
                endpoint=settings.opa_base_url,
                detail="project_local_opa_missing",
            )
        self._start_child("opa", command)
        if self._wait_until(lambda: self.opa_status().status == "healthy"):
            return LocalRuntimeComponentStatus(
                component="opa",
                status="healthy",
                endpoint=settings.opa_base_url,
                managed_by_framework=True,
            )
        return LocalRuntimeComponentStatus(
            component="opa",
            status="unavailable",
            endpoint=settings.opa_base_url,
            managed_by_framework=True,
            detail="opa_startup_timeout",
        )

    def ensure_gateway(self, *, auto_start: bool = True) -> LocalRuntimeComponentStatus:
        current = self.gateway_status()
        if current.status == "healthy" or not auto_start:
            return current
        command = gateway_command(self._python())
        self._start_child("gateway", command)
        if self._wait_until(lambda: self.gateway_status().status == "healthy"):
            return LocalRuntimeComponentStatus(
                component="gateway",
                status="healthy",
                endpoint=gateway_base_url(),
                managed_by_framework=True,
            )
        return LocalRuntimeComponentStatus(
            component="gateway",
            status="unavailable",
            endpoint=gateway_base_url(),
            managed_by_framework=True,
            detail="gateway_startup_timeout",
        )

    def ensure_mcp_lab(self, *, auto_start: bool = True) -> LocalRuntimeComponentStatus:
        current = self.mcp_lab_status()
        if current.status == "healthy" or not auto_start:
            return current
        self._start_child("mcp_lab", mcp_lab_command(self._python()))
        if self._wait_until(lambda: self.mcp_lab_status().status == "healthy"):
            return LocalRuntimeComponentStatus(
                component="mcp_lab",
                status="healthy",
                endpoint=mcp_lab_base_url(),
                managed_by_framework=True,
            )
        return LocalRuntimeComponentStatus(
            component="mcp_lab",
            status="unavailable",
            endpoint=mcp_lab_base_url(),
            managed_by_framework=True,
            detail="mcp_lab_startup_timeout",
        )

    def ensure_identity_provider(
        self,
        *,
        auto_start: bool = True,
    ) -> LocalRuntimeComponentStatus:
        current = self.identity_provider_status()
        if current.status == "healthy" or not auto_start:
            return current
        parsed = urlsplit(settings.agent_identity_jwks_url)
        if parsed.hostname not in {"127.0.0.1", "localhost"}:
            return LocalRuntimeComponentStatus(
                component="identity_provider",
                status="unavailable",
                endpoint=settings.agent_identity_jwks_url,
                detail="external_identity_provider_unavailable",
            )
        self._start_child(
            "identity_provider",
            local_identity_provider_command(self._python()),
        )
        if self._wait_until(lambda: self.identity_provider_status().status == "healthy"):
            return LocalRuntimeComponentStatus(
                component="identity_provider",
                status="healthy",
                endpoint=settings.agent_identity_jwks_url,
                managed_by_framework=True,
            )
        return LocalRuntimeComponentStatus(
            component="identity_provider",
            status="unavailable",
            endpoint=settings.agent_identity_jwks_url,
            managed_by_framework=True,
            detail="identity_provider_startup_timeout",
        )

    def ensure_frontend(self, *, auto_start: bool = True) -> LocalRuntimeComponentStatus:
        current = self.frontend_status()
        if current.status == "healthy" or not auto_start:
            return current
        npm = shutil.which("npm.cmd" if os.name == "nt" else "npm")
        if not npm:
            return LocalRuntimeComponentStatus(
                component="frontend", status="unavailable",
                detail="npm_missing_for_frontend",
            )
        command = [
            npm, "run", "dev", "--", "--host", settings.frontend_host,
            "--port", str(settings.frontend_port), "--strictPort",
        ]
        self._start_child("frontend", command, cwd=PROJECT_ROOT / "frontend")
        if self._wait_until(lambda: self.frontend_status().status == "healthy"):
            return LocalRuntimeComponentStatus(
                component="frontend", status="healthy",
                endpoint=f"http://{settings.frontend_host}:{settings.frontend_port}",
                managed_by_framework=True,
            )
        return LocalRuntimeComponentStatus(
            component="frontend", status="unavailable",
            endpoint=f"http://{settings.frontend_host}:{settings.frontend_port}",
            managed_by_framework=True, detail="frontend_startup_timeout",
        )

    def frontend_status(self) -> LocalRuntimeComponentStatus:
        return _http_status(
            "frontend", f"http://{settings.frontend_host}:{settings.frontend_port}", self._check_url,
            managed_by_framework=self._is_owned_component("frontend"),
        )

    def start_backend(self) -> LocalRuntimeComponentStatus:
        current = self.backend_status()
        if current.status == "healthy":
            return current
        self._start_child("backend", backend_command(self._python()))
        if self._wait_until(lambda: self.backend_status().status == "healthy"):
            return LocalRuntimeComponentStatus(
                component="backend",
                status="healthy",
                endpoint=backend_base_url(),
                managed_by_framework=True,
            )
        return LocalRuntimeComponentStatus(
            component="backend",
            status="unavailable",
            endpoint=backend_base_url(),
            managed_by_framework=True,
            detail="backend_startup_timeout",
        )

    def backend_status(self) -> LocalRuntimeComponentStatus:
        return _http_status(
            "backend",
            f"{backend_base_url()}/api/v1/health",
            self._check_url,
            managed_by_framework=self._is_owned_component("backend"),
        )

    def opa_status(self) -> LocalRuntimeComponentStatus:
        return _http_status(
            "opa",
            f"{settings.opa_base_url.rstrip('/')}/health",
            self._check_url,
            managed_by_framework=self._is_owned_component("opa"),
        )

    def gateway_status(self) -> LocalRuntimeComponentStatus:
        return _http_status(
            "gateway",
            f"{gateway_base_url()}/health",
            self._check_url,
            managed_by_framework=self._is_owned_component("gateway"),
        )

    def mcp_lab_status(self) -> LocalRuntimeComponentStatus:
        return _http_status(
            "mcp_lab",
            f"{mcp_lab_base_url()}/health",
            self._check_url,
            managed_by_framework=self._is_owned_component("mcp_lab"),
        )

    def provenance(self, api_identity: dict[str, Any], *, json_fetcher: Callable[[str], Any] | None = None) -> dict[str, Any]:
        """UX-01: probe each component's *loaded* identity independently.

        API identity is this process's start-time capture. Gateway identity is
        read from the running Gateway's /health. OPA identity is a content
        digest of the policy modules the running OPA reports, compared with
        the policy bundle this API process was started with.
        """
        from common.build_identity import policy_bundle_digest

        fetch = json_fetcher or _fetch_json

        def now() -> str:
            return datetime.now(timezone.utc).isoformat()

        components: dict[str, dict[str, Any]] = {
            "api": {"component": "api", "reachable": True, "build": api_identity, "probed_at": now()},
        }
        try:
            body = fetch(f"{gateway_base_url()}/health")
            build = body.get("build") if isinstance(body, dict) else None
            components["gateway"] = {"component": "gateway", "reachable": True,
                                     "build": build if isinstance(build, dict) else None,
                                     "probed_at": now()}
        except Exception:  # unreachable is a distinct state, never "unknown version"
            components["gateway"] = {"component": "gateway", "reachable": False, "build": None, "probed_at": now()}
        try:
            body = fetch(f"{settings.opa_base_url.rstrip('/')}/v1/policies")
            modules = [
                module for module in (body.get("result") or [])
                if isinstance(module, dict) and not str(module.get("id", "")).endswith("_test.rego")
            ]
            components["opa"] = {
                "component": "opa", "reachable": True,
                "policy_bundle_digest": policy_bundle_digest(str(m.get("raw", "")) for m in modules),
                "policy_module_count": len(modules), "probed_at": now(),
            }
        except Exception:
            components["opa"] = {"component": "opa", "reachable": False,
                                 "policy_bundle_digest": None, "policy_module_count": None, "probed_at": now()}

        gateway_build = components["gateway"].get("build") or {}
        comparisons = [
            _provenance_comparison(
                "gateway_revision_vs_api", "Gateway revision compared with API revision",
                api_identity.get("revision"), gateway_build.get("revision"),
                reachable=components["gateway"]["reachable"],
                dirty=bool(api_identity.get("worktree_dirty") or gateway_build.get("worktree_dirty")),
            ),
            _provenance_comparison(
                "opa_policy_vs_api_start", "Loaded OPA policies compared with the bundle the API started with",
                api_identity.get("policy_bundle_digest_at_start"),
                components["opa"].get("policy_bundle_digest"),
                reachable=components["opa"]["reachable"], dirty=False,
            ),
        ]
        states = {item["status"] for item in comparisons}
        overall = ("mismatch" if "mismatch" in states else "unreachable" if "unreachable" in states
                   else "unknown" if "unknown" in states else "match")
        return {"schema": "mcp.runtime_provenance.v1", "generated_at": now(), "overall": overall,
                "components": components, "comparisons": comparisons}

    def identity_provider_status(self) -> LocalRuntimeComponentStatus:
        endpoint = settings.agent_identity_jwks_url
        if not endpoint or endpoint.startswith("<"):
            return LocalRuntimeComponentStatus(
                component="identity_provider",
                status="unavailable",
                detail="identity_provider_not_configured",
            )
        return _http_status(
            "identity_provider",
            endpoint,
            self._check_url,
            managed_by_framework=self._is_owned_component("identity_provider"),
        )

    def database_status(self, *, db: Session | None = None) -> LocalRuntimeComponentStatus:
        try:
            if db is not None:
                db.execute(text("SELECT 1"))
            else:
                with engine.connect() as connection:
                    connection.execute(text("SELECT 1"))
        except Exception:
            return LocalRuntimeComponentStatus(
                component="database",
                status="unavailable",
                detail="database_unavailable",
            )
        return LocalRuntimeComponentStatus(component="database", status="healthy")

    def shutdown(self) -> None:
        for child in reversed(self.started_children):
            if (
                child.started_by_framework
                and child.terminate_on_shutdown
                and child.process.poll() is None
            ):
                # npm.cmd is a Windows command wrapper: terminating only the
                # wrapper leaves its Node/Vite child listening on the GUI port.
                # Kill the tree while its owned parent is still alive. Only
                # frontend children started by this manager are eligible.
                pid = getattr(child.process, "pid", None)
                if os.name == "nt" and child.component == "frontend" and isinstance(pid, int) and pid > 0:
                    taskkill = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "taskkill.exe"
                    if taskkill.is_file():
                        try:
                            subprocess.run(
                                [str(taskkill), "/PID", str(pid), "/T", "/F"],
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=15,
                                creationflags=subprocess.CREATE_NO_WINDOW,
                                check=False,
                            )
                        except (OSError, subprocess.TimeoutExpired):
                            # Continue with the normal owned-process fallback.
                            pass
                if child.process.poll() is None:
                    child.process.terminate()
                try:
                    child.process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    child.process.kill()
                    child.process.wait(timeout=5)
            # The drain thread owns the subprocess stdout pipe. Closing a
            # buffered pipe on the main thread while the reader is blocked in
            # read1() can deadlock on Windows, even after terminate() if an
            # inherited writer handle remains open. Join first, and only
            # close from this thread when no drain reader is still alive.
            if child.log_thread is not None and child.log_thread.is_alive():
                child.log_thread.join(timeout=2)
            stdout = getattr(child.process, "stdout", None)
            if stdout is not None and (child.log_thread is None or not child.log_thread.is_alive()):
                try:
                    stdout.close()
                except Exception:
                    pass
            if child.log_handle is not None:
                child.log_handle.close()
        self.started_children.clear()

    def required_child_failure(self) -> dict[str, Any] | None:
        for child in self.started_children:
            if not child.started_by_framework or child.component not in {
                "backend",
                "opa",
                "gateway",
                "identity_provider",
                "mcp_lab",
                "frontend",
            }:
                continue
            return_code = child.process.poll()
            if return_code is not None:
                return {
                    "component": child.component,
                    "return_code": return_code,
                }
        return None

    def recover_required_child(self, failure: dict[str, Any]) -> bool:
        component = str(failure.get("component") or "")
        if component not in {"backend", "opa", "gateway", "identity_provider", "mcp_lab", "frontend"}:
            return False
        attempts = settings.local_runtime_restart_attempts
        used = self.restart_counts.get(component, 0)
        if used >= attempts:
            return False
        self.restart_counts[component] = used + 1
        self._discard_failed_children(component)
        backoff = settings.local_runtime_restart_backoff_seconds * (used + 1)
        if backoff > 0:
            self.sleeper(backoff)
        try:
            if component == "backend":
                status = self.start_backend()
            elif component == "opa":
                status = self.ensure_opa(auto_start=True)
            elif component == "gateway":
                status = self.ensure_gateway(auto_start=True)
            elif component == "identity_provider":
                status = self.ensure_identity_provider(auto_start=True)
            elif component == "frontend":
                status = self.ensure_frontend(auto_start=True)
            else:
                status = self.ensure_mcp_lab(auto_start=True)
        except Exception:
            return False
        return status.status == "healthy"

    def _discard_failed_children(self, component: str) -> None:
        survivors: list[ManagedChildProcess] = []
        for child in self.started_children:
            if (
                child.component == component
                and child.started_by_framework
                and child.process.poll() is not None
            ):
                stdout = getattr(child.process, "stdout", None)
                if stdout is not None:
                    try:
                        stdout.close()
                    except Exception:
                        pass
                if child.log_thread is not None and child.log_thread.is_alive():
                    child.log_thread.join(timeout=2)
                if child.log_handle is not None:
                    child.log_handle.close()
                continue
            survivors.append(child)
        self.started_children = survivors

    def _check_url(self, url: str) -> bool:
        if self.readiness_checker is not None:
            return self.readiness_checker(url)
        try:
            with urlopen(url, timeout=0.5) as response:
                return 200 <= response.getcode() < 300
        except (OSError, URLError, TimeoutError):
            return False

    def _start_child(
        self,
        component: str,
        command: list[str],
        *,
        terminate_on_shutdown: bool = True,
        cwd: Path = PROJECT_ROOT,
    ) -> ManagedChildProcess:
        if not command or any(not isinstance(part, str) or not part for part in command):
            raise ValueError("local_runtime_command_invalid")
        RUNTIME_TMP_DIR.mkdir(parents=True, exist_ok=True)
        log_path = RUNTIME_TMP_DIR / f"{component}.log"
        env = {**os.environ, **runtime_environment()}
        process = self.process_starter(
            command,
            cwd=str(cwd),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=False,
        )
        log_thread = None
        stdout = getattr(process, "stdout", None)
        if stdout is not None:
            log_thread = threading.Thread(
                target=_drain_process_output,
                args=(
                    stdout,
                    log_path,
                    settings.local_runtime_log_max_bytes,
                    settings.local_runtime_log_backup_count,
                ),
                name=f"mcp-log-{component}",
                daemon=True,
            )
            log_thread.start()
        child = ManagedChildProcess(
            component=component,
            process=process,
            log_thread=log_thread,
            terminate_on_shutdown=terminate_on_shutdown,
        )
        self.started_children.append(child)
        return child

    def _wait_until(self, predicate: Callable[[], bool]) -> bool:
        deadline = time.monotonic() + settings.local_runtime_start_timeout_seconds
        while time.monotonic() < deadline:
            if predicate():
                return True
            self.sleeper(0.5)
        return predicate()

    def _python(self) -> Path:
        return self.python_executable or Path(sys.executable)

    def _is_owned_component(self, component: str) -> bool:
        return any(
            child.component == component
            and child.started_by_framework
            and child.process.poll() is None
            for child in self.started_children
        )


def _drain_process_output(
    stream: BinaryIO,
    log_path: Path,
    max_bytes: int,
    backup_count: int,
) -> None:
    max_bytes = max(1, int(max_bytes))
    backup_count = max(1, int(backup_count))
    handle = None
    current_size = 0
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        current_size = log_path.stat().st_size if log_path.exists() else 0
        handle = log_path.open("ab")
        while True:
            reader = getattr(stream, "read1", None)
            chunk = reader(8192) if callable(reader) else stream.read(8192)
            if not chunk:
                break
            if not isinstance(chunk, (bytes, bytearray)):
                chunk = str(chunk).encode("utf-8", errors="replace")
            data = bytes(chunk)
            if len(data) > max_bytes:
                data = data[-max_bytes:]
            if current_size + len(data) > max_bytes:
                handle.close()
                handle = None
                _rotate_process_log(log_path, backup_count)
                handle = log_path.open("ab")
                current_size = 0
            handle.write(data)
            handle.flush()
            current_size += len(data)
    except Exception:
        return
    finally:
        if handle is not None:
            try:
                handle.close()
            except Exception:
                pass
        try:
            stream.close()
        except Exception:
            pass


def _rotate_process_log(log_path: Path, backup_count: int) -> None:
    for index in range(backup_count, 0, -1):
        target = log_path.with_name(f"{log_path.name}.{index}")
        source = (
            log_path
            if index == 1
            else log_path.with_name(f"{log_path.name}.{index - 1}")
        )
        if target.exists():
            target.unlink()
        if source.exists():
            source.replace(target)


def _fetch_json(url: str) -> Any:
    with urlopen(url, timeout=1.0) as response:
        if not 200 <= response.getcode() < 300:
            raise OSError("provenance_probe_http_error")
        return json.loads(response.read(2_000_000))


def _provenance_comparison(key: str, label: str, expected: Any, observed: Any, *,
                           reachable: bool, dirty: bool) -> dict[str, Any]:
    if not reachable:
        status = "unreachable"
    elif not expected or not observed:
        status = "unknown"
    elif expected == observed:
        status = "match"
    else:
        status = "mismatch"
    return {"key": key, "label": label, "status": status, "expected": expected,
            "observed": observed, "uncommitted_changes_at_start": dirty}


def backend_base_url() -> str:
    return f"http://{settings.backend_host}:{settings.backend_port}"


def gateway_base_url() -> str:
    return f"http://{settings.mcp_gateway_host}:{settings.mcp_gateway_port}"


def mcp_lab_base_url() -> str:
    return f"http://127.0.0.1:{settings.mcp_lab_port}"


def opa_command() -> list[str] | None:
    if not OPA_EXE.exists():
        return None
    return [
        str(OPA_EXE),
        "run",
        "--server",
        "--addr",
        _opa_addr(),
        str(PROJECT_ROOT / "policies" / "opa"),
    ]


def backend_command(python_executable: Path) -> list[str]:
    return [
        str(python_executable),
        "-m",
        "uvicorn",
        "app.main:app",
        "--app-dir",
        "backend",
        "--host",
        settings.backend_host,
        "--port",
        str(settings.backend_port),
    ]


def gateway_command(python_executable: Path) -> list[str]:
    return [
        str(python_executable),
        "-m",
        "uvicorn",
        "proxy.gateway_app:app",
        "--host",
        settings.mcp_gateway_host,
        "--port",
        str(settings.mcp_gateway_port),
    ]


def mcp_lab_command(python_executable: Path) -> list[str]:
    return [
        str(python_executable),
        "-m",
        "uvicorn",
        "server:app",
        "--app-dir",
        str(PROJECT_ROOT / "mcp-lab" / "http_server"),
        "--host",
        "127.0.0.1",
        "--port",
        str(settings.mcp_lab_port),
    ]


def local_identity_provider_command(python_executable: Path) -> list[str]:
    return [
        str(python_executable),
        str(PROJECT_ROOT / "scripts" / "local_identity_provider.py"),
        "serve",
    ]


def managed_postgres_command() -> list[str] | None:
    raw = settings.local_runtime_managed_postgres_command_json.strip()
    if not raw:
        return None
    try:
        command = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("managed_postgres_command_invalid") from exc
    if (
        not isinstance(command, list)
        or not command
        or any(not isinstance(part, str) or not part for part in command)
    ):
        raise ValueError("managed_postgres_command_invalid")
    return command


def _opa_addr() -> str:
    parsed = urlsplit(settings.opa_base_url)
    if parsed.hostname is None:
        return "127.0.0.1:8181"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return f"{parsed.hostname}:{port}"


def _http_status(
    component: str,
    endpoint: str,
    checker: Callable[[str], bool],
    *,
    managed_by_framework: bool = False,
) -> LocalRuntimeComponentStatus:
    if checker(endpoint):
        return LocalRuntimeComponentStatus(
            component=component,
            status="healthy",
            endpoint=endpoint.rsplit("/", 1)[0] if endpoint.endswith("/health") else endpoint,
            managed_by_framework=managed_by_framework,
        )
    return LocalRuntimeComponentStatus(
        component=component,
        status="unavailable",
        endpoint=endpoint.rsplit("/", 1)[0] if endpoint.endswith("/health") else endpoint,
        managed_by_framework=managed_by_framework,
    )
