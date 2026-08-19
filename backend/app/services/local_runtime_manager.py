from __future__ import annotations

from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from typing import Any, Callable
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

    def as_dict(self) -> dict[str, Any]:
        return {
            "component": self.component,
            "status": self.status,
            "endpoint": self.endpoint,
            "managed_by_framework": self.managed_by_framework,
            "detail": self.detail,
        }


@dataclass
class ManagedChildProcess:
    component: str
    process: subprocess.Popen
    log_handle: Any | None = None
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
                child.process.terminate()
                try:
                    child.process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    child.process.kill()
                    child.process.wait(timeout=5)
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
            }:
                continue
            return_code = child.process.poll()
            if return_code is not None:
                return {
                    "component": child.component,
                    "return_code": return_code,
                }
        return None

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
    ) -> ManagedChildProcess:
        if not command or any(not isinstance(part, str) or not part for part in command):
            raise ValueError("local_runtime_command_invalid")
        RUNTIME_TMP_DIR.mkdir(parents=True, exist_ok=True)
        log_handle = (RUNTIME_TMP_DIR / f"{component}.log").open("ab")
        env = {**os.environ, **runtime_environment()}
        process = self.process_starter(
            command,
            cwd=str(PROJECT_ROOT),
            env=env,
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            shell=False,
        )
        child = ManagedChildProcess(
            component=component,
            process=process,
            log_handle=log_handle,
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


def backend_base_url() -> str:
    return f"http://{settings.backend_host}:{settings.backend_port}"


def gateway_base_url() -> str:
    return f"http://{settings.mcp_gateway_host}:{settings.mcp_gateway_port}"


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
