from __future__ import annotations

import json
from pathlib import Path
import signal
import sys
import time

REPO_ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = REPO_ROOT / "backend"
VENV_PYTHON = BACKEND_DIR / ".venv" / "Scripts" / "python.exe"

sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(BACKEND_DIR))

from app.core.runtime_paths import configure_runtime_environment  # noqa: E402
from common.project_environment import load_project_environment  # noqa: E402

load_project_environment()

from app.core.config import settings  # noqa: E402
from app.services.local_runtime_manager import LocalRuntimeManager  # noqa: E402


def main() -> int:
    configure_runtime_environment()
    python = VENV_PYTHON if VENV_PYTHON.exists() else Path(sys.executable)
    manager = LocalRuntimeManager(python_executable=python)
    interrupted = False

    def _signal_handler(signum, frame):  # noqa: ANN001
        nonlocal interrupted
        interrupted = True
        raise KeyboardInterrupt

    previous_sigint = signal.signal(signal.SIGINT, _signal_handler)
    try:
        database = manager.ensure_database(auto_start=True)
        if database.status != "healthy":
            print(json.dumps({"ready": False, "database": database.as_dict()}, indent=2))
            return 1

        opa = manager.ensure_opa(auto_start=True)
        if opa.status != "healthy":
            print(json.dumps({"ready": False, "opa": opa.as_dict()}, indent=2))
            return 1

        identity_provider = manager.ensure_identity_provider(
            auto_start=settings.local_runtime_autostart_identity_provider
        )
        if identity_provider.status != "healthy":
            print(
                json.dumps(
                    {"ready": False, "identity_provider": identity_provider.as_dict()},
                    indent=2,
                )
            )
            return 1

        backend = manager.start_backend()
        if backend.status != "healthy":
            print(json.dumps({"ready": False, "backend": backend.as_dict()}, indent=2))
            return 1

        gateway = manager.ensure_gateway(auto_start=True)
        status = manager.status()
        print(json.dumps(status.as_dict(), indent=2))
        if gateway.status != "healthy" or not status.ready:
            return 1

        print("Framework ready. Press Ctrl+C to stop processes started by this launcher.")
        while not interrupted:
            failure = manager.required_child_failure()
            if failure is not None:
                print(
                    json.dumps(
                        {
                            "ready": False,
                            "error": "framework_owned_child_exited",
                            **failure,
                        },
                        indent=2,
                    ),
                    file=sys.stderr,
                )
                return 1
            time.sleep(1)
    except KeyboardInterrupt:
        return 0
    finally:
        signal.signal(signal.SIGINT, previous_sigint)
        manager.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
