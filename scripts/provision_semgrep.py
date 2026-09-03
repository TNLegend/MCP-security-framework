from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import venv

REPO_ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = REPO_ROOT / "backend"
for import_path in (REPO_ROOT, BACKEND_DIR):
    if str(import_path) not in sys.path:
        sys.path.insert(0, str(import_path))

from app.core.runtime_paths import (  # noqa: E402
    SEMGREP_DIR,
    SEMGREP_EXE,
    SEMGREP_VERSION,
    SEMGREP_VENV_DIR,
    configure_runtime_environment,
    runtime_environment,
)


def semgrep_python() -> Path:
    if os.name == "nt":
        return SEMGREP_VENV_DIR / "Scripts" / "python.exe"
    return SEMGREP_VENV_DIR / "bin" / "python"


def _run(
    command: list[str],
    *,
    env: dict[str, str],
    timeout: int = 600,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=REPO_ROOT,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
        check=False,
        shell=False,
    )


def installed_semgrep_version(*, env: dict[str, str]) -> str | None:
    if not SEMGREP_EXE.is_file():
        return None
    try:
        result = _run([str(SEMGREP_EXE), "--version"], env=env, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    version = result.stdout.strip().splitlines()
    return version[-1].strip() if version else None


def provision_semgrep() -> dict[str, object]:
    configure_runtime_environment()
    env = {**os.environ, **runtime_environment()}
    env.update(
        {
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PIP_NO_INPUT": "1",
            "SEMGREP_SEND_METRICS": "off",
            "SEMGREP_ENABLE_VERSION_CHECK": "0",
        }
    )
    SEMGREP_DIR.mkdir(parents=True, exist_ok=True)

    tool_python = semgrep_python()
    if not tool_python.is_file():
        venv.EnvBuilder(with_pip=True, clear=False).create(SEMGREP_VENV_DIR)

    status = "present"
    current = installed_semgrep_version(env=env)
    if current != SEMGREP_VERSION:
        install = _run(
            [
                str(tool_python),
                "-m",
                "pip",
                "install",
                "--disable-pip-version-check",
                "--no-input",
                f"semgrep=={SEMGREP_VERSION}",
            ],
            env=env,
            timeout=1200,
        )
        if install.returncode != 0:
            raise RuntimeError("semgrep_install_failed")
        status = "installed"

    current = installed_semgrep_version(env=env)
    if current != SEMGREP_VERSION:
        raise RuntimeError("semgrep_version_mismatch")

    healthy = _run(
        [str(tool_python), "-m", "pip", "check"],
        env=env,
        timeout=60,
    )
    if healthy.returncode != 0:
        raise RuntimeError("semgrep_dependency_check_failed")

    freeze = _run(
        [str(tool_python), "-m", "pip", "freeze", "--all"],
        env=env,
        timeout=60,
    )
    if freeze.returncode == 0:
        (SEMGREP_DIR / "installed-freeze.txt").write_text(
            freeze.stdout,
            encoding="utf-8",
        )

    state = {
        "version": current,
        "executable": str(SEMGREP_EXE),
        "status": status,
    }
    (SEMGREP_DIR / "state.json").write_text(
        json.dumps(state, indent=2),
        encoding="utf-8",
    )
    return state


def main() -> int:
    state = provision_semgrep()
    print(json.dumps({"semgrep": state}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
