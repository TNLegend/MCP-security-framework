from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = REPO_ROOT / "backend"
VENV_DIR = BACKEND_DIR / ".venv"
PYTHON_EXE = VENV_DIR / "Scripts" / "python.exe"

sys.path.insert(0, str(BACKEND_DIR))

from app.core.runtime_paths import (  # noqa: E402
    OPA_EXE,
    configure_runtime_environment,
    runtime_environment,
)


def _run(command: list[str], *, env: dict[str, str]) -> None:
    subprocess.run(command, cwd=REPO_ROOT, env=env, check=True)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Prepare the project-local runtime, Python venv, models, and OPA."
    )
    parser.add_argument("--skip-venv", action="store_true")
    parser.add_argument("--skip-python-deps", action="store_true")
    parser.add_argument("--skip-models", action="store_true")
    parser.add_argument("--skip-opa", action="store_true")
    parser.add_argument("--skip-service-identities", action="store_true")
    args = parser.parse_args()

    configured = configure_runtime_environment()
    env = {**dict(os.environ), **runtime_environment()}

    if not args.skip_venv and not PYTHON_EXE.exists():
        _run([sys.executable, "-m", "venv", str(VENV_DIR)], env=env)

    python = str(PYTHON_EXE if PYTHON_EXE.exists() else Path(sys.executable))

    if not args.skip_python_deps:
        _run(
            [
                python,
                "-m",
                "pip",
                "install",
                "--cache-dir",
                configured["PIP_CACHE_DIR"],
                "-r",
                str(BACKEND_DIR / "requirements.txt"),
            ],
            env=env,
        )

    if not args.skip_service_identities:
        _run([python, str(REPO_ROOT / "scripts" / "provision_service_identities.py")], env=env)

    if not args.skip_models:
        _run([python, str(REPO_ROOT / "scripts" / "download_tool_analyzer_models.py")], env=env)

    if not args.skip_opa:
        _run([python, str(REPO_ROOT / "scripts" / "download_opa.py")], env=env)

    print(
        json.dumps(
            {
                "runtime_env": configured,
                "python": python,
                "opa": str(OPA_EXE),
                "env_file_modified": False,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
