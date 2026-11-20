"""Opt-in, isolated Checkov provisioning for Deploy Security.

Use: python scripts/provision_checkov.py --status
     python scripts/provision_checkov.py --install

No Checkov packages are installed in the framework backend's virtualenv.
The installer is optional and never called on generic framework startup.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT))
from app.core.runtime_paths import (  # noqa: E402
    CHECKOV_DIR, CHECKOV_EXE, CHECKOV_PYTHON, CHECKOV_VENV_DIR, CHECKOV_VERSION,
)

PYTHON = (CHECKOV_VENV_DIR / ("Scripts/python.exe" if os.name == "nt" else "bin/python"))


def probe() -> bool:
    if not CHECKOV_EXE.is_file() or not CHECKOV_PYTHON.is_file():
        return False
    try:
        completed = subprocess.run(
            [str(CHECKOV_PYTHON), "-c",
             "import importlib.metadata;print(importlib.metadata.version('checkov'))"],
            cwd=CHECKOV_DIR, stdin=subprocess.DEVNULL,
            capture_output=True, timeout=15, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return (completed.returncode == 0 and
            completed.stdout.decode("utf-8", "replace").strip() == CHECKOV_VERSION)


def main() -> int:
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--status", action="store_true")
    group.add_argument("--install", action="store_true")
    args = parser.parse_args()

    if args.status:
        print(f"Checkov {CHECKOV_VERSION}: {'READY' if probe() else 'NOT_INSTALLED'}")
        return 0
    if probe():
        print(f"Checkov {CHECKOV_VERSION}: already installed")
        return 0
    CHECKOV_DIR.mkdir(parents=True, exist_ok=True)
    if not PYTHON.is_file():
        init = subprocess.run([sys.executable, "-m", "venv", str(CHECKOV_VENV_DIR)],
                              cwd=ROOT, check=False, timeout=180)
        if init.returncode:
            print("CHECKOV_VENV_CREATION_FAILED")
            return 1
    # Do not execute install-time source build scripts from third-party sdists.
    # A wheel-only attempt may fail on unsupported host architectures; fail
    # visibly rather than weakening the installation boundary.
    try:
        completed = subprocess.run([
            str(PYTHON), "-m", "pip", "install", "--only-binary=:all:",
            "--disable-pip-version-check", "--no-input",
            "--retries", "1", "--timeout", "15",
            f"checkov=={CHECKOV_VERSION}",
        ], cwd=CHECKOV_DIR, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
           timeout=420, check=False)
    except subprocess.TimeoutExpired:
        print("CHECKOV_INSTALL_TIMEOUT")
        return 2
    if completed.returncode:
        print("CHECKOV_INSTALL_FAILED")
        return 1
    check = subprocess.run([str(PYTHON), "-m", "pip", "check"],
                           cwd=CHECKOV_DIR, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=30, check=False)
    if check.returncode or not probe():
        print("CHECKOV_POSTINSTALL_VERIFICATION_FAILED")
        return 1
    print(f"CHECKOV_READY_{CHECKOV_VERSION}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
