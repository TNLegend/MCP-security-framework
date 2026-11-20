"""Opt-in pinned Prowler installer in a separate virtual environment.

The framework does not implicitly install external packages at startup.
Examples:
  python scripts/provision_prowler.py --status
  python scripts/provision_prowler.py --install
"""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.core.runtime_paths import (  # noqa: E402
    PROWLER_DIR, PROWLER_EXE, PROWLER_PYTHON,
    PROWLER_VENV_DIR, PROWLER_VERSION,
)


def probe() -> bool:
    if not PROWLER_EXE.is_file() or not PROWLER_PYTHON.is_file():
        return False
    try:
        run = subprocess.run(
            [str(PROWLER_PYTHON), "-c",
             "import importlib.metadata;print(importlib.metadata.version('prowler'))"],
            cwd=PROWLER_DIR, capture_output=True, stdin=subprocess.DEVNULL,
            timeout=18, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    if run.returncode or run.stdout.decode("utf-8", "replace").strip() != PROWLER_VERSION:
        return False
    try:
        cli = subprocess.run(
            [str(PROWLER_EXE), "--version"], cwd=PROWLER_DIR,
            capture_output=True, stdin=subprocess.DEVNULL, timeout=30, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return cli.returncode == 0 and PROWLER_VERSION in cli.stdout.decode("utf-8", "replace")



# Vendor source-only package required by pinned Prowler 5.51.0.
# Permit a single pinned, hash-checked source build; the main Prowler install
# continues to require wheels for every other transitive dependency.
_SOURCE_SHA256 = "5eb7fa450dc7350d5c71577974b9d7f489479e5c5ec7efc1c5376385e8c1c0a5"


def _bootstrap_wheel() -> Path | None:
    cache = PROWLER_DIR / "wheels"
    cache.mkdir(parents=True, exist_ok=True)
    tarball = cache / "alibabacloud_gateway_oss_util-0.0.3.tar.gz"
    wheel = cache / "alibabacloud_gateway_oss_util-0.0.3-py3-none-any.whl"
    if not tarball.exists():
        child = subprocess.run([
            str(PROWLER_PYTHON), "-m", "pip", "download", "--no-deps",
            "--no-binary=alibabacloud-gateway-oss-util",
            "--disable-pip-version-check", "--no-input",
            "--index-url", "https://pypi.org/simple", "--dest", str(cache),
            "alibabacloud-gateway-oss-util==0.0.3",
        ], cwd=PROWLER_DIR, stdin=subprocess.DEVNULL,
           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=100)
        if child.returncode != 0:
            print("PROWLER_PINNED_SOURCE_DOWNLOAD_FAILED")
            return None
    if hashlib.sha256(tarball.read_bytes()).hexdigest() != _SOURCE_SHA256:
        print("PROWLER_PINNED_SOURCE_HASH_MISMATCH")
        return None
    if not wheel.exists():
        build = subprocess.run([
            str(PROWLER_PYTHON), "-m", "pip", "wheel", "--no-deps",
            "--disable-pip-version-check", "--no-input",
            "--index-url", "https://pypi.org/simple",
            "--wheel-dir", str(cache), str(tarball),
        ], cwd=PROWLER_DIR, stdin=subprocess.DEVNULL,
           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=180)
        if build.returncode != 0 or not wheel.exists():
            print("PROWLER_PINNED_SOURCE_WHEEL_FAILED")
            return None
    return cache

def main() -> int:
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--status", action="store_true")
    group.add_argument("--install", action="store_true")
    args = parser.parse_args()
    if args.status:
        print(f"Prowler {PROWLER_VERSION}: {'READY' if probe() else 'NOT_INSTALLED'}")
        return 0
    if probe():
        print(f"Prowler {PROWLER_VERSION}: already installed")
        return 0
    PROWLER_DIR.mkdir(parents=True, exist_ok=True)
    if not PROWLER_PYTHON.is_file():
        try:
            venv = subprocess.run(
                [sys.executable, "-m", "venv", str(PROWLER_VENV_DIR)],
                cwd=ROOT, timeout=180, check=False,
            )
        except subprocess.TimeoutExpired:
            print("PROWLER_VENV_TIMEOUT")
            return 2
        if venv.returncode:
            print("PROWLER_VENV_FAILED")
            return 1
    # Resolve the large multi-cloud dependency tree with uv. Some official
    # Prowler dependencies exist only as source distributions; wheel-only pip
    # cannot install this release on Windows. The pinned bootstrap tarball is
    # hash-verified before it is built into a wheel inside this isolated venv.
    wheel_cache = _bootstrap_wheel()
    if wheel_cache is None:
        return 1
    uv_exe = PROWLER_VENV_DIR / ("Scripts/uv.exe" if os.name == "nt" else "bin/uv")
    if not uv_exe.is_file():
        try:
            bootstrap = subprocess.run(
                [str(PROWLER_PYTHON), "-m", "pip", "install",
                 "--only-binary=:all:", "--disable-pip-version-check",
                 "--no-input", "--index-url", "https://pypi.org/simple",
                 "uv==0.9.18"],
                cwd=PROWLER_DIR, stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=180, check=False,
            )
        except subprocess.TimeoutExpired:
            print("PROWLER_UV_BOOTSTRAP_TIMEOUT")
            return 2
        if bootstrap.returncode:
            print("PROWLER_UV_BOOTSTRAP_FAILED")
            return 1
    try:
        install = subprocess.run(
            [str(uv_exe), "pip", "install", "--python", str(PROWLER_PYTHON),
             "--index-url", "https://pypi.org/simple",
             "--find-links", str(wheel_cache),
             f"prowler=={PROWLER_VERSION}"],
            cwd=PROWLER_DIR, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=900, check=False,
        )
    except subprocess.TimeoutExpired:
        print("PROWLER_INSTALL_TIMEOUT")
        return 2
    if install.returncode:
        print("PROWLER_INSTALL_FAILED")
        return 1
    integrity = subprocess.run(
        [str(PROWLER_PYTHON), "-m", "pip", "check"],
        cwd=PROWLER_DIR, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, timeout=30, check=False,
    )
    if integrity.returncode or not probe():
        print("PROWLER_POSTINSTALL_VERIFICATION_FAILED")
        return 1
    print(f"PROWLER_READY_{PROWLER_VERSION}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
