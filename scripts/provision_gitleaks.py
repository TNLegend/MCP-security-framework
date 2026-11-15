from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import stat
import subprocess
import sys
import tarfile
from typing import BinaryIO
from urllib.request import Request, urlopen
import zipfile

REPO_ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = REPO_ROOT / "backend"
for import_path in (REPO_ROOT, BACKEND_DIR):
    if str(import_path) not in sys.path:
        sys.path.insert(0, str(import_path))

from app.core.runtime_paths import (  # noqa: E402
    GITLEAKS_DIR,
    GITLEAKS_EXE,
    GITLEAKS_VERSION,
    RUNTIME_TMP_DIR,
)

_RELEASE_BASE = f"https://github.com/gitleaks/gitleaks/releases/download/v{GITLEAKS_VERSION}"
_ASSETS = {
    ("win32", "x86_64"): (
        f"gitleaks_{GITLEAKS_VERSION}_windows_x64.zip",
        "d29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e",
    ),
    ("win32", "arm64"): (
        f"gitleaks_{GITLEAKS_VERSION}_windows_arm64.zip",
        "b95f5e4f5c425cedca7ee203d9afd29597e692c4924a12ed42f970537c72cc0f",
    ),
    ("linux", "x86_64"): (
        f"gitleaks_{GITLEAKS_VERSION}_linux_x64.tar.gz",
        "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb",
    ),
    ("linux", "arm64"): (
        f"gitleaks_{GITLEAKS_VERSION}_linux_arm64.tar.gz",
        "e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080",
    ),
    ("darwin", "x86_64"): (
        f"gitleaks_{GITLEAKS_VERSION}_darwin_x64.tar.gz",
        "dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709",
    ),
    ("darwin", "arm64"): (
        f"gitleaks_{GITLEAKS_VERSION}_darwin_arm64.tar.gz",
        "b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5",
    ),
}
_MAX_ARCHIVE_BYTES = 100 * 1024 * 1024
_USER_AGENT = "MCP-Security-Framework-Build-Security"


def normalized_machine() -> str:
    machine = platform.machine().strip().lower()
    if machine in {"amd64", "x86_64"}:
        return "x86_64"
    if machine in {"arm64", "aarch64"}:
        return "arm64"
    return machine


def release_asset() -> tuple[str, str]:
    key = (sys.platform, normalized_machine())
    asset = _ASSETS.get(key)
    if asset is None:
        raise RuntimeError(f"unsupported_gitleaks_platform:{key[0]}:{key[1]}")
    return asset


def _copy_bounded(source: BinaryIO, destination: Path) -> str:
    digest = sha256()
    total = 0
    with destination.open("xb") as handle:
        while True:
            block = source.read(1024 * 1024)
            if not block:
                break
            total += len(block)
            if total > _MAX_ARCHIVE_BYTES:
                raise RuntimeError("gitleaks_archive_too_large")
            digest.update(block)
            handle.write(block)
    return digest.hexdigest()


def download_release_archive(destination: Path, *, asset_name: str) -> str:
    url = f"{_RELEASE_BASE}/{asset_name}"
    request = Request(url, headers={"User-Agent": _USER_AGENT})
    try:
        with urlopen(request, timeout=60) as response:
            return _copy_bounded(response, destination)
    except Exception as exc:
        destination.unlink(missing_ok=True)
        raise RuntimeError("gitleaks_download_failed") from exc


def _extract_gitleaks_binary(archive: Path, destination: Path) -> None:
    target_name = "gitleaks.exe" if os.name == "nt" else "gitleaks"
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    temporary.unlink(missing_ok=True)

    try:
        if zipfile.is_zipfile(archive):
            with zipfile.ZipFile(archive) as bundle:
                members = [
                    info
                    for info in bundle.infolist()
                    if Path(info.filename).name == target_name and not info.is_dir()
                ]
                if len(members) != 1:
                    raise RuntimeError("gitleaks_archive_binary_missing")
                if Path(members[0].filename).parts != (target_name,):
                    raise RuntimeError("gitleaks_archive_path_invalid")
                with bundle.open(members[0], "r") as source:
                    _copy_bounded(source, temporary)
        else:
            with tarfile.open(archive, mode="r:gz") as bundle:
                members = [
                    member
                    for member in bundle.getmembers()
                    if Path(member.name).name == target_name and member.isfile()
                ]
                if len(members) != 1:
                    raise RuntimeError("gitleaks_archive_binary_missing")
                if Path(members[0].name).parts != (target_name,):
                    raise RuntimeError("gitleaks_archive_path_invalid")
                source = bundle.extractfile(members[0])
                if source is None:
                    raise RuntimeError("gitleaks_archive_binary_missing")
                with source:
                    _copy_bounded(source, temporary)

        temporary.replace(destination)
        if os.name != "nt":
            destination.chmod(destination.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP)
    finally:
        temporary.unlink(missing_ok=True)


def installed_version() -> str | None:
    if not GITLEAKS_EXE.is_file():
        return None
    try:
        completed = subprocess.run(
            [str(GITLEAKS_EXE), "version"],
            cwd=GITLEAKS_DIR,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=20,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0 or len(completed.stdout or b"") > 65_536:
        return None
    text = (completed.stdout or b"").decode("utf-8", errors="replace").strip()
    return text.splitlines()[-1].strip() if text else None


def provision_gitleaks() -> dict[str, object]:
    asset_name, expected_sha256 = release_asset()
    GITLEAKS_DIR.mkdir(parents=True, exist_ok=True)

    current = installed_version()
    status = "present"
    if current != GITLEAKS_VERSION:
        RUNTIME_TMP_DIR.mkdir(parents=True, exist_ok=True)
        archive = RUNTIME_TMP_DIR / f"{asset_name}.download"
        archive.unlink(missing_ok=True)
        try:
            actual_sha256 = download_release_archive(archive, asset_name=asset_name)
            if actual_sha256.lower() != expected_sha256.lower():
                raise RuntimeError("gitleaks_checksum_mismatch")
            _extract_gitleaks_binary(archive, GITLEAKS_EXE)
        finally:
            archive.unlink(missing_ok=True)
        status = "downloaded"

    current = installed_version()
    if current != GITLEAKS_VERSION:
        raise RuntimeError("gitleaks_version_mismatch")

    state = {
        "version": current,
        "executable": str(GITLEAKS_EXE),
        "status": status,
        "asset": asset_name,
        "sha256": expected_sha256,
    }
    (GITLEAKS_DIR / "state.json").write_text(
        json.dumps(state, indent=2),
        encoding="utf-8",
    )
    return state


def main() -> int:
    print(json.dumps({"gitleaks": provision_gitleaks()}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
