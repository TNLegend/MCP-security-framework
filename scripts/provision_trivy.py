from __future__ import annotations

from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import shutil
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

from app.core.config import settings  # noqa: E402
from app.core.runtime_paths import (  # noqa: E402
    RUNTIME_TMP_DIR,
    TRIVY_CACHE_DIR,
    TRIVY_DIR,
    TRIVY_DOCKER_CONFIG_DIR,
    TRIVY_EXE,
    TRIVY_VERSION,
)

_RELEASE_BASE = f"https://github.com/aquasecurity/trivy/releases/download/v{TRIVY_VERSION}"
_ASSETS = {
    ("win32", "x86_64"): (
        f"trivy_{TRIVY_VERSION}_windows-64bit.zip",
        "94c40e0696e4b907a74b7b2e1438d5d72ebaca83115817407f568a002d520842",
    ),
    ("linux", "x86_64"): (
        f"trivy_{TRIVY_VERSION}_Linux-64bit.tar.gz",
        "2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a",
    ),
    ("linux", "arm64"): (
        f"trivy_{TRIVY_VERSION}_Linux-ARM64.tar.gz",
        "b94ce1976bbf3c15b514b605ee88be7c6d94a29be2302847ff01cb794d47aad5",
    ),
    ("darwin", "x86_64"): (
        f"trivy_{TRIVY_VERSION}_macOS-64bit.tar.gz",
        "472816f6888dda689d075c30254d4210b4d1035acf365aa72332f584c2f60485",
    ),
    ("darwin", "arm64"): (
        f"trivy_{TRIVY_VERSION}_macOS-ARM64.tar.gz",
        "1caada5e0e2091909357c7525d3aa76f4b660b13821bc143b190c7483e31cc11",
    ),
}
_MAX_ARCHIVE_BYTES = 250 * 1024 * 1024
_USER_AGENT = "MCP-Security-Framework-Build-Security"
_DB_REPOSITORY = "ghcr.io/aquasecurity/trivy-db:2"


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
        raise RuntimeError(f"unsupported_trivy_platform:{key[0]}:{key[1]}")
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
                raise RuntimeError("trivy_archive_too_large")
            digest.update(block)
            handle.write(block)
    return digest.hexdigest()


def download_release_archive(destination: Path, *, asset_name: str) -> str:
    request = Request(
        f"{_RELEASE_BASE}/{asset_name}",
        headers={"User-Agent": _USER_AGENT},
    )
    try:
        with urlopen(request, timeout=90) as response:
            return _copy_bounded(response, destination)
    except Exception as exc:
        destination.unlink(missing_ok=True)
        raise RuntimeError("trivy_download_failed") from exc


def _extract_binary(archive: Path, destination: Path) -> None:
    target_name = "trivy.exe" if os.name == "nt" else "trivy"
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
                    raise RuntimeError("trivy_archive_binary_missing")
                if Path(members[0].filename).parts != (target_name,):
                    raise RuntimeError("trivy_archive_path_invalid")
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
                    raise RuntimeError("trivy_archive_binary_missing")
                if Path(members[0].name).parts != (target_name,):
                    raise RuntimeError("trivy_archive_path_invalid")
                source = bundle.extractfile(members[0])
                if source is None:
                    raise RuntimeError("trivy_archive_binary_missing")
                with source:
                    _copy_bounded(source, temporary)

        temporary.replace(destination)
        if os.name != "nt":
            destination.chmod(destination.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP)
    finally:
        temporary.unlink(missing_ok=True)


def _trusted_environment() -> dict[str, str]:
    TRIVY_DOCKER_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    config = TRIVY_DOCKER_CONFIG_DIR / "config.json"
    if not config.is_file():
        config.write_text("{}\n", encoding="utf-8")
    env = dict(os.environ)
    for name in (
        "TRIVY_USERNAME",
        "TRIVY_PASSWORD",
        "TRIVY_TOKEN",
        "TRIVY_CONFIG",
        "TRIVY_CACHE_DIR",
        "TRIVY_DB_REPOSITORY",
    ):
        env.pop(name, None)
    env["DOCKER_CONFIG"] = str(TRIVY_DOCKER_CONFIG_DIR)
    return env


def installed_version() -> str | None:
    if not TRIVY_EXE.is_file():
        return None
    try:
        completed = subprocess.run(
            [str(TRIVY_EXE), "--version"],
            cwd=TRIVY_DIR,
            env=_trusted_environment(),
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
    for line in (completed.stdout or b"").decode("utf-8", errors="replace").splitlines():
        if line.startswith("Version:"):
            return line.split(":", 1)[1].strip()
    return None


def _metadata_datetime(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def vulnerability_db_is_fresh(
    state: dict[str, object],
    *,
    now: datetime | None = None,
) -> bool:
    metadata = state.get("metadata")
    if not isinstance(metadata, dict):
        return False
    updated_at = _metadata_datetime(metadata.get("UpdatedAt"))
    if updated_at is None:
        updated_at = _metadata_datetime(metadata.get("DownloadedAt"))
    if updated_at is None:
        return False
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    else:
        current = current.astimezone(timezone.utc)
    age = current - updated_at
    if age < timedelta(minutes=-5):
        return False
    return age <= timedelta(hours=settings.build_scan_trivy_db_max_age_hours)


def vulnerability_db_state() -> dict[str, object] | None:
    database = TRIVY_CACHE_DIR / "db" / "trivy.db"
    metadata = TRIVY_CACHE_DIR / "db" / "metadata.json"
    if not database.is_file() or database.stat().st_size < 1_000_000 or not metadata.is_file():
        return None
    try:
        parsed = json.loads(metadata.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(parsed, dict):
        return None
    return {
        "database_bytes": database.stat().st_size,
        "metadata": {
            key: parsed.get(key)
            for key in ("Version", "Type", "UpdatedAt", "NextUpdate", "DownloadedAt")
            if key in parsed
        },
    }


def provision_vulnerability_db() -> dict[str, object]:
    TRIVY_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    existing = vulnerability_db_state()
    if existing is not None and vulnerability_db_is_fresh(existing):
        return {"status": "present", **existing}

    try:
        completed = subprocess.run(
            [
                str(TRIVY_EXE),
                "filesystem",
                "--download-db-only",
                "--cache-dir",
                str(TRIVY_CACHE_DIR),
                "--db-repository",
                _DB_REPOSITORY,
                "--no-progress",
                "--quiet",
            ],
            cwd=TRIVY_DIR,
            env=_trusted_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            timeout=1800,
            check=False,
            shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("trivy_db_download_timed_out") from exc
    except OSError as exc:
        raise RuntimeError("trivy_db_download_failed") from exc
    if completed.returncode != 0:
        raise RuntimeError("trivy_db_download_failed")

    state = vulnerability_db_state()
    if state is None or not vulnerability_db_is_fresh(state):
        raise RuntimeError("trivy_db_invalid_or_stale")
    return {"status": "downloaded", **state}


def provision_trivy() -> dict[str, object]:
    asset_name, expected_sha256 = release_asset()
    TRIVY_DIR.mkdir(parents=True, exist_ok=True)

    current = installed_version()
    binary_status = "present"
    if current != TRIVY_VERSION:
        RUNTIME_TMP_DIR.mkdir(parents=True, exist_ok=True)
        archive = RUNTIME_TMP_DIR / f"{asset_name}.download"
        archive.unlink(missing_ok=True)
        try:
            actual = download_release_archive(archive, asset_name=asset_name)
            if actual.lower() != expected_sha256.lower():
                raise RuntimeError("trivy_checksum_mismatch")
            _extract_binary(archive, TRIVY_EXE)
        finally:
            archive.unlink(missing_ok=True)
        binary_status = "downloaded"

    current = installed_version()
    if current != TRIVY_VERSION:
        raise RuntimeError("trivy_version_mismatch")

    database = provision_vulnerability_db()
    state = {
        "version": current,
        "executable": str(TRIVY_EXE),
        "binary_status": binary_status,
        "asset": asset_name,
        "sha256": expected_sha256,
        "vulnerability_db": database,
    }
    (TRIVY_DIR / "state.json").write_text(
        json.dumps(state, indent=2),
        encoding="utf-8",
    )
    return state


def main() -> int:
    print(json.dumps({"trivy": provision_trivy()}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
