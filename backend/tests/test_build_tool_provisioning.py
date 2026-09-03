from __future__ import annotations

from datetime import datetime, timedelta, timezone
from hashlib import sha256
import io
from pathlib import Path
import zipfile

import pytest

from app.core.runtime_paths import GITLEAKS_VERSION, TRIVY_VERSION
from scripts import provision_gitleaks, provision_trivy


def test_gitleaks_release_asset_for_current_platform_is_pinned() -> None:
    name, checksum = provision_gitleaks.release_asset()
    assert name.startswith(f"gitleaks_{GITLEAKS_VERSION}_")
    assert name.endswith((".zip", ".tar.gz"))
    assert len(checksum) == 64
    int(checksum, 16)


def test_gitleaks_windows_x64_release_checksum_is_exact() -> None:
    assert provision_gitleaks._ASSETS[("win32", "x86_64")] == (
        f"gitleaks_{GITLEAKS_VERSION}_windows_x64.zip",
        "d29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e",
    )


def test_copy_bounded_returns_sha256_and_rejects_oversized_download(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data = b"safe-binary-content"
    destination = tmp_path / "asset.bin"
    digest = provision_gitleaks._copy_bounded(io.BytesIO(data), destination)
    assert digest == sha256(data).hexdigest()
    assert destination.read_bytes() == data

    monkeypatch.setattr(provision_gitleaks, "_MAX_ARCHIVE_BYTES", 4)
    with pytest.raises(RuntimeError, match="gitleaks_archive_too_large"):
        provision_gitleaks._copy_bounded(
            io.BytesIO(b"12345"),
            tmp_path / "too-large.bin",
        )


def test_gitleaks_zip_extraction_accepts_only_root_binary(tmp_path: Path) -> None:
    archive = tmp_path / "valid.zip"
    target = tmp_path / "gitleaks.exe"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("gitleaks.exe", b"binary")
        bundle.writestr("README.md", b"ignored")

    provision_gitleaks._extract_gitleaks_binary(archive, target)
    assert target.read_bytes() == b"binary"


def test_gitleaks_zip_extraction_rejects_nested_binary(tmp_path: Path) -> None:
    archive = tmp_path / "nested.zip"
    target = tmp_path / "gitleaks.exe"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("../gitleaks.exe", b"binary")

    with pytest.raises(RuntimeError, match="gitleaks_archive_path_invalid"):
        provision_gitleaks._extract_gitleaks_binary(archive, target)
    assert not target.exists()


def test_gitleaks_provision_is_idempotent_when_exact_version_is_present(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        provision_gitleaks,
        "installed_version",
        lambda: GITLEAKS_VERSION,
    )
    monkeypatch.setattr(
        provision_gitleaks,
        "download_release_archive",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("download called")),
    )
    state = provision_gitleaks.provision_gitleaks()
    assert state["version"] == GITLEAKS_VERSION
    assert state["status"] == "present"


def test_trivy_release_asset_for_current_platform_is_pinned() -> None:
    name, checksum = provision_trivy.release_asset()
    assert name.startswith(f"trivy_{TRIVY_VERSION}_")
    assert name.endswith((".zip", ".tar.gz"))
    assert len(checksum) == 64
    int(checksum, 16)


def test_trivy_windows_x64_release_checksum_is_exact() -> None:
    assert provision_trivy._ASSETS[("win32", "x86_64")] == (
        f"trivy_{TRIVY_VERSION}_windows-64bit.zip",
        "94c40e0696e4b907a74b7b2e1438d5d72ebaca83115817407f568a002d520842",
    )


def test_trivy_database_freshness_honors_configured_max_age() -> None:
    now = datetime(2026, 9, 3, 8, 0, tzinfo=timezone.utc)
    fresh = {
        "metadata": {
            "UpdatedAt": (now - timedelta(hours=71)).isoformat(),
        }
    }
    stale = {
        "metadata": {
            "UpdatedAt": (now - timedelta(hours=73)).isoformat(),
        }
    }

    assert provision_trivy.vulnerability_db_is_fresh(fresh, now=now) is True
    assert provision_trivy.vulnerability_db_is_fresh(stale, now=now) is False


def test_trivy_stale_database_triggers_refresh(monkeypatch: pytest.MonkeyPatch) -> None:
    stale = {
        "database_bytes": 1_234_567,
        "metadata": {"UpdatedAt": "2026-08-01T00:00:00Z"},
    }
    fresh = {
        "database_bytes": 1_234_567,
        "metadata": {"UpdatedAt": datetime.now(timezone.utc).isoformat()},
    }
    states = iter((stale, fresh))
    monkeypatch.setattr(provision_trivy, "vulnerability_db_state", lambda: next(states))

    class Completed:
        returncode = 0

    monkeypatch.setattr(provision_trivy.subprocess, "run", lambda *args, **kwargs: Completed())

    result = provision_trivy.provision_vulnerability_db()

    assert result["status"] == "downloaded"


def test_trivy_provision_is_idempotent_when_binary_and_db_are_present(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(provision_trivy, "installed_version", lambda: TRIVY_VERSION)
    monkeypatch.setattr(
        provision_trivy,
        "provision_vulnerability_db",
        lambda: {
            "status": "present",
            "database_bytes": 1_234_567,
            "metadata": {"Version": 2},
        },
    )
    monkeypatch.setattr(
        provision_trivy,
        "download_release_archive",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("download called")),
    )

    state = provision_trivy.provision_trivy()
    assert state["version"] == TRIVY_VERSION
    assert state["binary_status"] == "present"
    assert state["vulnerability_db"]["status"] == "present"
