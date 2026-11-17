"""Offline, SHA-pinned M3 Prompt Guard 2 V3 *research SHADOW* provisioner.

This only copies already-qualified local files. It never downloads remote code,
touches signed M4/M6 models, modifies policy, or grants production authority.
Use the existing setup_local_environment.py with M3_PG2_V3_SOURCE_DIR, or call
this script explicitly with --source for local/offline installation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
from app.core.runtime_paths import RUNTIME_MODELS_DIR, RUNTIME_TMP_DIR, configure_runtime_environment  # noqa: E402

TARGET = RUNTIME_MODELS_DIR / "m3_prompt_guard2_v3"
MANIFEST_NAME = "M3_PG2_V3_RESEARCH_MANIFEST.json"
EXPECTED = {
    "model.safetensors": (
        "5751dd3a08fad1178d835941a8ad98e019aadcdb6dcfd54a616d9908b0204bf8", 1115268200,
    ),
    "config.json": (
        "cd54ac39a1f2c3c5146bd5295b34038f8b4d9069e2f844450da014a523bb7653", 871,
    ),
    "tokenizer.json": (
        "3e7e96867c2acdd575f0862c74822e05d1d15b93d9d9a4a2144b1ce83ae3339f", 16351353,
    ),
    "tokenizer_config.json": (
        "fa09cf22b9d723377f95706967f789ca1a8267e1412385705e1ed51ce0559189", 19674,
    ),
    "special_tokens_map.json": (
        "9463f61e1b109a8eb4688b829260d7c6b1e6dff04c98ff7269bb89e2b92369b9", 286,
    ),
}
SCOPE = "M3_ENGLISH_TOOL_DESCRIPTION_RESEARCH_SHADOW_NO_POLICY_AUTHORITY"


def _regular_file(path: Path) -> bool:
    return path.is_file() and not path.is_symlink() and not getattr(path, "is_junction", lambda: False)()


def digest(path: Path) -> str:
    sha = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(4 * 1024 * 1024), b""):
            sha.update(chunk)
    return sha.hexdigest()


def verify_files(folder: Path) -> None:
    if folder.is_symlink() or getattr(folder, "is_junction", lambda: False)():
        raise RuntimeError("M3_PG2_LINKED_BUNDLE_REFUSED")
    if not folder.is_dir():
        raise RuntimeError("M3_PG2_BUNDLE_MISSING")
    found = set()
    for path in folder.iterdir():
        if path.is_symlink() or getattr(path, "is_junction", lambda: False)():
            raise RuntimeError("M3_PG2_LINKED_CONTENT_REFUSED")
        if not _regular_file(path):
            raise RuntimeError("M3_PG2_NONREGULAR_BUNDLE_CONTENT")
        found.add(path.name)
    if found != set(EXPECTED) and found != set(EXPECTED) | {MANIFEST_NAME}:
        raise RuntimeError("M3_PG2_BUNDLE_FILE_INVENTORY_MISMATCH")
    for name, (expected, size) in EXPECTED.items():
        path = folder / name
        if not _regular_file(path) or path.stat().st_size != size or digest(path) != expected:
            raise RuntimeError("M3_PG2_FROZEN_FILE_INTEGRITY_MISMATCH:" + name)


def verify_install(folder: Path = TARGET) -> dict[str, object]:
    verify_files(folder)
    manifest = folder / MANIFEST_NAME
    if not _regular_file(manifest):
        raise RuntimeError("M3_PG2_MANIFEST_MISSING")
    record = json.loads(manifest.read_text(encoding="utf8"))
    if (record.get("schema") != "m3-pg2-v3-research-local-install-v1"
            or record.get("scope") != SCOPE
            or record.get("production_approved") is not False
            or record.get("signed") is not False
            or record.get("files") != {
                name: {"sha256": sha, "bytes": size}
                for name, (sha, size) in EXPECTED.items()
            }):
        raise RuntimeError("M3_PG2_MANIFEST_CONTENT_INVALID")
    return {
        "status": "VERIFIED_M3_PG2_V3_RESEARCH_SHADOW_ONLY",
        "weights_sha256": EXPECTED["model.safetensors"][0],
        "model_directory": str(folder),
        "production_approved": False,
    }


def install(source: Path, target: Path = TARGET) -> dict[str, object]:
    configure_runtime_environment()
    if target.exists():
        # Never replace a previously installed model silently.
        return verify_install(target)
    verify_files(source)
    RUNTIME_TMP_DIR.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="m3-pg2-v3-", dir=RUNTIME_TMP_DIR) as staging:
        tmp = Path(staging) / "m3_prompt_guard2_v3"
        tmp.mkdir()
        for name in EXPECTED:
            shutil.copyfile(source / name, tmp / name)
        verify_files(tmp)
        manifest = {
            "schema": "m3-pg2-v3-research-local-install-v1",
            "scope": SCOPE,
            "checkpoint_name": "PROMPT_GUARD_2_86M_V3",
            "production_approved": False,
            "signed": False,
            "files": {
                name: {"sha256": sha, "bytes": size}
                for name, (sha, size) in EXPECTED.items()
            },
        }
        (tmp / MANIFEST_NAME).write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf8",
        )
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            raise RuntimeError("M3_PG2_MODEL_TARGET_CREATED_CONCURRENTLY")
        tmp.rename(target)
    return verify_install(target)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=None)
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()
    if args.verify_only:
        result = verify_install()
    else:
        source = args.source or (
            Path(os.environ["M3_PG2_V3_SOURCE_DIR"])
            if os.environ.get("M3_PG2_V3_SOURCE_DIR") else None
        )
        if source is None:
            parser.error("--source or M3_PG2_V3_SOURCE_DIR is required")
        result = install(source)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
