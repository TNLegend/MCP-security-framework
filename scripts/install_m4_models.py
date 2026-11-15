"""Install the two frozen, fine-tuned M4 models from private Hugging Face.

Security: exact allowlist, SHA256+byte sizes, no extra model files or symlinks,
no automatic model approval, no download secrets recorded. E5 is M6 only.
"""
from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = PROJECT_ROOT / "backend"
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.core.runtime_paths import RUNTIME_MODELS_DIR, RUNTIME_TMP_DIR, configure_runtime_environment

MODEL_ROOT = RUNTIME_MODELS_DIR / "m4_semantics"
MANIFEST = "M4_BUNDLE_SHA256_MANIFEST.json"
# Revisions pin the private repositories. SHA256 pins each actual file
# independently, including when the remote refs move.
REPOSITORIES = {
    "GLINER": {
        "repo_id": "tnlegend/mcp-security-m4-gliner-pass10",
        "revision": "f195451a70632a0edbf37cbc446d6ce4b02aa1e9",
        "files": {
            "model.safetensors": ("6621bd9f90b9439d4b0883333c05a002bdae77b75b3e78d15f085830dd777130", 774366564),
            "config.json": ("5dee87c98247b89596b99994e957cf8eaa6f264b6ab1cc058234bae0d96bd312", 4097),
            "encoder_config/config.json": ("9e0dc30d76a04a9dcbe1952637db55b0a3f7c1a0fe8c847c10a87355af3d60b0", 858),
            "tokenizer.json": ("cbc8ae6037812709c9c26f2a160f8dc48b0440bcb79c8141804259ae2d6adac3", 8341713),
            "tokenizer_config.json": ("8b3c1969bb7eb4be436b91fd5231b1136d8c89a210f3505dd5f7dc9126319032", 644),
        },
    },
    "DEBERTA_V2": {
        "repo_id": "tnlegend/mcp-security-m4-deberta-v2",
        "revision": "598eb0e55da3c694eab7b8725fe438d635de49d9",
        "files": {
            "best_model.safetensors": ("331750fe70452dba7461d1dc1bc77cfc38726de59828d06588ae3c5c467c936d", 570007864),
            "config.json": ("b0bb1caf90a50aa67d1085130508dfbf8646ac5a11928305e280b07a36e100ae", 578),
            "LABELS_FOUR_HEADS.json": ("9d27b331dde992b4f20714228b76c46556391af92cb73ca0b0e4aa37667ac6b1", 377),
            "spm.model": ("c679fbf93643d19aab7ee10c0b99e460bdbc02fedf34b92b05af343b4af586fd", 2464616),
            "tokenizer.json": ("e9ddd853a4a31023721c993458663f2019e3154a05dacf0d2b3c217e53d9bdc8", 8339876),
            "tokenizer_config.json": ("28efde3273ceba3743712cfafd411e0a969507147b0cc8240a7089c18c9db2b4", 560),
        },
    },
}


def expected_files() -> dict[str, tuple[str, int]]:
    return {
        f"{directory}/{relative}": (digest, size)
        for directory, repo in REPOSITORIES.items()
        for relative, (digest, size) in repo["files"].items()
    }


def digest_file(path: Path) -> str:
    sha = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(4 * 1024 * 1024), b""):
            sha.update(chunk)
    return sha.hexdigest()


def assert_regular(path: Path, root: Path) -> None:
    relative = path.relative_to(root)
    probe = root
    for item in relative.parts:
        probe = probe / item
        if probe.is_symlink() or getattr(probe, "is_junction", lambda: False)():
            raise RuntimeError(f"M4_LINKED_MODEL_FILE_REFUSED:{relative}")
    if not path.is_file():
        raise RuntimeError(f"M4_REQUIRED_MODEL_FILE_MISSING:{relative}")


def verify_file(path: Path, root: Path, sha: str, size: int) -> None:
    assert_regular(path, root)
    if path.stat().st_size != size or digest_file(path) != sha:
        raise RuntimeError(f"M4_FROZEN_MODEL_SHA256_MISMATCH:{path.relative_to(root)}")


def validate_bundle(root: Path = MODEL_ROOT) -> dict:
    expected = expected_files()
    manifest = root / MANIFEST
    if not manifest.is_file():
        raise RuntimeError("M4_FROZEN_BUNDLE_MANIFEST_MISSING")
    if root.is_symlink() or getattr(root, "is_junction", lambda: False)():
        raise RuntimeError("M4_LINKED_BUNDLE_ROOT_REFUSED")
    for item in root.rglob("*"):
        if item.is_symlink() or getattr(item, "is_junction", lambda: False)():
            raise RuntimeError("M4_LINKED_BUNDLE_CONTENT_REFUSED")
    seen = {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()}
    if seen != set(expected) | {MANIFEST}:
        raise RuntimeError("M4_FROZEN_BUNDLE_FILE_INVENTORY_MISMATCH")
    assert_regular(manifest, root)
    record = json.loads(manifest.read_text(encoding="utf8"))
    if record.get("production_approved") is not False or record.get("signature") != "NOT_SIGNED":
        raise RuntimeError("M4_RESEARCH_BUNDLE_MANIFEST_AUTHORITY_CHANGED")
    entries = record.get("files")
    if not isinstance(entries, dict) or set(entries) != set(expected):
        raise RuntimeError("M4_BUNDLE_MANIFEST_FILE_SET_MISMATCH")
    for rel, (sha, size) in expected.items():
        row = entries[rel]
        if not isinstance(row, dict) or row.get("sha256") != sha or row.get("bytes") != size:
            raise RuntimeError(f"M4_BUNDLE_MANIFEST_PIN_MISMATCH:{rel}")
        verify_file(root / rel, root, sha, size)
    return {"status": "VERIFIED_FROZEN_M4_ASSETS", "artifacts": len(expected), "root": str(root)}


def create_local_manifest(root: Path) -> None:
    manifest = root / MANIFEST
    if manifest.exists():
        if manifest.is_symlink() or getattr(manifest, "is_junction", lambda: False)():
            raise RuntimeError("M4_LINKED_BUNDLE_MANIFEST_REFUSED")
        return
    entry = {}
    for name, info in REPOSITORIES.items():
        for relative, (sha, size) in info["files"].items():
            entry[f"{name}/{relative}"] = {
                "sha256": sha,
                "bytes": size,
                "source_path": f"huggingface://{info['repo_id']}/{relative}",
            }
    data = {
        "status": "FROZEN_MODEL_BUNDLE_VERIFIED_NOT_OWNER_ACTIVATED",
        "models": ["GLINER2.5_BASE_PASS10", "DEBERTA_V3_SMALL_V2"],
        "scope": "M4_ENGLISH_ONLY_ADVISORY",
        "training_changes": False,
        "production_approved": False,
        "signature": "NOT_SIGNED",
        "files": entry,
    }
    manifest.write_text(json.dumps(data, sort_keys=True, indent=2) + "\n", encoding="utf8")


def _token() -> str:
    for name in ("HF_TOKEN", "HUGGING_FACE_HUB_TOKEN"):
        token = os.environ.get(name, "").strip()
        if token:
            return token
    from huggingface_hub import get_token
    token = get_token()
    if token:
        return token
    if not sys.stdin.isatty():
        raise RuntimeError(
            "PRIVATE_HF_MODELS_REQUIRE_A_READ_TOKEN: set HF_TOKEN locally before setup"
        )
    token = getpass.getpass("Hugging Face READ token (hidden, never saved): ").strip()
    if not token:
        raise RuntimeError("PRIVATE_HF_MODELS_REQUIRE_A_READ_TOKEN")
    return token


def install(root: Path = MODEL_ROOT) -> dict:
    configure_runtime_environment()
    try:
        return validate_bundle(root)
    except (RuntimeError, OSError, ValueError):
        pass
    expected = expected_files()
    if root.exists():
        if root.is_symlink() or getattr(root, "is_junction", lambda: False)():
            raise RuntimeError("M4_LINKED_BUNDLE_ROOT_REFUSED")
        unexpected = {p.relative_to(root).as_posix() for p in root.rglob("*")
                      if p.is_file()} - set(expected) - {MANIFEST}
        if unexpected:
            raise RuntimeError("M4_UNEXPECTED_PREEXISTING_BUNDLE_FILES")
        for rel, (sha, size) in expected.items():
            if (root / rel).exists():
                verify_file(root / rel, root, sha, size)
    if all((root / rel).is_file() for rel in expected):
        create_local_manifest(root)
        return validate_bundle(root)
    from huggingface_hub import snapshot_download
    token = _token()
    temp = RUNTIME_TMP_DIR / "m4-model-download"
    for directory, repo in REPOSITORIES.items():
        target = root / directory
        files = repo["files"]
        for relative, (sha, size) in files.items():
            existing = target / relative
            if existing.is_file():
                verify_file(existing, root, sha, size)
        if all((target / name).is_file() for name in files):
            continue
        scratch = temp / directory
        scratch.mkdir(parents=True, exist_ok=True)
        snapshot_download(
            repo_id=repo["repo_id"],
            repo_type="model",
            revision=repo["revision"],
            token=token,
            local_dir=str(scratch),
            allow_patterns=list(files),
            max_workers=2,
        )
        # Verify the entire downloaded selection before moving any bytes.
        for relative, (sha, size) in files.items():
            verify_file(scratch / relative, scratch, sha, size)
        for relative, (sha, size) in files.items():
            destination = target / relative
            if destination.exists():
                verify_file(destination, root, sha, size)
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            temporary = destination.with_name(destination.name + ".partial")
            if temporary.exists():
                temporary.unlink()
            shutil.copyfile(scratch / relative, temporary)
            verify_file(temporary, root, sha, size)
            os.replace(temporary, destination)
    create_local_manifest(root)
    return validate_bundle(root)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Provision frozen, fine-tuned GLiNER PASS10 + DeBERTa V2; M6 E5 is separate.")
    parser.add_argument("--verify-only", action="store_true")
    parser.add_argument("--model-root", type=Path, default=MODEL_ROOT)
    args = parser.parse_args(argv)
    result = validate_bundle(args.model_root) if args.verify_only else install(args.model_root)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
