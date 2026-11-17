"""SHA-pinned M3 Llama Prompt Guard 2 V3 research-only local installer.

Installs from verified local files or an anonymous PUBLIC Hugging Face model
at an immutable 40-character commit SHA. Five executable assets and all
redistribution notices are verified independently by exact size and SHA-256.
No remote Python code, model authorization, M4/M6 bundle changes, or
production approval are implied.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
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
# Legal documents reside alongside the public model copy; they are not
# executable model input and have independent immutable content hashes.
PUBLIC_NOTICES = {
    "LICENSE": ("6b346865267ef58a4592287a99e9417178223c9300e9da361ce7801be6dea61f", 7603),
    "NOTICE": ("d815b78fe59765882c35c481ce62d06e7e1b81cc9e400cd654d18bf59cc61c0e", 431),
    "README.md": ("4c3c98b4a420cf2f9a9d4d945d92267c5e176497896d9ff294471ec43ec23f35", 1999),
    "USE_POLICY.md": ("bbf009b29f1dc413c2b3c9abb12637b0cdffa350cd0a3bd6eba89b270fc9e83f", 5824),
}
SCOPE = "M3_ENGLISH_TOOL_DESCRIPTION_RESEARCH_SHADOW_NO_POLICY_AUTHORITY"
HF_REPO_ID = "tnlegend/Llama-MCP-Prompt-Guard-2-V3"
# Verified public revision containing unchanged frozen weights AND legal notices.
HF_FROZEN_REVISION = "7e7355f040b68b9fb68f8632817e3111e556719f"


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
    model_names = set(EXPECTED)
    legal_names = set(PUBLIC_NOTICES)
    # Historical locally installed V3 bundles had only the five model files
    # plus a manifest. They remain readable, but every newly downloaded public
    # bundle must include all legal documents (partial/injected sets fail).
    legal_present = found & legal_names
    if (not model_names.issubset(found)
            or legal_present not in (set(), legal_names)
            or found - model_names - legal_names - {MANIFEST_NAME}):
        raise RuntimeError("M3_PG2_BUNDLE_FILE_INVENTORY_MISMATCH")
    checked = dict(EXPECTED)
    if legal_present:
        checked.update(PUBLIC_NOTICES)
    for name, (expected, size) in checked.items():
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
        legal = set(PUBLIC_NOTICES) if all((source / n).is_file() for n in PUBLIC_NOTICES) else set()
        for name in tuple(EXPECTED) + tuple(sorted(legal)):
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


def install_public_hf(
    revision: str, target: Path = TARGET,
) -> dict[str, object]:
    """Anonymous public immutable-commit download with exact provenance.

    Fail closed for private repos, moving refs, missing notices or altered
    model files. No token is read, asked for or forwarded to Hugging Face.
    Existing checked local bundles require no network access.
    """
    if not isinstance(revision, str) or re.fullmatch(r"[0-9a-f]{40}", revision) is None:
        raise RuntimeError("M3_PG2_V3_IMMUTABLE_HF_COMMIT_REQUIRED")
    if target.exists():
        return verify_install(target)
    from huggingface_hub import HfApi, hf_hub_download
    info = HfApi().model_info(HF_REPO_ID, revision=revision, token=False)
    if info.private is not False or info.sha != revision:
        raise RuntimeError("M3_PG2_V3_HF_REPO_NOT_PUBLIC_OR_NOT_PINNED")
    configure_runtime_environment()
    RUNTIME_TMP_DIR.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="m3-v3-public-hf-", dir=RUNTIME_TMP_DIR) as scratch:
        folder = Path(scratch)
        allowed = {**EXPECTED, **PUBLIC_NOTICES}
        for name, (expected_hash, size) in allowed.items():
            source = Path(hf_hub_download(
                repo_id=HF_REPO_ID, filename=name,
                revision=revision, token=False,
                repo_type="model",
            ))
            # A content-addressed HF cache may supply a symlink to a blob.
            # Copy only after matching exact expected size and content hash;
            # the final install itself forbids symlinks.
            if (not source.is_file()
                    or source.stat().st_size != size
                    or digest(source) != expected_hash):
                raise RuntimeError("M3_PG2_V3_PUBLIC_HF_FILE_HASH_MISMATCH:" + name)
            shutil.copyfile(source, folder / name)
        verify_files(folder)
        return install(folder, target=target)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=None)
    parser.add_argument("--from-public-hf", action="store_true")
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()
    source = args.source or (
        Path(os.environ["M3_PG2_V3_SOURCE_DIR"])
        if os.environ.get("M3_PG2_V3_SOURCE_DIR", "").strip() else None
    )
    if sum((bool(args.verify_only), bool(args.from_public_hf), source is not None)) != 1:
        parser.error("choose exactly one of --verify-only, --source/local env, --from-public-hf")
    if args.verify_only:
        result = verify_install()
    elif args.from_public_hf:
        revision = os.environ.get("M3_PG2_V3_HF_REVISION", "").strip() or HF_FROZEN_REVISION
        result = install_public_hf(revision)
    else:
        assert source is not None
        result = install(source)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
