from __future__ import annotations
from typing import Any
from pathlib import Path


def _model_version_from_config(model: Any, fallback: str) -> str:
    from pathlib import Path

    config = getattr(model, "config", None)
    commit_hash = getattr(config, "_commit_hash", None)
    if commit_hash:
        return str(commit_hash)
    name_or_path = getattr(config, "name_or_path", None)
    if name_or_path:
        path = Path(str(name_or_path))
        if path.parent.name == "snapshots":
            return path.name
        return str(name_or_path)
    return fallback


def _sentence_transformer_version(model: Any, fallback: str) -> str:
    for module in model.modules():
        auto_model = getattr(module, "auto_model", None)
        version = _model_version_from_config(auto_model, "")
        if version:
            return version
    return fallback


def _local_snapshot_path(cache_dir: Path, model_name: str) -> Path | None:
    model_dir = cache_dir / f"models--{model_name.replace('/', '--')}"
    refs_main = model_dir / "refs" / "main"
    if refs_main.exists():
        revision = refs_main.read_text(encoding="utf-8").strip()
        snapshot = model_dir / "snapshots" / revision
        if snapshot.exists():
            return snapshot
    snapshots_dir = model_dir / "snapshots"
    if not snapshots_dir.exists():
        return None
    snapshots = sorted(
        (path for path in snapshots_dir.iterdir() if path.is_dir()),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    return snapshots[0] if snapshots else None
