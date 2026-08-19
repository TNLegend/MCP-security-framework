from __future__ import annotations

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def resolve_project_path(
    value: str | Path,
    *,
    project_root: Path = PROJECT_ROOT,
) -> Path:
    candidate = Path(value).expanduser()
    if not candidate.is_absolute():
        candidate = project_root / candidate
    return candidate.resolve(strict=False)


def is_path_within(path: Path, root: Path) -> bool:
    resolved_path = path.resolve(strict=False)
    resolved_root = root.resolve(strict=False)
    return resolved_path == resolved_root or resolved_root in resolved_path.parents
