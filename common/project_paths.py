from __future__ import annotations

import os
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def resolve_project_path(
    value: str | Path,
    *,
    project_root: Path = PROJECT_ROOT,
) -> Path:
    candidate = Path(value).expanduser()
    if os.environ.get("MCP_FRAMEWORK_QA_ROOT") and project_root.resolve() == PROJECT_ROOT.resolve():
        operational = PROJECT_ROOT / ".runtime"
        if candidate.is_absolute() and is_path_within(candidate,operational):
            raise ValueError("qa_operational_runtime_path_refused")
        if not candidate.is_absolute() and candidate.parts and candidate.parts[0] == ".runtime":
            candidate = runtime_data_root(project_root).joinpath(*candidate.parts[1:])
    if not candidate.is_absolute():
        candidate = project_root / candidate
    return candidate.resolve(strict=False)


def is_path_within(path: Path, root: Path) -> bool:
    resolved_path = path.resolve(strict=False)
    resolved_root = root.resolve(strict=False)
    return resolved_path == resolved_root or resolved_root in resolved_path.parents


def runtime_data_root(project_root: Path = PROJECT_ROOT) -> Path:
    configured=os.environ.get("MCP_FRAMEWORK_QA_ROOT")
    if not configured:
        return project_root / ".runtime"
    value=Path(configured)
    if not value.is_absolute() or is_path_within(value,project_root):
        raise ValueError("qa_runtime_must_be_absolute_and_outside_source")
    return value.resolve()
