"""Exclude explicitly local QA-only files from the runtime source fingerprint.

The source repository intentionally ignores these investigation/test files.
They may exist on a developer machine but are absent from a clean Git clone.
Only these narrow, non-runtime patterns are excluded: every other eligible
source file remains covered by the existing SHA-256 and symlink checks.
"""
from __future__ import annotations

from fnmatch import fnmatchcase
from pathlib import Path

_PRIVATE_SCRIPT_PATTERNS = (
    "qa_*.py",
    "qualify_*.py",
    "replay_*.py",
    "analyzer_autonomous_*.py",
    "analyzer_proposition_*.py",
    "analyzer_selection_workflow.py",
    "analyze_analyzer_*.py",
    "evaluate_*.py",
    "benchmark_*.py",
    "finalize_lots*.py",
    "write_lots*.py",
    "verify_lot64_*.py",
    "check_analyzer_adjudication_freeze.py",
    "check_f11_staging_readiness.py",
    "smoke_analyzer_assessment.py",
)


def is_private_qa_source(path: Path) -> bool:
    """Match only the narrowly declared ignored QA files, not runtime code."""
    parts = tuple(piece.lower() for piece in Path(path).parts)
    if not parts:
        return False
    name = parts[-1]
    if len(parts) >= 2 and parts[-2] == "scripts":
        return any(fnmatchcase(name, pattern) for pattern in _PRIVATE_SCRIPT_PATTERNS)
    if (
        len(parts) >= 3 and parts[-3:-1] == ("policies", "opa")
        and name.endswith("_test.rego")
    ):
        return True
    if name.endswith((".test.js", ".test.jsx", ".test.ts", ".test.tsx",
                      ".spec.js", ".spec.jsx", ".spec.ts", ".spec.tsx")):
        return any(parts[i:i + 2] == ("frontend", "src")
                   for i in range(len(parts) - 1))
    return False
