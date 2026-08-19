from __future__ import annotations

import os
import stat
from pathlib import Path


def restrict_private_file(path: Path) -> None:
    _best_effort_chmod(path, stat.S_IRUSR | stat.S_IWUSR)


def restrict_public_file(path: Path) -> None:
    _best_effort_chmod(
        path,
        stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH,
    )


def _best_effort_chmod(path: Path, mode: int) -> None:
    try:
        os.chmod(path, mode)
    except OSError:
        # Windows and some mounted filesystems cannot express POSIX modes.
        pass
