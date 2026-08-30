from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = REPO_ROOT / "backend"
sys.path.insert(0, str(BACKEND_DIR))

from app.core.runtime_paths import OPA_EXE  # noqa: E402


MIN_PYTHON = (3, 11)
MAX_PYTHON_EXCLUSIVE = (3, 14)
MIN_POSTGRES_MAJOR = 15


@dataclass(frozen=True)
class DependencyCheck:
    name: str
    ok: bool
    detail: str
    project_managed: bool = False


def command_path(command: str) -> str | None:
    return shutil.which(command)


def find_postgres_tool(command: str) -> str | None:
    located = shutil.which(command)
    if located:
        return located

    psql = shutil.which("psql")
    if psql:
        sibling = Path(psql).resolve().parent / (command + (".exe" if os.name == "nt" else ""))
        if sibling.is_file():
            return str(sibling)

    if os.name == "nt":
        candidates: list[Path] = []
        for env_name in ("ProgramFiles", "ProgramFiles(x86)"):
            root = os.environ.get(env_name)
            if not root:
                continue
            postgres_root = Path(root) / "PostgreSQL"
            if not postgres_root.is_dir():
                continue
            for version_dir in postgres_root.iterdir():
                if version_dir.is_dir():
                    candidates.append(version_dir / "bin" / f"{command}.exe")
        def version_key(candidate: Path) -> tuple[int, ...]:
            try:
                return tuple(int(part) for part in candidate.parents[1].name.split("."))
            except ValueError:
                return (0,)

        for candidate in sorted(candidates, key=version_key, reverse=True):
            if candidate.is_file():
                return str(candidate)
    return None


def _run_version(command: list[str]) -> str:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
        return (result.stdout.strip() or result.stderr.strip()).strip()
    except Exception:
        return ""


def _parse_version(value: str) -> tuple[int, ...] | None:
    match = re.search(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?", value)
    if not match:
        return None
    return tuple(int(part or 0) for part in match.groups())


def python_supported(version_info=None) -> bool:  # noqa: ANN001
    current = version_info or sys.version_info
    value = (int(current.major), int(current.minor))
    return MIN_PYTHON <= value < MAX_PYTHON_EXCLUSIVE


def node_supported(version_text: str) -> bool:
    parsed = _parse_version(version_text)
    if parsed is None:
        return False
    major, minor, patch = (parsed + (0, 0, 0))[:3]
    if major == 20:
        return (major, minor, patch) >= (20, 19, 0)
    return (major, minor, patch) >= (22, 12, 0)


def postgres_supported(version_text: str) -> bool:
    parsed = _parse_version(version_text)
    return parsed is not None and parsed[0] >= MIN_POSTGRES_MAJOR


def system_prerequisite_checks() -> list[DependencyCheck]:
    checks: list[DependencyCheck] = []

    python_detail = sys.version.split()[0]
    checks.append(
        DependencyCheck(
            "Python",
            python_supported(),
            f"{python_detail} (supported: >=3.11,<3.14)",
        )
    )

    git = command_path("git")
    git_version = _run_version([git, "--version"]) if git else ""
    checks.append(
        DependencyCheck(
            "Git",
            bool(git),
            git_version or "command not found",
        )
    )

    node = command_path("node")
    node_version = _run_version([node, "--version"]) if node else ""
    checks.append(
        DependencyCheck(
            "Node.js",
            bool(node) and node_supported(node_version),
            (
                f"{node_version} (required by Vite: ^20.19.0 or >=22.12.0)"
                if node
                else "command not found"
            ),
        )
    )

    npm_command = "npm.cmd" if os.name == "nt" else "npm"
    npm = command_path(npm_command)
    npm_version = _run_version([npm, "--version"]) if npm else ""
    checks.append(
        DependencyCheck(
            "npm",
            bool(npm),
            npm_version or "command not found",
        )
    )

    postgres_tools = {
        name: find_postgres_tool(name)
        for name in ("postgres", "initdb")
    }
    missing_tools = [name for name, path in postgres_tools.items() if not path]
    postgres_version = (
        _run_version([postgres_tools["postgres"], "--version"])
        if postgres_tools["postgres"]
        else ""
    )
    checks.append(
        DependencyCheck(
            "PostgreSQL",
            not missing_tools and postgres_supported(postgres_version),
            (
                f"{postgres_version}; required server tools ready"
                if not missing_tools
                else "missing PostgreSQL server binaries: " + ", ".join(missing_tools)
            ),
        )
    )

    return checks


def project_managed_checks() -> list[DependencyCheck]:
    if OPA_EXE.exists():
        detail = _run_version([str(OPA_EXE), "version"]) or str(OPA_EXE)
        return [DependencyCheck("OPA", True, detail, project_managed=True)]
    return [
        DependencyCheck(
            "OPA",
            True,
            "not provisioned yet; setup downloads and checksum-verifies the pinned binary",
            project_managed=True,
        )
    ]


def assert_system_prerequisites() -> None:
    failed = [check for check in system_prerequisite_checks() if not check.ok]
    if failed:
        details = "; ".join(f"{item.name}: {item.detail}" for item in failed)
        raise RuntimeError("System prerequisites are not satisfied: " + details)


def main() -> int:
    print("MCP Security Framework - Dependency Check")
    print("=" * 72)

    checks = system_prerequisite_checks() + project_managed_checks()
    for check in checks:
        prefix = "PROJECT" if check.project_managed else ("OK" if check.ok else "MISSING")
        print(f"[{prefix}] {check.name}: {check.detail}")

    failed = [check for check in checks if not check.project_managed and not check.ok]
    print("=" * 72)
    if failed:
        print("System prerequisites missing or unsupported:")
        for item in failed:
            print(f"- {item.name}: {item.detail}")
        return 1

    print("System prerequisites are ready. Project-managed dependencies are handled by setup.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
