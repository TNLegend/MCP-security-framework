import shutil
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = REPO_ROOT / "backend"
sys.path.insert(0, str(BACKEND_DIR))

from app.core.runtime_paths import OPA_EXE  # noqa: E402


REQUIRED_COMMANDS = {
    "git": "Git",
    "python": "Python",
    "pip": "pip",
    "node": "Node.js",
    "npm": "npm",
    "psql": "PostgreSQL client",
}


def command_exists(command: str) -> bool:
    return shutil.which(command) is not None


def get_version(command: str | list[str]) -> str:
    try:
        command_line = command if isinstance(command, list) else [command, "--version"]
        result = subprocess.run(
            command_line,
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.stdout.strip() or result.stderr.strip()
    except Exception:
        return "version unavailable"


def main() -> int:
    print("MCP Security Framework - Dependency Check")
    print("=" * 50)

    missing = []

    for command, label in REQUIRED_COMMANDS.items():
        if command_exists(command):
            print(f"[OK] {label}: {get_version(command)}")
        else:
            print(f"[MISSING] {label}: command '{command}' not found")
            missing.append(label)

    if OPA_EXE.exists():
        print(f"[OK] OPA local: {get_version([str(OPA_EXE), 'version'])}")
    else:
        print(f"[MISSING] OPA local: expected {OPA_EXE}")
        missing.append("OPA local")

    print("=" * 50)

    if missing:
        print("Missing dependencies:")
        for item in missing:
            print(f"- {item}")
        return 1

    print("All required dependencies are installed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
