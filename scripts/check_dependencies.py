import shutil
import subprocess
import sys


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


def get_version(command: str) -> str:
    try:
        result = subprocess.run(
            [command, "--version"],
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
