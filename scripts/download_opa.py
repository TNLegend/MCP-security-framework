from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from urllib.request import urlopen


REPO_ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = REPO_ROOT / "backend"

sys.path.insert(0, str(BACKEND_DIR))

from app.core.runtime_paths import (  # noqa: E402
    OPA_DIR,
    OPA_EXE,
    OPA_SHA256,
    OPA_VERSION,
    configure_runtime_environment,
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Download the project-local OPA binary with checksum verification."
    )
    parser.add_argument("--version", default=OPA_VERSION, help="Pinned OPA version.")
    parser.add_argument(
        "--sha256",
        default=OPA_SHA256,
        help="Expected SHA-256 for opa_windows_amd64.exe.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Re-download even when the local binary already matches.",
    )
    args = parser.parse_args()

    if os.name != "nt":
        raise SystemExit(
            "The pinned local OPA provisioner currently supports Windows amd64 only."
        )

    configure_runtime_environment()
    OPA_DIR.mkdir(parents=True, exist_ok=True)

    if OPA_EXE.exists() and not args.force:
        current_sha = _sha256(OPA_EXE)
        if current_sha.lower() == args.sha256.lower():
            print(
                json.dumps(
                    {
                        "opa": {
                            "version": args.version,
                            "path": str(OPA_EXE),
                            "sha256": current_sha,
                            "status": "present",
                        }
                    },
                    indent=2,
                )
            )
            return 0

    url = (
        "https://github.com/open-policy-agent/opa/releases/download/"
        f"v{args.version}/opa_windows_amd64.exe"
    )
    tmp_path = OPA_EXE.with_suffix(".exe.download")
    with urlopen(url, timeout=120) as response:
        tmp_path.write_bytes(response.read())

    downloaded_sha = _sha256(tmp_path)
    if downloaded_sha.lower() != args.sha256.lower():
        tmp_path.unlink(missing_ok=True)
        raise SystemExit(
            "OPA checksum mismatch: "
            f"expected {args.sha256}, got {downloaded_sha}"
        )

    tmp_path.replace(OPA_EXE)
    print(
        json.dumps(
            {
                "opa": {
                    "version": args.version,
                    "path": str(OPA_EXE),
                    "sha256": downloaded_sha,
                    "status": "downloaded",
                }
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
