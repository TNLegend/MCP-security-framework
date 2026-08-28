from __future__ import annotations

import argparse
import io
import json
from pathlib import Path
import sys
import zipfile

REPO_ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = REPO_ROOT / "backend"
for path in (str(REPO_ROOT), str(BACKEND_DIR)):
    if path not in sys.path:
        sys.path.insert(0, path)

from proxy.trusted_adapter_packages import (  # noqa: E402
    build_adapter_starter_archive,
    create_signed_adapter_archive,
    install_adapter_archive,
    signer_fingerprint,
    verify_adapter_archive,
)
from proxy.tool_security_v2 import SecurityModelError  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Trusted Adapter SDK operator utility")
    subparsers = parser.add_subparsers(dest="command", required=True)

    starter = subparsers.add_parser("starter", help="Create a fail-closed adapter starter directory")
    starter.add_argument("starter_id")
    starter.add_argument("adapter_id")
    starter.add_argument("output", type=Path)

    sign = subparsers.add_parser("sign", help="Create a signed adapter distribution")
    sign.add_argument("source", type=Path)
    sign.add_argument("private_key", type=Path)
    sign.add_argument("output", type=Path)

    validate = subparsers.add_parser("validate", help="Verify a signed adapter distribution")
    validate.add_argument("archive", type=Path)
    validate.add_argument("--trusted-fingerprint", action="append", required=True)

    install = subparsers.add_parser("install", help="Install a verified distribution for the next controlled restart")
    install.add_argument("archive", type=Path)
    install.add_argument("directory", type=Path)
    install.add_argument("--trusted-fingerprint", action="append", required=True)

    args = parser.parse_args()
    try:
        if args.command == "starter":
            _extract_starter(
                build_adapter_starter_archive(args.starter_id, args.adapter_id),
                args.output,
            )
            print(f"Starter created: {args.output.resolve()}")
        elif args.command == "sign":
            archive = create_signed_adapter_archive(
                args.source,
                private_key_pem=args.private_key.read_bytes(),
            )
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_bytes(archive)
            registration = verify_adapter_archive(
                archive,
                trusted_signer_fingerprints=(
                    _archive_signer_fingerprint(archive),
                ),
            )
            print(f"Signed adapter: {registration.adapter.manifest.adapter_id}")
            print(f"Signer fingerprint: {registration.signer_key_fingerprint}")
        elif args.command == "validate":
            registration = verify_adapter_archive(
                args.archive.read_bytes(),
                trusted_signer_fingerprints=tuple(args.trusted_fingerprint),
            )
            print(f"Valid adapter: {registration.adapter.manifest.adapter_id}")
            print(f"Distribution SHA-256: {registration.distribution_sha256}")
        else:
            target = install_adapter_archive(
                args.archive.read_bytes(),
                destination_directory=args.directory,
                trusted_signer_fingerprints=tuple(args.trusted_fingerprint),
            )
            print(f"Installed for controlled restart: {target.resolve()}")
    except (OSError, SecurityModelError, zipfile.BadZipFile) as exc:
        print(f"Trusted adapter operation failed: {exc}", file=sys.stderr)
        return 1
    return 0


def _extract_starter(archive: bytes, destination: Path) -> None:
    if destination.exists() and any(destination.iterdir()):
        raise SecurityModelError("adapter_starter_destination_not_empty")
    destination.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(archive)) as package:
        for info in package.infolist():
            target = (destination / info.filename).resolve()
            if destination.resolve() not in target.parents:
                raise SecurityModelError("adapter_starter_archive_invalid")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(package.read(info.filename))


def _archive_signer_fingerprint(archive: bytes) -> str:
    with zipfile.ZipFile(io.BytesIO(archive)) as package:
        signature = json.loads(package.read("signature.json"))
    return signer_fingerprint(signature["public_key_pem"])


if __name__ == "__main__":
    raise SystemExit(main())
