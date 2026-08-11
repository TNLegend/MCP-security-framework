from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = REPO_ROOT / "backend"
sys.path.insert(0, str(BACKEND_DIR))

from app.db.database import SessionLocal  # noqa: E402
from app.db.init_db import init_db  # noqa: E402
from app.services.control_plane_auth import ControlPlaneAuthError, create_user  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Create a Control Plane human user.")
    parser.add_argument("--username", required=True)
    parser.add_argument("--role", required=True, choices=["ADMIN", "VIEWER"])
    parser.add_argument("--display-name")
    parser.add_argument("--disabled", action="store_true")
    args = parser.parse_args()

    password = getpass.getpass("Password: ")
    confirmation = getpass.getpass("Confirm password: ")
    if password != confirmation:
        raise SystemExit("Passwords do not match.")
    if len(password) < 8:
        raise SystemExit("Password must contain at least 8 characters.")

    init_db()
    with SessionLocal() as db:
        try:
            user = create_user(
                db,
                username=args.username,
                password=password,
                role=args.role,
                enabled=not args.disabled,
                display_name=args.display_name,
            )
        except ControlPlaneAuthError as exc:
            db.rollback()
            raise SystemExit(str(exc)) from exc
        db.commit()
        print(f"Created Control Plane user '{user.username}' with role {user.role}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
