from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

from sqlalchemy import func, select


REPO_ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = REPO_ROOT / "backend"
for import_path in (REPO_ROOT, BACKEND_DIR):
    if str(import_path) not in sys.path:
        sys.path.insert(0, str(import_path))

from app.db.database import SessionLocal  # noqa: E402
from app.db.init_db import init_db  # noqa: E402
from app.models.control_plane import ControlPlaneUser  # noqa: E402
from app.services.control_plane_auth import (  # noqa: E402
    ROLE_ADMIN,
    ControlPlaneAuthError,
    create_user,
)


class BootstrapAdminRequired(RuntimeError):
    pass


def read_initial_admin_passwords(*, password_func=getpass.getpass,
                                 input_stream=None) -> tuple[str, str]:
    """Read two secrets from a terminal or an explicitly trusted stdin pipe.

    The opt-in pipe is for unattended first-install acceptance and automated
    provisioning; no password is placed in argv, environment variables, logs,
    or source files. Default human installations still use getpass.
    """
    stream = input_stream if input_stream is not None else sys.stdin
    if os.environ.get("MCP_BOOTSTRAP_ADMIN_STDIN") == "1":
        if stream.isatty():
            raise BootstrapAdminRequired(
                "MCP_BOOTSTRAP_ADMIN_STDIN requires a redirected, trusted stdin pipe."
            )
        password = stream.readline().rstrip("\r\n")
        confirmation = stream.readline().rstrip("\r\n")
        return password, confirmation
    return password_func("Password: "), password_func("Confirm password: ")


def ensure_initial_admin(
    *,
    interactive: bool | None = None,
    input_func=input,
    password_func=getpass.getpass,
) -> str:
    use_interactive = sys.stdin.isatty() if interactive is None else interactive
    with SessionLocal() as db:
        active_admins = int(
            db.scalar(
                select(func.count()).select_from(ControlPlaneUser).where(
                    ControlPlaneUser.role == ROLE_ADMIN,
                    ControlPlaneUser.enabled.is_(True),
                )
            )
            or 0
        )
        if active_admins:
            return "existing"
        if not use_interactive:
            raise BootstrapAdminRequired(
                "No active Control Plane ADMIN exists. Run interactively or execute: "
                ".\\backend\\.venv\\Scripts\\python.exe "
                "scripts\\create_control_plane_user.py --username <name> --role ADMIN"
            )

        username = input_func("Initial ADMIN username: ").strip()
        if not username:
            raise BootstrapAdminRequired("Initial ADMIN username must not be empty.")
        password, confirmation = read_initial_admin_passwords(password_func=password_func)
        if password != confirmation:
            raise BootstrapAdminRequired("Passwords do not match.")
        if len(password) < 8:
            raise BootstrapAdminRequired("Password must contain at least 8 characters.")
        try:
            create_user(
                db,
                username=username,
                password=password,
                role=ROLE_ADMIN,
            )
        except ControlPlaneAuthError as exc:
            db.rollback()
            raise BootstrapAdminRequired(str(exc)) from exc
        db.commit()
        return "created"


def main() -> int:
    parser = argparse.ArgumentParser(description="Create a Control Plane human user.")
    parser.add_argument("--username")
    parser.add_argument("--role", choices=["ADMIN", "VIEWER"])
    parser.add_argument("--display-name")
    parser.add_argument("--disabled", action="store_true")
    parser.add_argument("--bootstrap-initial-admin", action="store_true")
    args = parser.parse_args()

    init_db()
    if args.bootstrap_initial_admin:
        try:
            result = ensure_initial_admin()
        except BootstrapAdminRequired as exc:
            raise SystemExit(str(exc)) from exc
        print(f"Initial Control Plane ADMIN status: {result}.")
        return 0
    if not args.username or not args.role:
        parser.error("--username and --role are required unless bootstrapping the initial ADMIN")

    password = getpass.getpass("Password: ")
    confirmation = getpass.getpass("Confirm password: ")
    if password != confirmation:
        raise SystemExit("Passwords do not match.")
    if len(password) < 8:
        raise SystemExit("Password must contain at least 8 characters.")

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
