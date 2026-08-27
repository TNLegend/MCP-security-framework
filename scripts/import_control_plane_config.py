from __future__ import annotations

import argparse
from dataclasses import dataclass
import sys
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session


REPO_ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = REPO_ROOT / "backend"
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(BACKEND_DIR))

from app.db.database import SessionLocal  # noqa: E402
from app.db.init_db import init_db  # noqa: E402
from app.models.control_plane import ControlPlaneConfigRevision, ControlPlaneState  # noqa: E402
from app.schemas.control_plane import (  # noqa: E402
    ControlPlaneConfigContent,
    empty_latest_configuration,
)
from app.services.control_plane_config import (  # noqa: E402
    create_revision,
    lock_control_plane_state_for_update,
)
from app.services.published_configuration import (  # noqa: E402
    PublishedConfigurationError,
    PublishedConfigurationProvider,
    content_model_to_json,
    validate_config_content,
)
class ConfigurationBootstrapError(RuntimeError):
    def __init__(
        self,
        code: str,
        *,
        revision_count: int = 0,
        revisions: tuple[dict[str, Any], ...] = (),
    ) -> None:
        super().__init__(code)
        self.code = code
        self.revision_count = revision_count
        self.revisions = revisions


@dataclass(frozen=True)
class ConfigurationBootstrapResult:
    status: str
    revision_id: str
    revision_number: int
    content_hash: str
    schema_version: int


def load_latest_config() -> ControlPlaneConfigContent:
    return empty_latest_configuration()


def ensure_initial_published_configuration(
    db: Session,
) -> ConfigurationBootstrapResult:
    state = lock_control_plane_state_for_update(db)
    provider = PublishedConfigurationProvider(db)
    try:
        snapshot = provider.load_active_snapshot()
    except PublishedConfigurationError as exc:
        active_error = exc.code
        if active_error != "active_config_missing":
            revisions = _revision_summaries(db)
            raise ConfigurationBootstrapError(
                active_error,
                revision_count=len(revisions),
                revisions=tuple(revisions),
            ) from exc
    except Exception as exc:
        raise ConfigurationBootstrapError("active_config_validation_failed") from exc
    else:
        return ConfigurationBootstrapResult(
            status="READY",
            revision_id=snapshot.revision_id,
            revision_number=snapshot.revision_number,
            content_hash=snapshot.content_hash,
            schema_version=snapshot.schema_version,
        )

    revisions = _revision_summaries(db)
    if not revisions and state.active_revision_id is None:
        content = load_latest_config()
        validate_config_content(content_model_to_json(content))
        revision = create_revision(
            db,
            content=content,
            status="PUBLISHED",
            actor=None,
            change_summary="Initial latest configuration",
        )
        state.active_revision_id = revision.id
        db.add(state)
        db.flush()
        snapshot = provider.load_active_snapshot()
        return ConfigurationBootstrapResult(
            status="IMPORTED",
            revision_id=snapshot.revision_id,
            revision_number=snapshot.revision_number,
            content_hash=snapshot.content_hash,
            schema_version=snapshot.schema_version,
        )

    raise ConfigurationBootstrapError(
        active_error,
        revision_count=len(revisions),
        revisions=tuple(revisions),
    )


def bootstrap_initial_published_configuration(
) -> ConfigurationBootstrapResult:
    with SessionLocal() as db:
        result = ensure_initial_published_configuration(db)
        db.commit()
        return result


def _revision_summaries(db: Session) -> list[dict[str, Any]]:
    revisions = db.scalars(
        select(ControlPlaneConfigRevision).order_by(
            ControlPlaneConfigRevision.revision_number
        )
    ).all()
    return [
        {
            "revision_number": revision.revision_number,
            "status": revision.status,
            "schema_version": revision.schema_version,
            "content_hash": revision.content_hash,
        }
        for revision in revisions
    ]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create the initial latest Control Plane configuration."
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Allow import when no active revision exists but old drafts exist.",
    )
    args = parser.parse_args()

    init_db()
    with SessionLocal() as db:
        try:
            if args.force:
                state = db.get(ControlPlaneState, 1)
                published_exists = db.scalar(
                    select(ControlPlaneConfigRevision.id)
                    .where(ControlPlaneConfigRevision.status == "PUBLISHED")
                    .limit(1)
                )
                if state is not None and state.active_revision_id is not None:
                    raise ConfigurationBootstrapError("active_config_exists")
                if published_exists is not None:
                    raise ConfigurationBootstrapError("published_revision_exists")
                content = load_latest_config()
                validate_config_content(content_model_to_json(content))
                revision = create_revision(
                    db,
                    content=content,
                    status="PUBLISHED",
                    actor=None,
                    change_summary="Forced initial latest configuration",
                )
                state = state or ControlPlaneState(id=1)
                state.active_revision_id = revision.id
                db.add(state)
                db.flush()
                snapshot = PublishedConfigurationProvider(db).load_active_snapshot()
                result = ConfigurationBootstrapResult(
                    status="IMPORTED",
                    revision_id=snapshot.revision_id,
                    revision_number=snapshot.revision_number,
                    content_hash=snapshot.content_hash,
                    schema_version=snapshot.schema_version,
                )
            else:
                result = ensure_initial_published_configuration(db)
        except ConfigurationBootstrapError as exc:
            raise SystemExit(_format_bootstrap_error(exc)) from exc
        db.commit()
        print(
            "Control Plane config "
            f"status={result.status} revision={result.revision_number} "
            f"hash={result.content_hash}"
        )
    return 0


def _format_bootstrap_error(error: ConfigurationBootstrapError) -> str:
    message = (
        "Control Plane configuration bootstrap refused: "
        f"{error.code}; revision_count={error.revision_count}"
    )
    if error.revisions:
        safe_revisions = [
            {
                "revision_number": revision["revision_number"],
                "status": revision["status"],
                "schema_version": revision["schema_version"],
            }
            for revision in error.revisions
        ]
        message += f"; revisions={safe_revisions}"
    return message


if __name__ == "__main__":
    raise SystemExit(main())
