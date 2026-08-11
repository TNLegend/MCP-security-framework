from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

import yaml


REPO_ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = REPO_ROOT / "backend"
sys.path.insert(0, str(BACKEND_DIR))

from app.db.database import SessionLocal  # noqa: E402
from app.db.init_db import init_db  # noqa: E402
from app.models.control_plane import ControlPlaneConfigRevision, ControlPlaneState  # noqa: E402
from app.schemas.control_plane import ControlPlaneConfigContent  # noqa: E402
from app.services.control_plane_config import create_revision  # noqa: E402
from app.services.published_configuration import content_model_to_json  # noqa: E402
from proxy.identity_binding import IdentityBindingDocument  # noqa: E402
from proxy.resource_registry import ResourceScopeDocument  # noqa: E402
from proxy.tool_security_profiles import ToolSecurityProfileDocument  # noqa: E402
from app.services.subject_authorization import SubjectAuthorizationDocument  # noqa: E402


def _read_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"{path.name} must contain a YAML object.")
    return data


def load_yaml_config() -> ControlPlaneConfigContent:
    policies = REPO_ROOT / "policies"
    return ControlPlaneConfigContent(
        schema_version=1,
        identity_bindings=IdentityBindingDocument.model_validate(
            _read_yaml(policies / "identity_bindings.yaml")
        ),
        agent_authorizations=SubjectAuthorizationDocument.model_validate(
            _read_yaml(policies / "agent_authorizations.yaml")
        ),
        tool_security_profiles=ToolSecurityProfileDocument.model_validate(
            _read_yaml(policies / "tool_security_profiles.yaml")
        ),
        resource_scopes=ResourceScopeDocument.model_validate(
            _read_yaml(policies / "resource_scopes.yaml")
        ),
        policy_settings={
            "rules": {
                "tool_analysis_required": {
                    "enabled": True,
                    "severity": "HIGH",
                }
            }
        },
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Import administrative YAML registries into Control Plane Revision 1."
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Allow import when no active revision exists but old drafts exist.",
    )
    args = parser.parse_args()

    init_db()
    with SessionLocal() as db:
        existing = db.query(ControlPlaneConfigRevision).count()
        state = db.get(ControlPlaneState, 1)
        if existing and not args.force:
            raise SystemExit("Control Plane config revisions already exist; refusing double import.")
        if state is not None and state.active_revision_id is not None and not args.force:
            raise SystemExit("An active Control Plane config already exists.")

        content = load_yaml_config()
        revision = create_revision(
            db,
            content=content,
            status="PUBLISHED",
            actor=None,
            change_summary="Initial import from administrative YAML registries",
        )
        state = state or ControlPlaneState(id=1)
        state.active_revision_id = revision.id
        db.add(state)
        db.commit()
        print(
            "Imported Control Plane config "
            f"revision={revision.revision_number} hash={revision.content_hash} "
            f"items={len(content_model_to_json(content))}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
