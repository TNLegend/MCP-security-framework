"""CF-01: read-only diff and impact preview of a configuration PUBLISH.

The preview never writes, never signs and never records an audit event. Its
impact figures come from the SAME helpers that publish_revision() applies
(identity-binding session revocation and contract-change quarantine), so the
GUI cannot show an impact the backend did not compute. Lists are bounded and
contain configuration identifiers only, never secrets or evidence payloads.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Callable

from sqlalchemy import func, select, tuple_
from sqlalchemy.orm import Session

from app.models.control_plane import ControlPlaneConfigRevision, ControlPlaneState
from app.models.trusted_agent_session import TrustedAgentSession

PREVIEW_VERSION = "config-publication-preview-v1"
MAX_ITEMS_PER_LIST = 50

# Section -> (path inside the content JSON, identity function).
_LIST_SECTIONS: dict[str, tuple[tuple[str, ...], Callable[[dict], str]]] = {
    "identity_bindings": (("identity_bindings", "bindings"),
                          lambda b: f"{b.get('issuer')} | {b.get('subject')}"),
    "security_packs": (("security_packs",), lambda p: str(p.get("id"))),
    "security_pack_installations": (("security_pack_installations",),
                                    lambda p: str(p.get("pack_id"))),
    "tool_security_contracts": (("tool_security_contracts",),
                                lambda c: f"{c.get('server_ref')} / {c.get('tool_name')}"),
    "authority_resource_scopes": (("authority_resource_scopes",), lambda s: str(s.get("scope_id"))),
    "adapter_resolutions": (("adapter_resolutions",),
                            lambda a: f"{a.get('effect_id')} / {a.get('resource_type')}"),
    "tool_observation_approvals": (("tool_observation_approvals",),
                                   lambda a: str(a.get("tool_observation_id"))),
}
_DICT_SECTIONS: dict[str, tuple[str, ...]] = {
    "agent_authorizations": ("agent_authorizations", "subjects"),
    "authority_contexts": ("authority_contexts",),
}
_OBJECT_SECTIONS = ("policy_settings", "build_security")


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _get(content: dict | None, path: tuple[str, ...]) -> Any:
    value: Any = content or {}
    for key in path:
        value = value.get(key) if isinstance(value, dict) else None
    return value


def _bounded(keys: list[str]) -> dict[str, Any]:
    ordered = sorted(keys)
    return {"count": len(ordered), "items": ordered[:MAX_ITEMS_PER_LIST],
            "truncated": len(ordered) > MAX_ITEMS_PER_LIST}


def _diff_maps(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    added = [k for k in new if k not in old]
    removed = [k for k in old if k not in new]
    changed = [k for k in new if k in old and _canonical(new[k]) != _canonical(old[k])]
    return {"added": _bounded(added), "removed": _bounded(removed), "changed": _bounded(changed)}


def content_diff(previous: dict | None, draft: dict) -> dict[str, Any]:
    sections: dict[str, Any] = {}
    for name, (path, identity) in _LIST_SECTIONS.items():
        def index(items):
            return {identity(i): i for i in (items or []) if isinstance(i, dict)}
        sections[name] = _diff_maps(index(_get(previous, path)), index(_get(draft, path)))
    for name, path in _DICT_SECTIONS.items():
        old, new = _get(previous, path) or {}, _get(draft, path) or {}
        sections[name] = _diff_maps(dict(old), dict(new))
    for name in _OBJECT_SECTIONS:
        old, new = _get(previous, (name,)) or {}, _get(draft, (name,)) or {}
        fields = sorted(k for k in set(old) | set(new)
                        if _canonical(old.get(k)) != _canonical(new.get(k)))
        sections[name] = {"changed_fields": fields}
    changed_sections = sorted(
        name for name, value in sections.items()
        if any(value.get(kind, {}).get("count") for kind in ("added", "removed", "changed"))
        or value.get("changed_fields")
    )
    return {"sections": sections, "changed_sections": changed_sections,
            "has_changes": bool(changed_sections)}


def preview_fingerprint(draft: ControlPlaneConfigRevision, active: ControlPlaneConfigRevision | None) -> str:
    material = {
        "version": PREVIEW_VERSION,
        "draft_id": draft.id, "draft_hash": draft.content_hash,
        "active_id": active.id if active else None,
        "active_hash": active.content_hash if active else None,
    }
    return hashlib.sha256(_canonical(material).encode("utf-8")).hexdigest()


def _blockers(db: Session, draft: ControlPlaneConfigRevision,
              active: ControlPlaneConfigRevision | None) -> list[str]:
    """The refusal conditions publish_revision() checks, evaluated read-only
    (no lock, no signature, no CONFIG_VALIDATED audit event)."""
    from app.services.control_plane_config import (
        ControlPlaneConfigError, _validate_v2_database_artifacts,
    )
    from app.services.published_configuration import (
        config_content_hash, content_model_to_json, validate_config_content,
    )
    blockers: list[str] = []
    if draft.status != "DRAFT":
        blockers.append("only_draft_can_publish")
    if active is not None:
        if draft.revision_number <= active.revision_number:
            blockers.append("stale_draft_publication_conflict")
        if draft.parent_revision_id is not None and draft.parent_revision_id != active.id:
            blockers.append("draft_active_parent_changed")
    elif draft.parent_revision_id is not None:
        blockers.append("draft_active_parent_changed")
    try:
        content = validate_config_content(draft.content)
        _validate_v2_database_artifacts(db, draft, content)
        if config_content_hash(content_model_to_json(content)) != draft.content_hash:
            blockers.append("revision_hash_mismatch")
    except ControlPlaneConfigError as exc:
        blockers.append(str(exc.args[0]) if exc.args else "configuration_invalid")
    except ValueError:
        # Validation detail can echo submitted content: keep a fixed code.
        blockers.append("configuration_invalid")
    return blockers


def _active(db: Session) -> ControlPlaneConfigRevision | None:
    state = db.get(ControlPlaneState, 1)
    if state is None or state.active_revision_id is None:
        return None
    revision = db.get(ControlPlaneConfigRevision, state.active_revision_id)
    return revision if revision is not None and revision.status == "PUBLISHED" else None


def preview_publication(db: Session, draft_id: str) -> dict[str, Any]:
    from app.services.control_plane_config import (
        ControlPlaneConfigError, changed_contract_keys, changed_identity_binding_keys,
        tools_affected_by_contract_change,
    )
    from app.services.published_configuration import validate_config_content

    draft = db.get(ControlPlaneConfigRevision, draft_id)
    if draft is None:
        raise ControlPlaneConfigError("revision_not_found")
    active = _active(db)
    blockers = _blockers(db, draft, active)
    diff = content_diff(active.content if active else None, draft.content)

    impact: dict[str, Any] = {"computed": False, "basis": "PUBLISH_RULES"}
    try:
        previous_model = validate_config_content(active.content) if active else None
        draft_model = validate_config_content(draft.content)
    except (ControlPlaneConfigError, ValueError):
        impact["unavailable_reason"] = "CONTENT_INVALID_IMPACT_NOT_COMPUTED"
    else:
        bindings = changed_identity_binding_keys(previous_model, draft_model)
        sessions = 0
        if bindings:
            sessions = int(db.scalar(
                select(func.count(TrustedAgentSession.id)).where(
                    tuple_(TrustedAgentSession.identity_issuer,
                           TrustedAgentSession.identity_subject).in_(bindings),
                    TrustedAgentSession.revoked_at.is_(None),
                )
            ) or 0)
        contracts = changed_contract_keys(previous_model, draft_model)
        tools = tools_affected_by_contract_change(db, contracts)
        impact.update({
            "computed": True,
            "identity_bindings_changed": _bounded([f"{i} | {s}" for i, s in bindings]),
            "sessions_to_revoke": sessions,
            "tool_contracts_changed_or_removed": _bounded([f"{r} / {t}" for r, t in contracts]),
            "tools_to_restrict": _bounded([f"{tool.name} (server {server.id})" for tool, server in tools]),
            "first_publication": active is None,
        })
    return {
        "preview_version": PREVIEW_VERSION,
        "draft": {"id": draft.id, "revision_number": draft.revision_number,
                  "content_hash": draft.content_hash, "status": draft.status},
        "active": ({"id": active.id, "revision_number": active.revision_number,
                    "content_hash": active.content_hash} if active else None),
        "publishable": not blockers,
        "blockers": blockers,
        "diff": diff,
        "impact": impact,
        "preview_fingerprint": preview_fingerprint(draft, active),
    }
