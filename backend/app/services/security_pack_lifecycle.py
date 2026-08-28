from __future__ import annotations

import base64
import binascii
import hashlib
from datetime import datetime, timezone
from typing import Any, Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from sqlalchemy.orm import Session

from common.canonical_json import canonical_json_bytes
from app.models.control_plane import ControlPlaneConfigRevision, ControlPlaneUser
from app.schemas.control_plane import ControlPlaneConfigContent
from app.schemas.security_pack import SecurityPackPackageInput
from app.services.control_plane_audit import record_control_plane_audit
from app.services.control_plane_config import active_revision, patch_draft_revision
from app.services.published_configuration import validate_config_content
from proxy.security_packs import (
    SecurityPackDependency,
    SecurityPackError,
    SecurityPackInstallation,
    SecurityPackInstalledVersion,
    SecurityPackManifest,
    SecurityPackRegistry,
    active_lifecycle_manifests,
    builtin_security_packs,
    parse_security_pack_version,
    security_pack_manifest_hash,
    validate_security_pack_lifecycle,
)
from proxy.resource_adapters_v2 import AdapterRegistry
from proxy.tool_security_v2 import SecurityModelError


class SecurityPackLifecycleError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def lifecycle_catalog(content: ControlPlaneConfigContent) -> dict[str, Any]:
    return {
        "builtin_packs": builtin_security_packs(),
        "installations": bootstrap_installations(content),
    }


def validate_package(
    package: SecurityPackPackageInput,
    *,
    content: ControlPlaneConfigContent,
) -> dict[str, Any]:
    manifest = package.manifest
    validate_custom_manifest_safety(manifest)
    digest = security_pack_manifest_hash(manifest)
    expected_matched = package.expected_sha256 is None or package.expected_sha256 == digest
    if not expected_matched:
        raise SecurityPackLifecycleError("security_pack_package_hash_mismatch")

    signature_verified = False
    signer_fingerprint: str | None = None
    if package.signature is not None:
        signature_verified, signer_fingerprint = _verify_detached_signature(
            manifest,
            public_key_pem=package.signature.public_key_pem,
            signature_base64=package.signature.signature_base64,
        )

    installations = bootstrap_installations(content)
    collisions = _manifest_collisions(manifest, installations)
    dependencies_satisfied = _dependencies_satisfied(manifest, installations)
    existing = _installation_by_id(installations).get(manifest.id)
    already_installed = bool(
        existing
        and any(
            item.version == manifest.version and item.manifest_sha256 == digest
            for item in existing.versions
        )
    )
    version_conflict = bool(
        existing
        and any(
            item.version == manifest.version and item.manifest_sha256 != digest
            for item in existing.versions
        )
    )
    if version_conflict:
        collisions = (*collisions, "security_pack_version_hash_conflict")
    return {
        "pack_id": manifest.id,
        "version": manifest.version,
        "manifest_sha256": digest,
        "expected_hash_matched": expected_matched,
        "signature_present": package.signature is not None,
        "signature_verified": signature_verified,
        "signer_key_fingerprint": signer_fingerprint,
        "dependencies_satisfied": dependencies_satisfied,
        "collisions": tuple(sorted(set(collisions))),
        "installable": not collisions and dependencies_satisfied and not already_installed,
    }


def install_package(
    db: Session,
    *,
    package: SecurityPackPackageInput,
    draft_revision_id: str,
    activate: bool,
    enable: bool | None,
    actor: ControlPlaneUser,
    change_summary: str,
) -> ControlPlaneConfigRevision:
    draft, content = _require_draft(db, draft_revision_id)
    validation = validate_package(package, content=content)
    if not validation["dependencies_satisfied"]:
        raise SecurityPackLifecycleError("security_pack_dependency_unsatisfied")
    if validation["collisions"]:
        raise SecurityPackLifecycleError(validation["collisions"][0])
    if not validation["installable"]:
        raise SecurityPackLifecycleError("security_pack_version_already_installed")

    manifest = package.manifest
    installations = list(bootstrap_installations(content))
    by_id = _installation_by_id(installations)
    current = by_id.get(manifest.id)
    record = SecurityPackInstalledVersion(
        version=manifest.version,
        manifest=manifest,
        manifest_sha256=validation["manifest_sha256"],
        installed_at=_utc_now(),
        signature_verified=validation["signature_verified"],
        signer_key_fingerprint=validation["signer_key_fingerprint"],
    )
    if current is None:
        next_install = SecurityPackInstallation(
            pack_id=manifest.id,
            active_version=manifest.version,
            enabled=bool(enable) if enable is not None else False,
            versions=(record,),
        )
        action = "SECURITY_PACK_INSTALLED"
        before = None
    else:
        next_install = current.model_copy(
            update={
                "versions": (*current.versions, record),
                "active_version": manifest.version if activate else current.active_version,
                "enabled": current.enabled if enable is None else bool(enable),
            }
        )
        action = "SECURITY_PACK_UPGRADED"
        before = _installation_summary(current)
    installations = [item for item in installations if item.pack_id != manifest.id]
    installations.append(next_install)
    next_content = _content_with_installations(content, installations)
    revision = patch_draft_revision(
        db,
        draft_id=draft.id,
        content=next_content,
        actor=actor,
        change_summary=change_summary,
    )
    record_control_plane_audit(
        db,
        actor=actor,
        action=action,
        target_type="security_pack",
        target_id=manifest.id,
        revision_id=revision.id,
        before_json=before,
        after_json={
            **_installation_summary(next_install),
            "installed_version": manifest.version,
            "manifest_sha256": validation["manifest_sha256"],
            "signature_verified": validation["signature_verified"],
            "signer_key_fingerprint": validation["signer_key_fingerprint"],
        },
        reason=change_summary,
    )
    return revision


def set_enabled(
    db: Session,
    *,
    pack_id: str,
    enabled: bool,
    draft_revision_id: str,
    actor: ControlPlaneUser,
    change_summary: str,
) -> ControlPlaneConfigRevision:
    draft, content = _require_draft(db, draft_revision_id)
    installations = list(bootstrap_installations(content))
    current = _require_installation(installations, pack_id)
    if current.enabled == enabled:
        raise SecurityPackLifecycleError(
            "security_pack_already_enabled" if enabled else "security_pack_already_disabled"
        )
    if not enabled:
        _assert_pack_not_referenced(content, current.active().manifest)
        _assert_not_required_by_enabled_pack(installations, pack_id)
    next_install = current.model_copy(update={"enabled": enabled})
    installations = [item for item in installations if item.pack_id != pack_id]
    installations.append(next_install)
    next_content = _content_with_installations(content, installations)
    revision = patch_draft_revision(
        db,
        draft_id=draft.id,
        content=next_content,
        actor=actor,
        change_summary=change_summary,
    )
    record_control_plane_audit(
        db,
        actor=actor,
        action="SECURITY_PACK_ENABLED" if enabled else "SECURITY_PACK_DISABLED",
        target_type="security_pack",
        target_id=pack_id,
        revision_id=revision.id,
        before_json=_installation_summary(current),
        after_json=_installation_summary(next_install),
        reason=change_summary,
    )
    return revision


def activate_version(
    db: Session,
    *,
    pack_id: str,
    version: str,
    allow_deprecated: bool,
    draft_revision_id: str,
    actor: ControlPlaneUser,
    change_summary: str,
) -> ControlPlaneConfigRevision:
    parse_security_pack_version(version)
    draft, content = _require_draft(db, draft_revision_id)
    installations = list(bootstrap_installations(content))
    current = _require_installation(installations, pack_id)
    target = next((item for item in current.versions if item.version == version), None)
    if target is None:
        raise SecurityPackLifecycleError("security_pack_version_not_installed")
    if target.deprecated and not allow_deprecated:
        raise SecurityPackLifecycleError("security_pack_version_deprecated")
    if current.active_version == version:
        raise SecurityPackLifecycleError("security_pack_version_already_active")
    rollback = parse_security_pack_version(version) < parse_security_pack_version(current.active_version)
    next_install = current.model_copy(update={"active_version": version})
    installations = [item for item in installations if item.pack_id != pack_id]
    installations.append(next_install)
    next_content = _content_with_installations(content, installations)
    revision = patch_draft_revision(
        db,
        draft_id=draft.id,
        content=next_content,
        actor=actor,
        change_summary=change_summary,
    )
    record_control_plane_audit(
        db,
        actor=actor,
        action="SECURITY_PACK_ROLLED_BACK" if rollback else "SECURITY_PACK_VERSION_ACTIVATED",
        target_type="security_pack",
        target_id=pack_id,
        revision_id=revision.id,
        before_json=_installation_summary(current),
        after_json=_installation_summary(next_install),
        reason=change_summary,
        metadata={"target_version": version, "rollback": rollback},
    )
    return revision


def set_version_deprecated(
    db: Session,
    *,
    pack_id: str,
    version: str,
    deprecated: bool,
    draft_revision_id: str,
    actor: ControlPlaneUser,
    change_summary: str,
) -> ControlPlaneConfigRevision:
    draft, content = _require_draft(db, draft_revision_id)
    installations = list(bootstrap_installations(content))
    current = _require_installation(installations, pack_id)
    found = False
    versions = []
    for item in current.versions:
        if item.version == version:
            found = True
            if item.deprecated == deprecated:
                raise SecurityPackLifecycleError(
                    "security_pack_version_already_deprecated"
                    if deprecated
                    else "security_pack_version_not_deprecated"
                )
            item = item.model_copy(update={"deprecated": deprecated})
        versions.append(item)
    if not found:
        raise SecurityPackLifecycleError("security_pack_version_not_installed")
    next_install = current.model_copy(update={"versions": tuple(versions)})
    installations = [item for item in installations if item.pack_id != pack_id]
    installations.append(next_install)
    next_content = _content_with_installations(content, installations)
    revision = patch_draft_revision(
        db,
        draft_id=draft.id,
        content=next_content,
        actor=actor,
        change_summary=change_summary,
    )
    record_control_plane_audit(
        db,
        actor=actor,
        action="SECURITY_PACK_VERSION_DEPRECATED" if deprecated else "SECURITY_PACK_VERSION_RESTORED",
        target_type="security_pack",
        target_id=pack_id,
        revision_id=revision.id,
        before_json=_installation_summary(current),
        after_json=_installation_summary(next_install),
        reason=change_summary,
        metadata={"version": version},
    )
    return revision


def remove_pack(
    db: Session,
    *,
    pack_id: str,
    draft_revision_id: str,
    actor: ControlPlaneUser,
    change_summary: str,
) -> ControlPlaneConfigRevision:
    draft, content = _require_draft(db, draft_revision_id)
    installations = list(bootstrap_installations(content))
    current = _require_installation(installations, pack_id)
    if current.enabled:
        raise SecurityPackLifecycleError("security_pack_disable_before_remove")
    _assert_pack_not_referenced(content, current.active().manifest)
    for other in installations:
        if other.pack_id == pack_id:
            continue
        if any(
            dependency.pack_id == pack_id
            for version in other.versions
            for dependency in version.manifest.dependencies
        ):
            raise SecurityPackLifecycleError("security_pack_required_by_installed_pack")
    installations = [item for item in installations if item.pack_id != pack_id]
    next_content = _content_with_installations(content, installations)
    revision = patch_draft_revision(
        db,
        draft_id=draft.id,
        content=next_content,
        actor=actor,
        change_summary=change_summary,
    )
    record_control_plane_audit(
        db,
        actor=actor,
        action="SECURITY_PACK_REMOVED",
        target_type="security_pack",
        target_id=pack_id,
        revision_id=revision.id,
        before_json=_installation_summary(current),
        after_json={"removed": True},
        reason=change_summary,
    )
    return revision


def bootstrap_installations(
    content: ControlPlaneConfigContent,
) -> tuple[SecurityPackInstallation, ...]:
    if content.security_pack_installations:
        return content.security_pack_installations
    return tuple(
        SecurityPackInstallation(
            pack_id=manifest.id,
            active_version=manifest.version,
            enabled=True,
            versions=(
                SecurityPackInstalledVersion(
                    version=manifest.version,
                    manifest=manifest,
                    manifest_sha256=security_pack_manifest_hash(manifest),
                    installed_at=None,
                    signature_verified=False,
                ),
            ),
        )
        for manifest in content.security_packs
    )


def content_with_declarative_manifest(
    content: ControlPlaneConfigContent,
    manifest: SecurityPackManifest,
) -> ControlPlaneConfigContent:
    validate_custom_manifest_safety(manifest)
    installations = list(bootstrap_installations(content))
    current = _installation_by_id(installations).get(manifest.id)
    digest = security_pack_manifest_hash(manifest)
    record = SecurityPackInstalledVersion(
        version=manifest.version,
        manifest=manifest,
        manifest_sha256=digest,
        installed_at=_utc_now(),
        signature_verified=False,
    )
    if current is None:
        next_install = SecurityPackInstallation(
            pack_id=manifest.id,
            active_version=manifest.version,
            enabled=True,
            versions=(record,),
        )
    else:
        same_version = next(
            (item for item in current.versions if item.version == manifest.version),
            None,
        )
        if same_version is not None:
            if same_version.manifest_sha256 != digest:
                raise SecurityPackLifecycleError(
                    "security_pack_version_requires_upgrade"
                )
            next_install = current
        else:
            next_install = current.model_copy(
                update={
                    "versions": (*current.versions, record),
                    "active_version": manifest.version,
                }
            )
    installations = [item for item in installations if item.pack_id != manifest.id]
    installations.append(next_install)
    return _content_with_installations(content, installations)


def _content_with_installations(
    content: ControlPlaneConfigContent,
    installations: Iterable[SecurityPackInstallation],
) -> ControlPlaneConfigContent:
    installed = tuple(sorted(installations, key=lambda item: item.pack_id))
    projection = tuple(sorted(active_lifecycle_manifests(installed), key=lambda item: item.id))
    try:
        validate_security_pack_lifecycle(projection, installed)
    except SecurityPackError as exc:
        raise SecurityPackLifecycleError(exc.code) from exc
    candidate = content.model_copy(
        update={
            "security_pack_installations": installed,
            "security_packs": projection,
        }
    )
    try:
        return validate_config_content(candidate.model_dump(mode="json"))
    except SecurityPackLifecycleError:
        raise
    except SecurityPackError as exc:
        raise SecurityPackLifecycleError(exc.code) from exc
    except Exception as exc:
        message = str(exc)
        if "unknown capability" in message.lower():
            raise SecurityPackLifecycleError("security_pack_active_capability_in_use") from exc
        if "resource type" in message.lower() or "scope" in message.lower():
            raise SecurityPackLifecycleError("security_pack_active_resource_in_use") from exc
        raise SecurityPackLifecycleError("security_pack_lifecycle_config_invalid") from exc


def _require_draft(
    db: Session,
    draft_revision_id: str,
) -> tuple[ControlPlaneConfigRevision, ControlPlaneConfigContent]:
    revision = db.get(ControlPlaneConfigRevision, draft_revision_id)
    if revision is None or revision.status != "DRAFT" or revision.schema_version != 2:
        raise SecurityPackLifecycleError("v2_draft_required")
    return revision, validate_config_content(revision.content)


def configuration_for_validation(
    db: Session,
    draft_revision_id: str | None,
) -> ControlPlaneConfigContent:
    if draft_revision_id is not None:
        return _require_draft(db, draft_revision_id)[1]
    revision = active_revision(db)
    if revision is None:
        raise SecurityPackLifecycleError("published_configuration_required")
    return validate_config_content(revision.content)


def _require_installation(
    installations: Iterable[SecurityPackInstallation],
    pack_id: str,
) -> SecurityPackInstallation:
    installation = _installation_by_id(installations).get(pack_id)
    if installation is None:
        raise SecurityPackLifecycleError("security_pack_not_installed")
    return installation


def _installation_by_id(
    installations: Iterable[SecurityPackInstallation],
) -> dict[str, SecurityPackInstallation]:
    return {item.pack_id: item for item in installations}


def validate_custom_manifest_safety(manifest: SecurityPackManifest) -> None:
    if manifest.origin != "DECLARATIVE":
        raise SecurityPackLifecycleError("custom_pack_must_be_declarative")
    registry = AdapterRegistry()
    resources = {resource.id: resource for resource in manifest.resource_types}
    for resource in manifest.resource_types:
        if resource.adapter_id == "generic-declarative":
            if (
                resource.requires_specialized_interpretation
                or resource.canonicalizer not in {"hierarchical_name", "email_address"}
            ):
                raise SecurityPackLifecycleError(
                    "declarative_pack_requires_safe_generic_adapter"
                )
            continue
        if not resource.requires_specialized_interpretation:
            raise SecurityPackLifecycleError("trusted_specialized_adapter_required")
        try:
            registry.get(resource.adapter_id)
        except SecurityModelError as exc:
            raise SecurityPackLifecycleError(
                "trusted_specialized_adapter_required"
            ) from exc
    for capability in manifest.capabilities:
        for resource_type in capability.allowed_resource_types:
            resource = resources[resource_type]
            if resource.adapter_id == "generic-declarative":
                continue
            adapter = registry.get(resource.adapter_id).manifest
            capability_supported = (
                "*" in adapter.supported_capabilities
                or capability.id in adapter.supported_capabilities
            )
            resource_supported = (
                "*" in adapter.supported_resource_types
                or resource_type in adapter.supported_resource_types
            )
            if not capability_supported or not resource_supported:
                raise SecurityPackLifecycleError(
                    "trusted_specialized_adapter_incompatible"
                )


def _manifest_collisions(
    manifest: SecurityPackManifest,
    installations: Iterable[SecurityPackInstallation],
) -> tuple[str, ...]:
    pack_ids: set[str] = set()
    capability_ids: set[str] = set()
    resource_ids: set[str] = set()
    template_ids: set[str] = set()
    for builtin in builtin_security_packs():
        pack_ids.add(builtin.id)
        capability_ids.update(item.id for item in builtin.capabilities)
        resource_ids.update(item.id for item in builtin.resource_types)
        template_ids.update(item.id for item in builtin.templates)
    for installation in installations:
        if installation.pack_id == manifest.id:
            continue
        pack_ids.add(installation.pack_id)
        for version in installation.versions:
            capability_ids.update(item.id for item in version.manifest.capabilities)
            resource_ids.update(item.id for item in version.manifest.resource_types)
            template_ids.update(item.id for item in version.manifest.templates)
    collisions: list[str] = []
    if manifest.id in {pack.id for pack in builtin_security_packs()}:
        collisions.append("builtin_security_pack_id_collision")
    if capability_ids.intersection(item.id for item in manifest.capabilities):
        collisions.append("security_pack_capability_collision")
    if resource_ids.intersection(item.id for item in manifest.resource_types):
        collisions.append("security_pack_resource_type_collision")
    if template_ids.intersection(item.id for item in manifest.templates):
        collisions.append("security_pack_template_collision")
    return tuple(collisions)


def _dependencies_satisfied(
    manifest: SecurityPackManifest,
    installations: Iterable[SecurityPackInstallation],
) -> bool:
    by_id = _installation_by_id(installations)
    builtins = {pack.id: pack for pack in builtin_security_packs()}
    for dependency in manifest.dependencies:
        builtin = builtins.get(dependency.pack_id)
        if builtin is not None:
            if not dependency.accepts(builtin.version):
                return False
            continue
        installed = by_id.get(dependency.pack_id)
        if installed is None:
            return False
        if not any(dependency.accepts(item.version) for item in installed.versions):
            return False
    return True


def _assert_pack_not_referenced(
    content: ControlPlaneConfigContent,
    manifest: SecurityPackManifest,
) -> None:
    capabilities = {item.id for item in manifest.capabilities}
    resource_types = {item.id for item in manifest.resource_types}
    if any(
        effect.capability in capabilities
        for contract in content.tool_security_contracts
        for effect in contract.effects
    ):
        raise SecurityPackLifecycleError("security_pack_referenced_by_tool_contract")
    if any(
        grant.capability in capabilities
        for subject in content.agent_authorizations.subjects.values()
        for grant in subject.grants
    ):
        raise SecurityPackLifecycleError("security_pack_referenced_by_authorization")
    if any(scope.resource_type in resource_types for scope in content.authority_resource_scopes):
        raise SecurityPackLifecycleError("security_pack_referenced_by_scope")


def _assert_not_required_by_enabled_pack(
    installations: Iterable[SecurityPackInstallation],
    pack_id: str,
) -> None:
    for installation in installations:
        if not installation.enabled or installation.pack_id == pack_id:
            continue
        if any(
            dependency.pack_id == pack_id
            for dependency in installation.active().manifest.dependencies
        ):
            raise SecurityPackLifecycleError("security_pack_required_by_enabled_pack")


def _verify_detached_signature(
    manifest: SecurityPackManifest,
    *,
    public_key_pem: str,
    signature_base64: str,
) -> tuple[bool, str]:
    try:
        key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    except Exception as exc:
        raise SecurityPackLifecycleError("security_pack_signature_public_key_invalid") from exc
    if not isinstance(key, ed25519.Ed25519PublicKey):
        raise SecurityPackLifecycleError("security_pack_signature_key_must_be_ed25519")
    try:
        signature = base64.b64decode(signature_base64, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise SecurityPackLifecycleError("security_pack_signature_encoding_invalid") from exc
    if len(signature) != 64:
        raise SecurityPackLifecycleError("security_pack_signature_length_invalid")
    try:
        key.verify(signature, canonical_json_bytes(manifest.model_dump(mode="json")))
    except InvalidSignature as exc:
        raise SecurityPackLifecycleError("security_pack_signature_invalid") from exc
    der = key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return True, hashlib.sha256(der).hexdigest()


def _installation_summary(installation: SecurityPackInstallation) -> dict[str, Any]:
    active = installation.active()
    return {
        "pack_id": installation.pack_id,
        "active_version": installation.active_version,
        "enabled": installation.enabled,
        "installed_versions": [item.version for item in installation.versions],
        "active_manifest_sha256": active.manifest_sha256,
        "active_version_deprecated": active.deprecated,
    }


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
