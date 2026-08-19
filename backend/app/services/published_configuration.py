from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from sqlalchemy.orm import Session
from sqlalchemy import func, select

from common.canonical_json import sha256_canonical_json

from app.db.database import SessionLocal
from app.models.control_plane import ControlPlaneConfigRevision, ControlPlaneState
from app.schemas.control_plane import ControlPlaneConfigContent
from app.services.subject_authorization import (
    ResolvedCapabilityGrant,
    ResolvedSubjectAuthorization,
)
from app.services.revision_signing import (
    RevisionSignatureError,
    revision_signature_payload,
    verify_revision_payload,
)
from proxy.identity_binding import IdentityBindingError, ResolvedIdentityBinding
from proxy.resource_registry import (
    ResourceRegistry,
    ResourceRegistryError,
    ResolvedFilesystemScope,
)
from proxy.tool_security_profiles import (
    ResolvedToolSecurityProfile,
    ToolSecurityProfileError,
)
from proxy.tool_security_v2 import (
    AdapterResolution,
    AuthorityResourceScope,
    CapabilityCatalog,
    ResourceTypeRegistry,
    ToolObservationApproval,
    ToolSecurityContract,
    validate_scope,
)


class PublishedConfigurationError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class ActiveRevisionMetadata:
    revision_id: str
    revision_number: int
    content_hash: str


@dataclass(frozen=True)
class PublishedConfigurationSnapshot:
    revision_id: str
    revision_number: int
    content_hash: str
    schema_version: int
    content: ControlPlaneConfigContent

    def active_revision_metadata(self) -> ActiveRevisionMetadata:
        return ActiveRevisionMetadata(
            revision_id=self.revision_id,
            revision_number=self.revision_number,
            content_hash=self.content_hash,
        )

    def get_identity_binding(self, *, issuer: str, subject: str) -> ResolvedIdentityBinding:
        for binding in self.content.identity_bindings.bindings:
            if binding.issuer == issuer and binding.subject == subject:
                return ResolvedIdentityBinding(
                    agent_id=binding.agent_id,
                    revision=self.content_hash,
                )
        raise IdentityBindingError("agent_identity_binding_not_found")

    def resolve(self, **kwargs: Any) -> ResolvedIdentityBinding | ResolvedToolSecurityProfile:
        if "issuer" in kwargs and "subject" in kwargs:
            return self.get_identity_binding(
                issuer=kwargs["issuer"],
                subject=kwargs["subject"],
            )
        if "server_ref" in kwargs and "tool_name" in kwargs:
            return self.get_tool_security_profile(
                server_ref=kwargs["server_ref"],
                tool_name=kwargs["tool_name"],
            )
        raise TypeError("unsupported published configuration resolution")

    def get_agent_authorization(self, agent_id: str) -> ResolvedSubjectAuthorization:
        profile = self.content.agent_authorizations.subjects.get(agent_id)
        if profile is None:
            return ResolvedSubjectAuthorization(
                agent_id=agent_id,
                role="unknown",
                authorization_status="unknown",
                authorization_revision=self.content_hash,
                grants=(),
                allowed_capabilities=(),
                allowed_scopes=(),
            )
        grants = tuple(
            ResolvedCapabilityGrant(
                capability=grant.capability,
                scopes=tuple(grant.scopes),
            )
            for grant in profile.grants
        )
        return ResolvedSubjectAuthorization(
            agent_id=agent_id,
            role=profile.role,
            authorization_status="resolved",
            authorization_revision=self.content_hash,
            grants=grants,
            allowed_capabilities=tuple(grant.capability for grant in grants),
            allowed_scopes=tuple(
                dict.fromkeys(scope for grant in grants for scope in grant.scopes)
            ),
        )

    def get_tool_security_profile(
        self,
        *,
        server_ref: str,
        tool_name: str,
    ) -> ResolvedToolSecurityProfile:
        if self.schema_version != 1 or self.content.tool_security_profiles is None:
            raise ToolSecurityProfileError("legacy_tool_security_profile_unavailable")
        for binding in self.content.tool_security_profiles.bindings:
            if binding.server_ref == server_ref and binding.tool_name == tool_name:
                return ResolvedToolSecurityProfile(
                    revision=self.content_hash,
                    server_ref=binding.server_ref,
                    tool_name=binding.tool_name,
                    operation=binding.operation,
                    required_capability=binding.required_capability,
                    resource=binding.resource,
                )
        raise ToolSecurityProfileError("unknown_tool_security_profile")

    def get_resource_registry(self) -> ResourceRegistry:
        if self.schema_version != 1 or self.content.resource_scopes is None:
            raise ResourceRegistryError("legacy_resource_registry_unavailable")
        resolved_scopes: dict[str, ResolvedFilesystemScope] = {}
        for scope_id, scope in self.content.resource_scopes.filesystem_scopes.items():
            raw_root = os.getenv(scope.root_env)
            if not isinstance(raw_root, str) or not raw_root.strip():
                raise ResourceRegistryError("resource_registry_unavailable")
            root = Path(raw_root)
            if not _is_absolute_path(raw_root, root):
                raise ResourceRegistryError("resource_registry_unavailable")
            try:
                root_resolved = root.resolve(strict=True)
            except OSError as exc:
                raise ResourceRegistryError("resource_registry_unavailable") from exc
            if not root_resolved.is_dir():
                raise ResourceRegistryError("resource_registry_unavailable")
            resolved_scopes[scope_id] = ResolvedFilesystemScope(
                scope_id=scope_id,
                root=root,
                root_resolved=root_resolved,
                allowed_operations=tuple(scope.allowed_operations),
                sensitivity=scope.sensitivity,
                symlink_policy=scope.symlink_policy,
                denied_patterns=tuple(scope.denied_patterns),
            )
        return ResourceRegistry(
            revision=self.content_hash,
            filesystem_scopes=resolved_scopes,
        )

    def load(self) -> ResourceRegistry:
        return self.get_resource_registry()

    def get_policy_settings(self) -> dict[str, Any]:
        return self.content.policy_settings.model_dump(mode="json")

    def get_tool_security_contract(
        self,
        *,
        server_ref: str,
        tool_name: str,
    ) -> ToolSecurityContract:
        if self.schema_version != 2 or self.content.tool_security_contracts is None:
            raise PublishedConfigurationError("tool_security_contract_unavailable")
        matches = [
            contract
            for contract in self.content.tool_security_contracts
            if contract.server_ref == server_ref and contract.tool_name == tool_name
        ]
        if len(matches) != 1:
            raise PublishedConfigurationError("tool_security_contract_missing_or_ambiguous")
        return matches[0]

    def get_authority_resource_scopes(self) -> tuple[AuthorityResourceScope, ...]:
        if self.schema_version != 2 or self.content.authority_resource_scopes is None:
            raise PublishedConfigurationError("authority_resource_scopes_unavailable")
        return self.content.authority_resource_scopes

    def get_adapter_resolutions(self, *, effect_id: str) -> tuple[AdapterResolution, ...]:
        if self.schema_version != 2 or self.content.adapter_resolutions is None:
            raise PublishedConfigurationError("adapter_resolutions_unavailable")
        return tuple(
            resolution
            for resolution in self.content.adapter_resolutions
            if resolution.effect_id == effect_id
        )

    def get_tool_observation_approval(
        self,
        *,
        server_ref: str,
        upstream_protocol_profile_id: str,
        tool_fingerprint: str,
    ) -> ToolObservationApproval:
        approvals = self.content.tool_observation_approvals
        if self.schema_version != 2 or approvals is None:
            raise PublishedConfigurationError("tool_observation_approval_unavailable")
        matches = [
            approval
            for approval in approvals
            if approval.server_ref == server_ref
            and approval.upstream_protocol_profile_id == upstream_protocol_profile_id
            and approval.tool_fingerprint == tool_fingerprint
        ]
        if len(matches) != 1:
            raise PublishedConfigurationError("tool_observation_approval_missing_or_ambiguous")
        return matches[0]

    def get_authority_context(self, authority: str) -> dict[str, Any]:
        contexts = self.content.authority_contexts
        if self.schema_version != 2 or contexts is None or authority not in contexts:
            raise PublishedConfigurationError("authority_context_unavailable")
        return contexts[authority].model_dump(mode="json")


def config_content_hash(content: dict[str, Any]) -> str:
    return sha256_canonical_json(content)


def _content_model_to_json(content: ControlPlaneConfigContent) -> dict[str, Any]:
    return content.model_dump(mode="json")


def validate_config_content(content: dict[str, Any]) -> ControlPlaneConfigContent:
    model = ControlPlaneConfigContent.model_validate(content)
    _validate_cross_references(model)
    return model


class PublishedConfigurationProvider:
    def __init__(self, db: Session) -> None:
        self.db = db

    def active_revision_metadata(self) -> ActiveRevisionMetadata:
        return self.load_active_snapshot().active_revision_metadata()

    def load_active_snapshot(self) -> PublishedConfigurationSnapshot:
        state = self.db.get(ControlPlaneState, 1)
        if state is None or state.active_revision_id is None:
            raise PublishedConfigurationError("active_config_missing")
        revision = self.db.get(ControlPlaneConfigRevision, state.active_revision_id)
        if revision is not None:
            latest_activated_number = self.db.scalar(
                select(func.max(ControlPlaneConfigRevision.revision_number)).where(
                    ControlPlaneConfigRevision.status.in_({"PUBLISHED", "ARCHIVED"})
                )
            )
            if (
                latest_activated_number is not None
                and revision.revision_number != latest_activated_number
            ):
                raise PublishedConfigurationError("active_config_rollback_detected")
        return self._snapshot_from_revision(revision, allowed_statuses={"PUBLISHED"})

    def load_snapshot(
        self,
        revision_id: str,
        *,
        expected_content_hash: str | None = None,
        allow_archived: bool = False,
    ) -> PublishedConfigurationSnapshot:
        revision = self.db.get(ControlPlaneConfigRevision, revision_id)
        allowed_statuses = {"PUBLISHED", "ARCHIVED"} if allow_archived else {"PUBLISHED"}
        snapshot = self._snapshot_from_revision(revision, allowed_statuses=allowed_statuses)
        if (
            expected_content_hash is not None
            and snapshot.content_hash != expected_content_hash
        ):
            raise PublishedConfigurationError("snapshot_hash_mismatch")
        return snapshot

    def get_identity_binding(self, *, issuer: str, subject: str) -> ResolvedIdentityBinding:
        return self.load_active_snapshot().get_identity_binding(
            issuer=issuer,
            subject=subject,
        )

    def get_agent_authorization(self, agent_id: str) -> ResolvedSubjectAuthorization:
        return self.load_active_snapshot().get_agent_authorization(agent_id)

    def get_tool_security_profile(
        self,
        *,
        server_ref: str,
        tool_name: str,
    ) -> ResolvedToolSecurityProfile:
        return self.load_active_snapshot().get_tool_security_profile(
            server_ref=server_ref,
            tool_name=tool_name,
        )

    def get_resource_registry(self) -> ResourceRegistry:
        return self.load_active_snapshot().get_resource_registry()

    def get_policy_settings(self) -> dict[str, Any]:
        return self.load_active_snapshot().get_policy_settings()

    def _snapshot_from_revision(
        self,
        revision: ControlPlaneConfigRevision | None,
        *,
        allowed_statuses: set[str],
    ) -> PublishedConfigurationSnapshot:
        if revision is None:
            raise PublishedConfigurationError("active_config_revision_missing")
        if revision.status not in allowed_statuses:
            raise PublishedConfigurationError("active_config_not_published")
        try:
            expected_hash = config_content_hash(revision.content)
        except Exception as exc:
            raise PublishedConfigurationError("config_hash_invalid") from exc
        if expected_hash != revision.content_hash:
            raise PublishedConfigurationError("config_hash_mismatch")
        try:
            content = validate_config_content(revision.content)
        except Exception as exc:
            raise PublishedConfigurationError("config_invalid") from exc
        if revision.schema_version != content.schema_version:
            raise PublishedConfigurationError("config_schema_version_mismatch")
        if revision.schema_version == 2:
            self._verify_v2_revision(revision)
        return PublishedConfigurationSnapshot(
            revision_id=revision.id,
            revision_number=revision.revision_number,
            content_hash=revision.content_hash,
            schema_version=revision.schema_version,
            content=content,
        )

    def _verify_v2_revision(
        self,
        revision: ControlPlaneConfigRevision,
        *,
        seen: set[str] | None = None,
    ) -> None:
        chain_seen = seen or set()
        if revision.id in chain_seen:
            raise PublishedConfigurationError("revision_chain_cycle")
        chain_seen.add(revision.id)
        required = (
            revision.previous_revision_hash,
            revision.signature,
            revision.signature_key_id,
            revision.signature_algorithm,
            revision.signature_version,
        )
        if not all(isinstance(value, str) and value for value in required):
            raise PublishedConfigurationError("revision_signature_missing")
        payload = revision_signature_payload(
            revision_id=revision.id,
            revision_number=revision.revision_number,
            schema_version=revision.schema_version,
            content_hash=revision.content_hash,
            previous_revision_hash=revision.previous_revision_hash,
        )
        try:
            verify_revision_payload(
                payload,
                signature=revision.signature,
                key_id=revision.signature_key_id,
                algorithm=revision.signature_algorithm,
                version=revision.signature_version,
            )
        except RevisionSignatureError as exc:
            raise PublishedConfigurationError(exc.code) from exc
        if revision.previous_revision_hash == "0" * 64:
            return
        predecessor = self.db.scalar(
            select(ControlPlaneConfigRevision).where(
                ControlPlaneConfigRevision.content_hash == revision.previous_revision_hash,
                ControlPlaneConfigRevision.revision_number < revision.revision_number,
            ).order_by(ControlPlaneConfigRevision.revision_number.desc())
        )
        if predecessor is None:
            raise PublishedConfigurationError("revision_chain_predecessor_missing")
        try:
            predecessor_hash = config_content_hash(predecessor.content)
        except Exception as exc:
            raise PublishedConfigurationError("revision_chain_predecessor_invalid") from exc
        if predecessor_hash != predecessor.content_hash:
            raise PublishedConfigurationError("revision_chain_predecessor_hash_mismatch")
        if predecessor.schema_version == 2:
            self._verify_v2_revision(predecessor, seen=chain_seen)


class PublishedConfigurationSnapshotResolver:
    def load_active_snapshot(self) -> PublishedConfigurationSnapshot:
        with SessionLocal() as db:
            return PublishedConfigurationProvider(db).load_active_snapshot()


class PublishedIdentityBindingResolver:
    def resolve(self, *, issuer: str, subject: str) -> ResolvedIdentityBinding:
        try:
            with SessionLocal() as db:
                return PublishedConfigurationProvider(db).get_identity_binding(
                    issuer=issuer,
                    subject=subject,
                )
        except IdentityBindingError:
            raise
        except Exception as exc:
            raise IdentityBindingError("agent_identity_binding_unavailable") from exc


class PublishedToolSecurityProfileResolver:
    def resolve(
        self,
        *,
        server_ref: str,
        tool_name: str,
    ) -> ResolvedToolSecurityProfile:
        try:
            with SessionLocal() as db:
                return PublishedConfigurationProvider(db).get_tool_security_profile(
                    server_ref=server_ref,
                    tool_name=tool_name,
                )
        except ToolSecurityProfileError:
            raise
        except Exception as exc:
            raise ToolSecurityProfileError("tool_security_profile_unavailable") from exc


class PublishedResourceRegistryResolver:
    def load(self) -> ResourceRegistry:
        try:
            with SessionLocal() as db:
                return PublishedConfigurationProvider(db).get_resource_registry()
        except ResourceRegistryError:
            raise
        except Exception as exc:
            raise ResourceRegistryError("resource_registry_unavailable") from exc


class PublishedSubjectAuthorizationResolver:
    def __init__(self, db: Session) -> None:
        self.db = db

    def resolve(self, agent_id: str) -> ResolvedSubjectAuthorization:
        try:
            return PublishedConfigurationProvider(self.db).get_agent_authorization(agent_id)
        except Exception as exc:
            from app.services.subject_authorization import SubjectAuthorizationError

            raise SubjectAuthorizationError("subject_authorization_unavailable") from exc


def _validate_cross_references(content: ControlPlaneConfigContent) -> None:
    known_agents = set(content.agent_authorizations.subjects)
    for binding in content.identity_bindings.bindings:
        if binding.agent_id not in known_agents:
            raise ValueError("identity binding references unknown agent.")

    if content.schema_version == 2:
        _validate_v2_cross_references(content)
        return

    if content.resource_scopes is None or content.tool_security_profiles is None:
        raise ValueError("legacy administrative documents are missing.")
    known_scopes = set(content.resource_scopes.filesystem_scopes)
    known_capabilities = {
        grant.capability
        for profile in content.agent_authorizations.subjects.values()
        for grant in profile.grants
    }
    for profile in content.agent_authorizations.subjects.values():
        for grant in profile.grants:
            for scope in grant.scopes:
                if scope not in known_scopes:
                    raise ValueError("authorization references unknown scope.")
    for binding in content.tool_security_profiles.bindings:
        if binding.required_capability not in known_capabilities:
            raise ValueError("tool profile references unknown capability.")
        resource = binding.resource
        referenced_scopes = set(resource.allowed_scope_candidates)
        if resource.relative_base_scope:
            referenced_scopes.add(resource.relative_base_scope)
        if not referenced_scopes <= known_scopes:
            raise ValueError("tool profile references unknown resource scope.")


def _validate_v2_cross_references(content: ControlPlaneConfigContent) -> None:
    contracts = content.tool_security_contracts or ()
    scopes = content.authority_resource_scopes or ()
    resolutions = content.adapter_resolutions or ()
    approvals = content.tool_observation_approvals or ()
    authority_contexts = content.authority_contexts or {}
    catalog = CapabilityCatalog()
    type_registry = ResourceTypeRegistry()

    contract_keys = [(contract.server_ref, contract.tool_name) for contract in contracts]
    if len(contract_keys) != len(set(contract_keys)):
        raise ValueError("duplicate v2 tool security contract.")
    effect_ids = [effect.effect_id for contract in contracts for effect in contract.effects]
    if len(effect_ids) != len(set(effect_ids)):
        raise ValueError("v2 effect ids must be globally unique within a revision.")
    scope_ids = [scope.scope_id for scope in scopes]
    if len(scope_ids) != len(set(scope_ids)):
        raise ValueError("duplicate authority resource scope.")
    approval_keys = [
        (
            approval.server_ref,
            approval.upstream_protocol_profile_id,
            approval.tool_fingerprint,
        )
        for approval in approvals
    ]
    if len(approval_keys) != len(set(approval_keys)):
        raise ValueError("duplicate profile-specific tool approval.")

    known_scopes = set(scope_ids)
    for profile in content.agent_authorizations.subjects.values():
        for grant in profile.grants:
            catalog.get(grant.capability)
            if not set(grant.scopes) <= known_scopes:
                raise ValueError("authorization references unknown v2 scope.")

    for scope in scopes:
        if scope.authority not in authority_contexts:
            raise ValueError("scope references unknown authority context.")
        validated_scope = validate_scope(
            scope,
            registry=type_registry,
            authority_config=authority_contexts[scope.authority].model_dump(mode="json"),
        )
        if validated_scope != scope:
            raise ValueError("scope value must already be canonical.")

    resolution_keys = [
        (resolution.effect_id, resolution.resource_type) for resolution in resolutions
    ]
    if len(resolution_keys) != len(set(resolution_keys)):
        raise ValueError("duplicate adapter resolution.")
    known_effects = {
        (effect.effect_id, binding.resource_type)
        for contract in contracts
        for effect in contract.effects
        for binding in effect.resource_bindings
    }
    if set(resolution_keys) != known_effects:
        raise ValueError("adapter resolutions do not exactly cover contract bindings.")
    for contract in contracts:
        for effect in contract.effects:
            catalog.get(effect.capability)
    contract_hashes = {contract.contract_hash for contract in contracts}
    if any(approval.contract_hash not in contract_hashes for approval in approvals):
        raise ValueError("approval references unknown contract hash.")


def _is_absolute_path(raw_value: str, path: Path) -> bool:
    return (
        path.is_absolute()
        or PureWindowsPath(raw_value).is_absolute()
        or PurePosixPath(raw_value).is_absolute()
    )


def content_model_to_json(content: ControlPlaneConfigContent) -> dict[str, Any]:
    return _content_model_to_json(content)
