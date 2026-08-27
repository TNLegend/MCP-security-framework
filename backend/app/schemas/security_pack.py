from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator

from proxy.security_packs import (
    SecurityPackInstallation,
    SecurityPackManifest,
)


class TemplateSuggestionPublic(BaseModel):
    pack_id: str
    pack_version: str
    template_id: str
    title: str
    description: str
    capability: str
    capabilities: tuple[str, ...] = ()
    confidence: float = Field(ge=0, le=1)
    argument_mappings: dict[str, tuple[str, ...]]
    missing_bindings: tuple[str, ...] = ()
    semantic_categories: tuple[str, ...] = ()


class AITemplateSuggestionPublic(TemplateSuggestionPublic):
    provider: Literal["gemini", "groq"]
    fallback_used: StrictBool = False
    uncertainties: tuple[str, ...] = ()


class AISecurityPackDraftPublic(BaseModel):
    manifest: SecurityPackManifest
    provider: Literal["gemini", "groq"]
    fallback_used: StrictBool = False
    uncertainties: tuple[str, ...] = ()


class SecurityPackCatalogPublic(BaseModel):
    catalog_version: str
    resource_registry_version: str
    packs: tuple[SecurityPackManifest, ...]


class ContractScopeInput(BaseModel):
    scope_id: str = Field(min_length=1, max_length=128)
    resource_type: str | None = Field(default=None, min_length=1, max_length=128)
    canonical_value: str = Field(min_length=1, max_length=4096)
    match_mode: Literal["SELF", "SUBTREE"] = "SELF"
    broad_scope_acknowledged: StrictBool = False

    model_config = ConfigDict(extra="forbid")


class CreateToolContractDraftRequest(BaseModel):
    template_id: str = Field(min_length=1, max_length=128)
    argument_mappings: dict[str, tuple[str, ...]] = Field(default_factory=dict)
    fixed_resources: dict[str, str] = Field(default_factory=dict)
    scopes: tuple[ContractScopeInput, ...] = ()
    draft_revision_id: str | None = Field(default=None, min_length=1, max_length=64)
    approve_observations: StrictBool = False
    change_summary: str = Field(min_length=3, max_length=2000)

    model_config = ConfigDict(extra="forbid")

    @field_validator("argument_mappings")
    @classmethod
    def validate_mappings(
        cls,
        value: dict[str, tuple[str, ...]],
    ) -> dict[str, tuple[str, ...]]:
        if len(value) > 64:
            raise ValueError("too many argument mappings")
        return value


class ToolContractDraftPublic(BaseModel):
    revision_id: str
    revision_number: int
    contract_hash: str
    contract: dict
    adapter_resolutions: tuple[dict, ...]
    observation_approvals: int
    analysis_statuses: tuple[str, ...]


class AddDeclarativeSecurityPackRequest(BaseModel):
    manifest: SecurityPackManifest
    draft_revision_id: str
    change_summary: str = Field(min_length=3, max_length=2000)

    model_config = ConfigDict(extra="forbid")


class CreateToolSecurityPackDraftRequest(BaseModel):
    manifest: SecurityPackManifest
    draft_revision_id: str | None = Field(default=None, min_length=1, max_length=64)
    change_summary: str = Field(min_length=3, max_length=2000)

    model_config = ConfigDict(extra="forbid")


class ToolReanalysisPublic(BaseModel):
    tool_id: int
    revision_id: str
    analysis_statuses: tuple[str, ...]

    model_config = ConfigDict(extra="forbid")

class SecurityPackDetachedSignature(BaseModel):
    algorithm: Literal["Ed25519"] = "Ed25519"
    public_key_pem: str = Field(min_length=32, max_length=8192)
    signature_base64: str = Field(min_length=40, max_length=512)
    signer_id: str | None = Field(default=None, min_length=1, max_length=128)

    model_config = ConfigDict(extra="forbid")


class SecurityPackPackageInput(BaseModel):
    package_version: Literal["1"] = "1"
    manifest: SecurityPackManifest
    expected_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    signature: SecurityPackDetachedSignature | None = None

    model_config = ConfigDict(extra="forbid")


class ValidateSecurityPackPackageRequest(BaseModel):
    package: SecurityPackPackageInput
    draft_revision_id: str | None = Field(default=None, min_length=1, max_length=64)

    model_config = ConfigDict(extra="forbid")


class InstallSecurityPackPackageRequest(BaseModel):
    package: SecurityPackPackageInput
    draft_revision_id: str = Field(min_length=1, max_length=64)
    activate: StrictBool = True
    enable: StrictBool | None = None
    change_summary: str = Field(min_length=3, max_length=2000)

    model_config = ConfigDict(extra="forbid")


class SecurityPackLifecycleActionRequest(BaseModel):
    draft_revision_id: str = Field(min_length=1, max_length=64)
    change_summary: str = Field(min_length=3, max_length=2000)

    model_config = ConfigDict(extra="forbid")


class SecurityPackActivateVersionRequest(SecurityPackLifecycleActionRequest):
    version: str = Field(min_length=5, max_length=64)
    allow_deprecated: StrictBool = False


class SecurityPackDeprecateVersionRequest(SecurityPackLifecycleActionRequest):
    version: str = Field(min_length=5, max_length=64)
    deprecated: StrictBool = True


class SecurityPackPackageValidationPublic(BaseModel):
    pack_id: str
    version: str
    manifest_sha256: str
    expected_hash_matched: StrictBool
    signature_present: StrictBool
    signature_verified: StrictBool
    signer_key_fingerprint: str | None = None
    dependencies_satisfied: StrictBool
    collisions: tuple[str, ...] = ()
    installable: StrictBool

    model_config = ConfigDict(extra="forbid")


class SecurityPackLifecycleCatalogPublic(BaseModel):
    builtin_packs: tuple[SecurityPackManifest, ...]
    installations: tuple[SecurityPackInstallation, ...]

    model_config = ConfigDict(extra="forbid")
