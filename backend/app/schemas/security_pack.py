from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator

from proxy.security_packs import SecurityPackManifest


class TemplateSuggestionPublic(BaseModel):
    pack_id: str
    pack_version: str
    template_id: str
    title: str
    description: str
    capability: str
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
