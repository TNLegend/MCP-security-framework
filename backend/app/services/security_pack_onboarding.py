from __future__ import annotations

import json
import os
import re
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from agent.llm_providers.base import LLMProviderError
from agent.llm_providers.gemini_provider import GeminiProvider
from agent.llm_providers.groq_provider import GroqProvider
from common.project_environment import load_project_environment
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.control_plane import ControlPlaneConfigRevision, ControlPlaneUser
from app.models.mcp_server import MCPServer
from app.models.mcp_tool import MCPTool
from app.models.tool_analysis import ToolProtocolObservation
from app.schemas.control_plane import AuthorityContext, ControlPlaneConfigContent
from app.schemas.security_pack import CreateToolContractDraftRequest
from app.services.control_plane_audit import record_control_plane_audit
from app.services.control_plane_config import (
    ControlPlaneConfigError,
    active_revision,
    create_draft_from_revision,
    create_revision,
    patch_draft_revision,
)
from app.services.published_configuration import (
    PublishedConfigurationProvider,
    validate_config_content,
)
from app.services.security_pack_lifecycle import (
    SecurityPackLifecycleError,
    validate_custom_manifest_safety,
    content_with_declarative_manifest,
)
from app.services.server_security_metadata import refresh_server_security_status
from app.services.tool_analysis import (
    ToolAnalysisService,
    mark_tool_contract_pending_publication,
)
from app.services.tool_observation_approval import approve_tool_observation
from proxy.protocol_profiles import LEGACY_PROFILE_ID
from proxy.resource_adapters_v2 import AdapterRegistry
from proxy.trusted_adapter_packages import adapter_starter_catalog
from proxy.security_packs import (
    SecurityPackError,
    SecurityPackManifest,
    SecurityPackRegistry,
    ToolContractTemplate,
)
from common.mcp_endpoint import server_ref_for_server
from proxy.tool_security_v2 import (
    ArgumentConstraint,
    AuthorityResourceScope,
    FixedResourceReference,
    ReferencePrecision,
    ResourceBinding,
    ResultControl,
    ScopeMatchMode,
    SupportedSchemaProfileV1,
    ToolEffect,
    security_schema_projection,
    ToolSecurityContract,
    validate_contract_for_schema,
)


class SecurityPackOnboardingError(ValueError):
    pass


CAPABILITY_ACTION_KEYWORDS = {
    "read": ("read", "get", "list", "search", "query", "fetch", "lire", "lister", "rechercher"),
    "list": ("list", "enumerate", "browse", "lister", "enumerer"),
    "write": ("write", "create", "update", "insert", "add", "ecrire", "creer", "modifier"),
    "delete": ("delete", "remove", "drop", "supprimer", "effacer"),
    "send": ("send", "post", "upload", "envoyer", "transmettre"),
    "request": ("request", "call", "fetch", "requete", "appeler"),
    "execute": ("execute", "run", "launch", "executer", "lancer"),
    "initiate": ("pay", "payment", "transfer", "purchase", "payer", "transferer"),
    "refund": ("refund", "reimburse", "rembourser"),
}

ADAPTER_FAMILY_SIGNALS = {
    "cloud-iam": ("iam", "arn", "role", "policy", "permission", "identity"),
    "database": ("sql", "query", "database", "table", "select", "insert", "update"),
    "filesystem": ("file", "path", "directory", "folder"),
    "http-api": ("url", "http", "endpoint", "request", "webhook"),
    "messaging": ("message", "email", "channel", "recipient", "chat"),
    "payments": ("payment", "transfer", "refund", "recipient", "merchant"),
    "process": ("shell", "command", "execute", "argv", "process"),
    "source-control": ("git", "repository", "branch", "commit", "pull request"),
}


class _AISuggestion(BaseModel):
    template_id: str
    argument_mappings: dict[str, tuple[str, ...]]
    confidence: float = Field(ge=0, le=1)
    uncertainties: tuple[str, ...] = ()

    model_config = ConfigDict(extra="forbid")


class _AIPackSuggestion(BaseModel):
    pack_id: str
    title: str
    capability_id: str
    resource_type_id: str
    template_id: str
    keywords: tuple[str, ...]
    argument_hints: tuple[str, ...]
    destructive: bool = False
    external_effect: bool = False
    uncertainties: tuple[str, ...] = ()

    model_config = ConfigDict(extra="forbid")

    @field_validator("keywords", "argument_hints", "uncertainties", mode="before")
    @classmethod
    def normalize_string_sequences(cls, value, info):
        if value is None:
            return ()
        if isinstance(value, dict):
            if info.field_name != "argument_hints":
                return value
            if not all(isinstance(key, str) for key in value):
                return value
            return tuple(value)
        if isinstance(value, str):
            normalized = value.strip()
            if normalized.lower() in {"", "none", "n/a"}:
                return ()
            return (normalized,)
        return value

    @field_validator("destructive", "external_effect", mode="before")
    @classmethod
    def normalize_boolean_literals(cls, value):
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in {"true", "yes"}:
                return True
            if normalized in {"false", "no", "none", "n/a"}:
                return False
        return value


def security_pack_catalog(
    content: ControlPlaneConfigContent | None = None,
) -> dict[str, Any]:
    custom = content.security_packs if content else ()
    registry = SecurityPackRegistry(custom)
    return {
        "catalog_version": "2",
        "resource_registry_version": "2",
        "packs": registry.packs(),
    }


def suggest_templates_for_tool(
    tool: MCPTool,
    *,
    content: ControlPlaneConfigContent | None = None,
) -> list[dict[str, Any]]:
    registry = SecurityPackRegistry(
        content.security_packs if content else ()
    )
    schema_paths = _schema_paths(tool.input_schema)
    searchable = " ".join(
        (
            tool.name,
            tool.title or "",
            tool.description or "",
            " ".join(path[-1] for path in schema_paths if path),
        )
    ).lower()
    suggestions: list[dict[str, Any]] = []
    for pack, template in registry.templates():
        score = _template_score(template, searchable)
        mappings, missing = _suggest_mappings(template, schema_paths)
        if score <= 0:
            continue
        confidence = min(0.99, 0.25 + score * 0.12 + (0.2 if not missing else 0.0))
        suggestions.append(
            {
                "pack_id": pack.id,
                "pack_version": pack.version,
                "template_id": template.id,
                "title": template.title,
                "description": template.description,
                "capability": _template_primary_capability(template),
                "capabilities": _template_capabilities(template),
                "confidence": round(confidence, 2),
                "argument_mappings": mappings,
                "missing_bindings": tuple(missing),
                "semantic_categories": pack.semantic_categories,
            }
        )
    suggestions.sort(
        key=lambda value: (
            -value["confidence"],
            len(value["missing_bindings"]),
            value["template_id"],
        )
    )
    return suggestions[:8]


def adapter_guidance_for_tool(
    tool: MCPTool,
    *,
    content: ControlPlaneConfigContent | None = None,
) -> dict[str, Any]:
    schema_paths = _schema_paths(tool.input_schema)
    suggestions = suggest_templates_for_tool(tool, content=content)
    searchable = " ".join(
        (
            tool.name,
            tool.title or "",
            tool.description or "",
            " ".join(path[-1] for path in schema_paths if path),
        )
    ).lower()
    registry = AdapterRegistry(
        security_packs=content.security_packs if content else (),
    )
    closest = []
    for adapter in registry.catalog():
        if adapter["adapter_id"] == "generic-declarative":
            continue
        signals = tuple(
            signal
            for signal in ADAPTER_FAMILY_SIGNALS.get(adapter["family"], ())
            if _keyword_matches_searchable(signal, searchable)
        )
        if not signals:
            continue
        closest.append(
            {
                "adapter_id": adapter["adapter_id"],
                "display_name": adapter["display_name"],
                "family": adapter["family"],
                "implementation_version": adapter["implementation_version"],
                "matching_signals": signals,
            }
        )
    closest.sort(key=lambda item: (-len(item["matching_signals"]), item["adapter_id"]))
    if suggestions:
        reasons = (
            "Installed contract templates match the declared tool semantics.",
            "Review every mapping before creating a contract draft.",
        )
        status = "TEMPLATE_AVAILABLE"
    else:
        reasons = (
            "No installed template has corroborated semantic keywords for this tool.",
            "Generic declarative mapping is suitable only when authority-relevant resources map directly to explicit schema paths.",
            "Use a reviewed specialized adapter when a value must be parsed or canonicalized before policy evaluation.",
        )
        status = "NO_COMPATIBLE_TEMPLATE"
    recommended = closest[0]["adapter_id"] if closest else "blank"
    return {
        "status": status,
        "generic_declarative_available": True,
        "template_matches": len(suggestions),
        "reasons": reasons,
        "closest_adapters": tuple(closest[:4]),
        "recommended_starter": recommended,
        "starters": adapter_starter_catalog(),
    }


def suggest_template_with_ai(
    tool: MCPTool,
    *,
    content: ControlPlaneConfigContent | None = None,
) -> dict[str, Any]:
    load_project_environment()
    registry = SecurityPackRegistry(
        content.security_packs if content else ()
    )
    candidates = [
        {
            "template_id": template.id,
            "pack_id": pack.id,
            "capability": _template_primary_capability(template),
            "capabilities": _template_capabilities(template),
            "description": template.description,
            "effects": [
                {
                    "key": effect.key,
                    "capability": effect.capability,
                    "bindings": [
                        {
                            "key": binding.key,
                            "resource_type": binding.resource_type,
                            "required": binding.required,
                            "argument_hints": binding.argument_hints,
                        }
                        for binding in effect.bindings
                    ],
                }
                for effect in _template_effects(template)
            ],
            "bindings": [
                {
                    "key": binding.key,
                    "resource_type": binding.resource_type,
                    "required": binding.required,
                    "argument_hints": binding.argument_hints,
                }
                for binding in _template_bindings(template)
            ],
            "constraints": [
                {
                    "key": constraint.key,
                    "operator": constraint.operator,
                    "required": constraint.required,
                    "argument_hints": constraint.argument_hints,
                }
                for constraint in template.constraints
            ],
        }
        for pack, template in registry.templates()
    ]
    prompt = (
        "You assist an MCP security administrator. Select exactly one installed "
        "security template for the declared tool and map template binding keys to "
        "exact JSON Schema leaf paths. Never invent a template, binding, argument, "
        "capability, or permission. Return JSON only with template_id, "
        "argument_mappings, confidence from 0 to 1, and uncertainties. A path is an "
        "array of property tokens and uses '*' for array items. If no candidate is "
        "safe, use confidence 0 and explain why in uncertainties.\n\n"
        f"Tool: {json.dumps({'name': tool.name, 'title': tool.title, 'description': tool.description, 'input_schema': tool.input_schema}, ensure_ascii=True)}\n\n"
        f"Installed templates: {json.dumps(candidates, ensure_ascii=True)}"
    )
    primary = os.getenv("SECURITY_PACK_AI_PROVIDER", "gemini").strip().lower()
    fallback = os.getenv("SECURITY_PACK_AI_FALLBACK_PROVIDER", "groq").strip().lower()
    provider_types = {"gemini": GeminiProvider, "groq": GroqProvider}
    names = [primary]
    if fallback and fallback != primary:
        names.append(fallback)
    errors: list[str] = []
    for index, name in enumerate(names):
        provider_type = provider_types.get(name)
        if provider_type is None:
            errors.append(f"{name}: unsupported provider")
            continue
        try:
            raw = provider_type().generate_json(prompt)
            suggestion = _AISuggestion.model_validate(raw)
            pack, template = registry.template(suggestion.template_id)
            schema_paths = set(_schema_paths(tool.input_schema))
            expected_mappings = {value.key for value in _template_mapping_specs(template)}
            if set(suggestion.argument_mappings) - expected_mappings:
                raise SecurityPackOnboardingError("ai_unknown_template_binding")
            if any(path not in schema_paths for path in suggestion.argument_mappings.values()):
                raise SecurityPackOnboardingError("ai_mapping_path_not_in_schema")
            missing = tuple(
                value.key
                for value in _template_mapping_specs(template)
                if value.required and value.key not in suggestion.argument_mappings
            )
            return {
                "pack_id": pack.id,
                "pack_version": pack.version,
                "template_id": template.id,
                "title": template.title,
                "description": template.description,
                "capability": _template_primary_capability(template),
                "capabilities": _template_capabilities(template),
                "confidence": suggestion.confidence,
                "argument_mappings": suggestion.argument_mappings,
                "missing_bindings": missing,
                "semantic_categories": pack.semantic_categories,
                "provider": name,
                "fallback_used": index > 0,
                "uncertainties": suggestion.uncertainties,
            }
        except Exception as exc:
            message = str(exc) if isinstance(exc, (LLMProviderError, SecurityPackOnboardingError)) else exc.__class__.__name__
            errors.append(f"{name}: {message}")
    raise SecurityPackOnboardingError(
        "security_pack_ai_unavailable:" + "; ".join(errors)
    )


def suggest_security_pack_with_ai(
    tool: MCPTool,
    *,
    content: ControlPlaneConfigContent | None = None,
) -> dict[str, Any]:
    load_project_environment()
    registry = SecurityPackRegistry(content.security_packs if content else ())
    installed_ids = {
        "packs": [pack.id for pack in registry.packs()],
        "capabilities": [
            capability.id
            for pack in registry.packs()
            for capability in pack.capabilities
        ],
        "resource_types": [
            resource.id
            for pack in registry.packs()
            for resource in pack.resource_types
        ],
        "templates": [
            template.id
            for pack in registry.packs()
            for template in pack.templates
        ],
    }
    prompt = (
        "You assist an MCP security administrator. Propose one minimal declarative "
        "Security Pack for a tool that has no compatible installed template. Return "
        "JSON only with pack_id, title, capability_id, resource_type_id, template_id, "
        "keywords, argument_hints, destructive, external_effect, and uncertainties. "
        "keywords, argument_hints, and uncertainties must be JSON arrays of strings; "
        "destructive and external_effect must be JSON booleans true or false. "
        "Identifiers must be lowercase and capability_id must be domain.verb. Use "
        "only semantics supported by the declared tool. Do not reuse installed IDs, "
        "invent permissions beyond the tool declaration, or generate executable code. "
        "The proposal is a non-authoritative draft that an administrator must review.\n\n"
        f"Tool: {json.dumps({'name': tool.name, 'title': tool.title, 'description': tool.description, 'input_schema': tool.input_schema, 'output_schema': tool.output_schema, 'annotations': tool.annotations, 'execution': tool.execution}, ensure_ascii=True)}\n\n"
        f"Installed IDs: {json.dumps(installed_ids, ensure_ascii=True)}"
    )
    primary = os.getenv("SECURITY_PACK_AI_PROVIDER", "gemini").strip().lower()
    fallback = os.getenv("SECURITY_PACK_AI_FALLBACK_PROVIDER", "groq").strip().lower()
    provider_types = {"gemini": GeminiProvider, "groq": GroqProvider}
    names = [primary]
    if fallback and fallback != primary:
        names.append(fallback)
    errors: list[str] = []
    for index, name in enumerate(names):
        provider_type = provider_types.get(name)
        if provider_type is None:
            errors.append(f"{name}: unsupported provider")
            continue
        try:
            raw = provider_type().generate_json(prompt)
            suggestion = _AIPackSuggestion.model_validate(raw)
            manifest = _pack_manifest_from_ai_suggestion(suggestion)
            SecurityPackRegistry((*(content.security_packs if content else ()), manifest))
            return {
                "manifest": manifest,
                "provider": name,
                "fallback_used": index > 0,
                "uncertainties": suggestion.uncertainties,
            }
        except Exception as exc:
            message = str(exc) if isinstance(
                exc,
                (LLMProviderError, SecurityPackOnboardingError, SecurityPackError),
            ) else exc.__class__.__name__
            errors.append(f"{name}: {message}")
    raise SecurityPackOnboardingError(
        "security_pack_ai_unavailable:" + "; ".join(errors)
    )


def create_tool_security_pack_draft(
    db: Session,
    *,
    tool: MCPTool,
    manifest: SecurityPackManifest,
    draft_revision_id: str | None,
    actor: ControlPlaneUser,
    change_summary: str,
) -> ControlPlaneConfigRevision:
    server = db.get(MCPServer, tool.server_id)
    if server is None or server.status == "archived":
        raise SecurityPackOnboardingError("tool_server_unavailable")
    draft, _ = resolve_v2_draft(
        db,
        draft_revision_id=draft_revision_id,
        actor=actor,
        change_summary=change_summary,
    )
    revision = add_declarative_security_pack(
        db,
        draft_revision_id=draft.id,
        manifest=manifest,
        actor=actor,
        change_summary=change_summary,
    )
    record_control_plane_audit(
        db,
        actor=actor,
        action="TOOL_SECURITY_PACK_DRAFTED",
        target_type="mcp_tool",
        target_id=str(tool.id),
        revision_id=revision.id,
        after_json={"security_pack_id": manifest.id, "version": manifest.version},
        reason=change_summary,
    )
    return revision


def reanalyze_tool_with_published_contract(
    db: Session,
    *,
    tool: MCPTool,
    actor: ControlPlaneUser,
) -> dict[str, Any]:
    server = db.get(MCPServer, tool.server_id)
    if server is None or server.status == "archived":
        raise SecurityPackOnboardingError("tool_server_unavailable")
    try:
        snapshot = PublishedConfigurationProvider(db).load_active_snapshot()
        server_ref = server_ref_for_server(
            {"transport": server.transport, "endpoint": server.endpoint}
        )
        contract = snapshot.get_tool_security_contract(
            server_ref=server_ref,
            tool_name=tool.name,
        )
    except Exception as exc:
        raise SecurityPackOnboardingError("published_tool_contract_unavailable") from exc
    profile_snapshot = {
        "revision": snapshot.content_hash,
        "schema_version": 2,
        "contract_hash": contract.contract_hash,
        "contract": contract.model_dump(mode="json"),
    }
    pack = _pack_for_contract(snapshot.content, contract)
    if pack is not None:
        profile_snapshot["security_pack"] = {
            "id": pack.id,
            "version": pack.version,
            "semantic_categories": pack.semantic_categories,
        }
    profile_ids = tuple(server.supported_protocol_profiles or ()) or (
        server.preferred_upstream_profile or LEGACY_PROFILE_ID,
    )
    analysis_service = ToolAnalysisService()
    statuses = tuple(
        analysis_service.observe_and_analyze(
            db=db,
            tool=tool,
            server_ref=server_ref,
            profile_snapshot=profile_snapshot,
            upstream_protocol_profile_id=profile_id,
        ).analysis_status
        for profile_id in dict.fromkeys(value for value in profile_ids if value)
    )
    refresh_server_security_status(db, server.id)
    record_control_plane_audit(
        db,
        actor=actor,
        action="TOOL_REANALYZED_AFTER_CONFIG_PUBLISH",
        target_type="mcp_tool",
        target_id=str(tool.id),
        revision_id=snapshot.revision_id,
        after_json={"analysis_statuses": statuses},
        reason="Reanalyze tool against its published contract.",
    )
    return {
        "tool_id": tool.id,
        "revision_id": snapshot.revision_id,
        "analysis_statuses": statuses,
    }


def create_tool_contract_draft(
    db: Session,
    *,
    tool: MCPTool,
    payload: CreateToolContractDraftRequest,
    actor: ControlPlaneUser,
) -> dict[str, Any]:
    server = db.get(MCPServer, tool.server_id)
    if server is None or server.status == "archived":
        raise SecurityPackOnboardingError("tool_server_unavailable")
    draft, content = _resolve_draft(db, payload, actor)
    registry = SecurityPackRegistry(content.security_packs)
    try:
        pack, template = registry.template(payload.template_id)
    except SecurityPackError as exc:
        raise SecurityPackOnboardingError(exc.code) from exc
    schema_paths = set(_schema_paths(tool.input_schema))
    contract = _build_contract(
        tool=tool,
        server=server,
        template=template,
        mappings=payload.argument_mappings,
        fixed_resources=payload.fixed_resources,
        schema_paths=schema_paths,
    )
    adapter_registry = AdapterRegistry(
        capability_catalog_version="2",
        resource_type_registry_version="2",
        security_packs=content.security_packs,
    )
    try:
        resolutions = validate_contract_for_schema(
            contract,
            security_schema_projection(tool.input_schema or {}),
            capability_catalog=adapter_registry.capabilities,
            resource_type_registry=adapter_registry.resource_types,
            adapter_resolver=adapter_registry,
        )
    except Exception as exc:
        code = getattr(exc, "code", "contract_or_schema_invalid")
        raise SecurityPackOnboardingError(code) from exc

    contracts = [
        value
        for value in content.tool_security_contracts or ()
        if (value.server_ref, value.tool_name) != (contract.server_ref, contract.tool_name)
    ]
    contracts.append(contract)
    effect_ids = {effect.effect_id for effect in contract.effects}
    configured_resolutions = [
        value
        for value in content.adapter_resolutions or ()
        if value.effect_id not in effect_ids
    ]
    configured_resolutions.extend(resolutions)
    scopes = _merge_scopes(
        existing=content.authority_resource_scopes or (),
        requested=payload.scopes,
        authority=contract.server_ref,
        resource_types=_contract_resource_types(contract),
        registry=adapter_registry,
    )
    authority_contexts = dict(content.authority_contexts or {})
    authority_contexts.setdefault(contract.server_ref, AuthorityContext())
    next_content = content.model_copy(
        update={
            "capability_catalog_version": "2",
            "resource_type_registry_version": "2",
            "tool_security_contracts": tuple(contracts),
            "adapter_resolutions": tuple(configured_resolutions),
            "authority_resource_scopes": tuple(scopes),
            "authority_contexts": authority_contexts,
        }
    )
    draft = patch_draft_revision(
        db,
        draft_id=draft.id,
        content=next_content,
        actor=actor,
        change_summary=payload.change_summary,
    )

    profile_snapshot = {
        "revision": draft.content_hash,
        "schema_version": 2,
        "contract_hash": contract.contract_hash,
        "contract": contract.model_dump(mode="json"),
        "security_pack": {
            "id": pack.id,
            "version": pack.version,
            "semantic_categories": pack.semantic_categories,
        },
    }
    profile_ids = tuple(server.supported_protocol_profiles or ()) or (
        server.preferred_upstream_profile,
    )
    analysis_statuses: list[str] = []
    approvals = list(next_content.tool_observation_approvals or ())
    for profile_id in dict.fromkeys(value for value in profile_ids if value):
        analysis = ToolAnalysisService().observe_and_analyze(
            db=db,
            tool=tool,
            server_ref=contract.server_ref,
            profile_snapshot=profile_snapshot,
            upstream_protocol_profile_id=profile_id,
        )
        analysis_statuses.append(analysis.analysis_status)
        if not payload.approve_observations:
            continue
        observation = db.scalar(
            select(ToolProtocolObservation).where(
                ToolProtocolObservation.tool_id == tool.id,
                ToolProtocolObservation.upstream_protocol_profile_id == profile_id,
                ToolProtocolObservation.tool_fingerprint == tool.current_fingerprint,
            )
        )
        if observation is None:
            raise SecurityPackOnboardingError("tool_observation_missing")
        try:
            approval = approve_tool_observation(
                db,
                observation_id=observation.id,
                contract=contract,
                admin_id=actor.id,
                revision_id=draft.id,
            )
        except ValueError as exc:
            raise SecurityPackOnboardingError(str(exc)) from exc
        approvals = [
            value
            for value in approvals
            if not (
                value.server_ref == approval.server_ref
                and value.upstream_protocol_profile_id
                == approval.upstream_protocol_profile_id
                and value.tool_fingerprint == approval.tool_fingerprint
            )
        ]
        approvals.append(approval)

    mark_tool_contract_pending_publication(tool)
    if payload.approve_observations:
        next_content = next_content.model_copy(
            update={"tool_observation_approvals": tuple(approvals)}
        )
        draft = patch_draft_revision(
            db,
            draft_id=draft.id,
            content=next_content,
            actor=actor,
            change_summary=payload.change_summary,
        )
    contract_approval_count = sum(
        1
        for value in approvals
        if value.server_ref == contract.server_ref
        and value.contract_hash == contract.contract_hash
    )
    record_control_plane_audit(
        db,
        actor=actor,
        action="TOOL_CONTRACT_DRAFTED",
        target_type="mcp_tool",
        target_id=str(tool.id),
        revision_id=draft.id,
        after_json={
            "security_pack_id": pack.id,
            "security_pack_version": pack.version,
            "template_id": template.id,
            "contract_hash": contract.contract_hash,
            "observation_approvals": contract_approval_count,
        },
        reason=payload.change_summary,
    )
    return {
        "revision_id": draft.id,
        "revision_number": draft.revision_number,
        "contract_hash": contract.contract_hash,
        "contract": contract.model_dump(mode="json"),
        "adapter_resolutions": tuple(value.model_dump(mode="json") for value in resolutions),
        "observation_approvals": contract_approval_count,
        "analysis_statuses": tuple(analysis_statuses),
    }


def add_declarative_security_pack(
    db: Session,
    *,
    draft_revision_id: str,
    manifest: SecurityPackManifest,
    actor: ControlPlaneUser,
    change_summary: str,
) -> ControlPlaneConfigRevision:
    try:
        validate_custom_manifest_safety(manifest)
    except SecurityPackLifecycleError as exc:
        raise SecurityPackOnboardingError(exc.code) from exc
    draft = db.get(ControlPlaneConfigRevision, draft_revision_id)
    if draft is None or draft.status != "DRAFT" or draft.schema_version != 2:
        raise SecurityPackOnboardingError("v2_draft_required")
    content = validate_config_content(draft.content)
    try:
        next_content = content_with_declarative_manifest(content, manifest)
    except SecurityPackLifecycleError as exc:
        raise SecurityPackOnboardingError(exc.code) from exc
    return patch_draft_revision(
        db,
        draft_id=draft.id,
        content=next_content,
        actor=actor,
        change_summary=change_summary,
    )


def _resolve_draft(
    db: Session,
    payload: CreateToolContractDraftRequest,
    actor: ControlPlaneUser,
) -> tuple[ControlPlaneConfigRevision, ControlPlaneConfigContent]:
    return resolve_v2_draft(
        db,
        draft_revision_id=payload.draft_revision_id,
        actor=actor,
        change_summary=payload.change_summary,
    )


def resolve_v2_draft(
    db: Session,
    *,
    draft_revision_id: str | None,
    actor: ControlPlaneUser,
    change_summary: str,
) -> tuple[ControlPlaneConfigRevision, ControlPlaneConfigContent]:
    if draft_revision_id:
        draft = db.get(ControlPlaneConfigRevision, draft_revision_id)
        if draft is None or draft.status != "DRAFT":
            raise SecurityPackOnboardingError("draft_revision_required")
    else:
        draft = db.scalar(
            select(ControlPlaneConfigRevision)
            .where(ControlPlaneConfigRevision.status == "DRAFT")
            .order_by(ControlPlaneConfigRevision.revision_number.desc())
        )
        if draft is None:
            published = active_revision(db)
            if published is None:
                raise SecurityPackOnboardingError("published_configuration_required")
            draft = create_draft_from_revision(
                db,
                published_revision_id=published.id,
                actor=actor,
                change_summary=change_summary,
            )
    if draft.schema_version != 2:
        raise SecurityPackOnboardingError("v2_draft_required")
    return draft, validate_config_content(draft.content)


def _pack_manifest_from_ai_suggestion(
    suggestion: _AIPackSuggestion,
) -> SecurityPackManifest:
    if "." not in suggestion.capability_id:
        raise SecurityPackOnboardingError("ai_capability_must_be_domain_verb")
    domain, verb = suggestion.capability_id.rsplit(".", 1)
    return SecurityPackManifest.model_validate({
        "id": suggestion.pack_id,
        "version": "1.0.0",
        "title": suggestion.title,
        "description": f"{suggestion.title} security capabilities.",
        "origin": "DECLARATIVE",
        "capabilities": [{
            "id": suggestion.capability_id,
            "domain": domain,
            "verb": verb,
            "destructive": suggestion.destructive,
            "external_effect": suggestion.external_effect,
            "requires_resource": True,
            "allowed_resource_types": [suggestion.resource_type_id],
            "lifecycle": "ACTIVE",
        }],
        "resource_types": [{
            "id": suggestion.resource_type_id,
            "version": "1",
            "canonicalizer": "hierarchical_name",
            "hierarchy_support": True,
            "allowed_matching_modes": ["SELF", "SUBTREE"],
            "adapter_id": "generic-declarative",
            "requires_specialized_interpretation": False,
            "case_semantics": "authority-defined",
            "unicode_policy": "NFC-strict",
        }],
        "templates": [{
            "id": suggestion.template_id,
            "title": suggestion.title,
            "description": f"Govern {suggestion.capability_id} tools.",
            "capability": suggestion.capability_id,
            "keywords": suggestion.keywords,
            "bindings": [{
                "key": "resource",
                "resource_type": suggestion.resource_type_id,
                "required": True,
                "multiple": False,
                "argument_hints": suggestion.argument_hints,
            }],
            "max_resource_cardinality": 100,
            "declared_reference_precision": "EXPLICIT",
        }],
        "semantic_categories": [],
    })


def _pack_for_contract(
    content: ControlPlaneConfigContent,
    contract: ToolSecurityContract,
) -> SecurityPackManifest | None:
    capabilities = {effect.capability for effect in contract.effects}
    registry = SecurityPackRegistry(content.security_packs)
    return next(
        (
            pack
            for pack in registry.packs()
            if capabilities.intersection(
                capability.id for capability in pack.capabilities
            )
        ),
        None,
    )


def _template_effects(template: ToolContractTemplate):
    return template.resolved_effects()


def _template_bindings(template: ToolContractTemplate):
    return tuple(
        binding
        for effect in _template_effects(template)
        for binding in effect.bindings
    )


def _template_mapping_specs(template: ToolContractTemplate):
    return (*_template_bindings(template), *template.constraints)


def _template_capabilities(template: ToolContractTemplate) -> tuple[str, ...]:
    return tuple(effect.capability for effect in _template_effects(template))


def _template_primary_capability(template: ToolContractTemplate) -> str:
    return _template_capabilities(template)[0]


def _build_contract(
    *,
    tool: MCPTool,
    server: MCPServer,
    template: ToolContractTemplate,
    mappings: dict[str, tuple[str, ...]],
    fixed_resources: dict[str, str],
    schema_paths: set[tuple[str, ...]],
) -> ToolSecurityContract:
    template_effects = _template_effects(template)
    resource_keys = {binding.key for binding in _template_bindings(template)}
    mapping_keys = {value.key for value in _template_mapping_specs(template)}
    if set(mappings) - mapping_keys or set(fixed_resources) - resource_keys:
        raise SecurityPackOnboardingError("unknown_template_binding")

    bound_paths: set[tuple[str, ...]] = set()
    effects: list[ToolEffect] = []
    for template_effect in template_effects:
        resource_bindings: list[ResourceBinding] = []
        fixed_resource: FixedResourceReference | None = None
        effect_fixed_keys: list[str] = []
        for binding in template_effect.bindings:
            path = mappings.get(binding.key)
            fixed = fixed_resources.get(binding.key)
            if path and fixed:
                raise SecurityPackOnboardingError("binding_resource_source_ambiguous")
            if path:
                if path not in schema_paths:
                    raise SecurityPackOnboardingError("contract_path_not_in_schema")
                resource_bindings.append(
                    ResourceBinding(
                        path=path,
                        resource_type=binding.resource_type,
                        role=binding.role,
                    )
                )
                bound_paths.add(path)
            elif fixed:
                effect_fixed_keys.append(binding.key)
                fixed_resource = FixedResourceReference(
                    resource_type=binding.resource_type,
                    canonical_value=fixed,
                    role=binding.role,
                )
            elif binding.required:
                raise SecurityPackOnboardingError("required_template_binding_missing")

        if effect_fixed_keys and (
            len(effect_fixed_keys) != 1
            or resource_bindings
            or len(template_effect.bindings) != 1
        ):
            raise SecurityPackOnboardingError("fixed_resource_multi_binding_unsupported")

        if template.effects:
            effect_id = f"tool-{tool.id}.{template_effect.key}"
        else:
            effect_id = f"tool-{tool.id}.{template_effect.capability}"
        effects.append(
            ToolEffect(
                effect_id=effect_id,
                capability=template_effect.capability,
                resource_bindings=tuple(resource_bindings),
                fixed_resource=fixed_resource,
                max_resource_cardinality=template_effect.max_resource_cardinality,
                declared_reference_precision=ReferencePrecision(
                    template_effect.declared_reference_precision
                ),
            )
        )

    argument_constraints: list[ArgumentConstraint] = []
    for constraint in template.constraints:
        path = mappings.get(constraint.key)
        if path is None:
            if constraint.required:
                raise SecurityPackOnboardingError("required_template_constraint_missing")
            continue
        if path not in schema_paths:
            raise SecurityPackOnboardingError("contract_path_not_in_schema")
        argument_constraints.append(
            ArgumentConstraint(
                constraint_id=f"tool-{tool.id}.{constraint.key}",
                path=path,
                operator=constraint.operator,
                value=constraint.value,
                required=constraint.required,
            )
        )

    unbound = tuple(sorted(schema_paths - bound_paths))
    return ToolSecurityContract(
        server_ref=server_ref_for_server(
            {"transport": server.transport, "endpoint": server.endpoint}
        ),
        tool_name=tool.name,
        effects=tuple(effects),
        argument_constraints=tuple(argument_constraints),
        result_control=ResultControl(**template.result_control.model_dump()),
        unbound_arguments=unbound,
    )


def _merge_scopes(
    *,
    existing: tuple[AuthorityResourceScope, ...],
    requested,
    authority: str,
    resource_types: tuple[str, ...],
    registry: AdapterRegistry,
) -> list[AuthorityResourceScope]:
    scopes = list(existing)
    if not requested:
        return scopes
    unique_resource_types = tuple(dict.fromkeys(resource_types))
    if not unique_resource_types:
        raise SecurityPackOnboardingError("scope_resource_type_unavailable")
    for value in requested:
        resource_type = value.resource_type
        if resource_type is None:
            if len(unique_resource_types) != 1:
                raise SecurityPackOnboardingError("scope_resource_type_ambiguous")
            resource_type = unique_resource_types[0]
        elif resource_type not in unique_resource_types:
            raise SecurityPackOnboardingError("scope_resource_type_not_in_contract")
        candidate = AuthorityResourceScope(
            scope_id=value.scope_id,
            authority=authority,
            resource_type=resource_type,
            canonical_value=value.canonical_value,
            match_mode=ScopeMatchMode(value.match_mode),
            broad_scope_acknowledged=value.broad_scope_acknowledged,
        )
        canonical, _ = registry.resource_types.canonicalize(
            resource_type,
            candidate.canonical_value,
            AuthorityContext().model_dump(mode="json"),
        )
        candidate = candidate.model_copy(update={"canonical_value": canonical})
        scopes = [scope for scope in scopes if scope.scope_id != candidate.scope_id]
        scopes.append(candidate)
    return scopes


def _contract_resource_types(contract: ToolSecurityContract) -> tuple[str, ...]:
    return tuple(
        binding.resource_type
        for effect in contract.effects
        for binding in effect.resource_bindings
    ) + tuple(
        effect.fixed_resource.resource_type
        for effect in contract.effects
        if effect.fixed_resource is not None
    )


def _schema_paths(schema: dict[str, Any] | None) -> tuple[tuple[str, ...], ...]:
    try:
        return SupportedSchemaProfileV1.validate(
            security_schema_projection(schema or {})
        )
    except Exception as exc:
        code = getattr(exc, "code", "schema_construct_unsupported")
        raise SecurityPackOnboardingError(code) from exc


def _keyword_matches_searchable(keyword: str, searchable: str) -> bool:
    normalized = keyword.lower()
    if re.search(
        rf"(?<![a-z0-9]){re.escape(normalized)}(?![a-z0-9])",
        searchable,
    ):
        return True
    if " " in normalized or not normalized.isalpha() or len(normalized) < 3:
        return False
    plural_forms = {f"{normalized}s", f"{normalized}es"}
    if normalized.endswith("y") and len(normalized) > 1:
        plural_forms.add(f"{normalized[:-1]}ies")
    return any(
        re.search(rf"(?<![a-z0-9]){re.escape(form)}(?![a-z0-9])", searchable)
        for form in plural_forms
    )


def _template_score(template: ToolContractTemplate, searchable: str) -> int:
    verbs = {
        effect.capability.rsplit(".", 1)[-1]
        for effect in _template_effects(template)
    }
    action_keywords = {
        keyword
        for verb in verbs
        for keyword in CAPABILITY_ACTION_KEYWORDS.get(verb, ())
    }
    matched_keywords = tuple(
        keyword
        for keyword in template.keywords
        if _keyword_matches_searchable(keyword, searchable)
    )
    semantic_matches = tuple(
        keyword
        for keyword in matched_keywords
        if " " in keyword or keyword.lower() not in action_keywords
    )
    if not semantic_matches:
        return 0
    keyword_score = sum(
        2 if " " in keyword else 1
        for keyword in matched_keywords
    )
    action_score = sum(
        2
        for keyword in action_keywords
        if _keyword_matches_searchable(keyword, searchable)
    )
    return keyword_score + action_score


def _suggest_mappings(
    template: ToolContractTemplate,
    paths: tuple[tuple[str, ...], ...],
) -> tuple[dict[str, tuple[str, ...]], list[str]]:
    mappings: dict[str, tuple[str, ...]] = {}
    missing: list[str] = []
    used_resource_paths: set[tuple[str, ...]] = set()

    def ranked_paths(hints, *, exclude: set[tuple[str, ...]]):
        return sorted(
            (
                (
                    max(
                        (
                            2 if path[-1].lower() == hint.lower() else 1
                            for hint in hints
                            if hint.lower() in path[-1].lower()
                        ),
                        default=0,
                    ),
                    path,
                )
                for path in paths
                if path not in exclude and path
            ),
            key=lambda value: (-value[0], value[1]),
        )

    for binding in _template_bindings(template):
        ranked = ranked_paths(binding.argument_hints, exclude=used_resource_paths)
        if ranked and ranked[0][0] > 0:
            mappings[binding.key] = ranked[0][1]
            used_resource_paths.add(ranked[0][1])
        elif binding.required:
            missing.append(binding.key)

    for constraint in template.constraints:
        ranked = ranked_paths(constraint.argument_hints, exclude=set())
        if ranked and ranked[0][0] > 0:
            mappings[constraint.key] = ranked[0][1]
        elif constraint.required:
            missing.append(constraint.key)

    return mappings, missing
