from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.control_plane import ControlPlaneConfigRevision, ControlPlaneUser
from app.models.mcp_server import MCPServer
from app.models.mcp_tool import MCPTool
from app.schemas.control_plane import AuthorityContext, ControlPlaneConfigContent
from app.services.control_plane_config import ControlPlaneConfigError, create_revision
from app.services.published_configuration import validate_config_content
from proxy.resource_adapters_v2 import AdapterRegistry
from proxy.tool_security_profiles import server_ref_for_server
from proxy.tool_security_v2 import (
    AdapterResolution,
    AuthorityResourceScope,
    ResourceBinding,
    ScopeMatchMode,
    ToolEffect,
    ToolSecurityContract,
    validate_contract_for_schema,
)


def create_v2_migration_draft(
    db: Session,
    *,
    source_revision_id: str,
    actor: ControlPlaneUser,
    change_summary: str,
) -> ControlPlaneConfigRevision:
    source = db.get(ControlPlaneConfigRevision, source_revision_id)
    if source is None:
        raise ControlPlaneConfigError("migration_source_missing")
    if source.schema_version != 1 or source.status not in {"PUBLISHED", "ARCHIVED"}:
        raise ControlPlaneConfigError("migration_source_must_be_published_v1")
    old = validate_config_content(source.content)
    if old.tool_security_profiles is None or old.resource_scopes is None:
        raise ControlPlaneConfigError("migration_source_invalid")

    servers = db.scalars(select(MCPServer)).all()
    server_by_ref = {
        server_ref_for_server(
            {
                "server_ref": getattr(server, "server_ref", None),
                "transport": server.transport,
                "endpoint": server.endpoint,
            }
        ): server
        for server in servers
    }
    tools = db.scalars(select(MCPTool)).all()
    tool_by_key = {(tool.server_id, tool.name): tool for tool in tools}

    contracts: list[ToolSecurityContract] = []
    resolutions: list[AdapterResolution] = []
    scope_authorities: dict[str, str] = {}
    for binding in old.tool_security_profiles.bindings:
        server = server_by_ref.get(binding.server_ref)
        if server is None:
            raise ControlPlaneConfigError("migration_server_inventory_missing")
        tool = tool_by_key.get((server.id, binding.tool_name))
        if tool is None or not isinstance(tool.input_schema, dict):
            raise ControlPlaneConfigError("migration_tool_schema_missing")
        contract = ToolSecurityContract(
            server_ref=binding.server_ref,
            tool_name=binding.tool_name,
            effects=(
                ToolEffect(
                    effect_id=f"{binding.tool_name}.{binding.operation}",
                    capability=binding.required_capability,
                    resource_bindings=(
                        ResourceBinding(
                            path=(binding.resource.argument_name,),
                            resource_type="filesystem_path",
                        ),
                    ),
                ),
            ),
            unbound_arguments=(),
        )
        try:
            derived = validate_contract_for_schema(
                contract,
                tool.input_schema,
                adapter_resolver=AdapterRegistry(),
            )
        except Exception as exc:
            raise ControlPlaneConfigError("migration_schema_or_contract_unsupported") from exc
        contracts.append(contract)
        resolutions.extend(derived)
        referenced_scope_ids = set(binding.resource.allowed_scope_candidates)
        if binding.resource.relative_base_scope:
            referenced_scope_ids.add(binding.resource.relative_base_scope)
        for scope_id in referenced_scope_ids:
            existing = scope_authorities.setdefault(scope_id, binding.server_ref)
            if existing != binding.server_ref:
                raise ControlPlaneConfigError("migration_scope_authority_ambiguous")

    migrated_scopes = tuple(
        AuthorityResourceScope(
            scope_id=scope_id,
            authority=authority,
            resource_type="filesystem_path",
            canonical_value="/",
            match_mode=ScopeMatchMode.SUBTREE,
            broad_scope_acknowledged=True,
        )
        for scope_id, authority in sorted(scope_authorities.items())
    )
    v2 = ControlPlaneConfigContent(
        schema_version=2,
        identity_bindings=old.identity_bindings,
        agent_authorizations=old.agent_authorizations,
        policy_settings=old.policy_settings,
        supported_schema_profile="supported-json-schema-v1",
        capability_catalog_version="1",
        resource_type_registry_version="1",
        tool_security_contracts=tuple(contracts),
        authority_resource_scopes=migrated_scopes,
        adapter_resolutions=tuple(resolutions),
        tool_observation_approvals=(),
        authority_contexts={
            authority: AuthorityContext(filesystem_path_mode="ABSOLUTE")
            for authority in sorted(set(scope_authorities.values()))
        },
    )
    return create_revision(
        db,
        content=v2,
        status="DRAFT",
        actor=actor,
        change_summary=change_summary,
        parent_revision_id=source.id,
    )
