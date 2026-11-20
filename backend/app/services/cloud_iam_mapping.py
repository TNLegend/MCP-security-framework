"""Admin-reviewed mappings pinned to signed, published MCP contracts.

Only SELF scopes from a verified signed control-plane revision may be expanded.
The mapping is explicitly approved by an administrator and hash-bound to the
revision. No arbitrary code, environment interpolation or wildcard resources.
"""
from __future__ import annotations
import hashlib
import json
import re

class MappingError(ValueError):
    pass

_TOKEN = re.compile(r"\$\{(scope|scope:[A-Za-z0-9_.-]{1,160})\}")
_RESOURCE = re.compile(r"arn:aws(?:-us-gov|-cn)?:[a-z0-9-]+:[A-Za-z0-9_.:/@+=,-]{1,460}")

def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(",",":"),
                                      ensure_ascii=True).encode()).hexdigest()

def mapping_digest(row):
    return digest({"environment_id":row.environment_id,"mcp_server_id":row.mcp_server_id,
                   "name":row.name,"configuration":row.configuration,
                   "signed_revision":row.signed_revision,
                   "signed_content_hash":row.signed_content_hash})

def _declared(snapshot, endpoint):
    authority="streamable_http:"+endpoint
    contracts=[c for c in snapshot.content.tool_security_contracts if c.server_ref==authority]
    if not contracts:
        raise MappingError("IAM_MCP_SIGNED_SERVER_CONTRACT_NOT_FOUND")
    # A signed revision can contain contracts without an approved tool
    # observation. Match the separately recorded observation approval to the
    # exact signed contract hash before generating cloud permissions.
    approved = {
        (approval.server_ref, approval.contract_hash)
        for approval in snapshot.content.tool_observation_approvals
    }
    if any((contract.server_ref, contract.contract_hash) not in approved
           for contract in contracts):
        raise MappingError("IAM_MCP_SIGNED_TOOL_APPROVAL_MISSING")
    effects={}
    for c in contracts:
        for e in c.effects:
            key=(c.tool_name,e.effect_id)
            if key in effects:
                raise MappingError("IAM_MCP_DUPLICATE_SIGNED_EFFECT")
            effects[key]=e
    scopes={s.scope_id:s for s in snapshot.content.authority_resource_scopes
            if s.authority==authority}
    return effects,scopes

def context_for_server(snapshot,endpoint):
    effects,scopes=_declared(snapshot,endpoint)
    return {
        "signed_revision":snapshot.revision_number,
        "signed_content_hash":snapshot.content_hash,
        "effects":[{
            "tool_name":tool,"effect_id":eid,"capability":effect.capability,
            "resource_type":effect.fixed_resource.resource_type if effect.fixed_resource
             else effect.resource_bindings[0].resource_type if len(effect.resource_bindings)==1
             else None,
        } for (tool,eid),effect in sorted(effects.items())],
        "scopes":[{
            "scope_id":s.scope_id,"resource_type":s.resource_type,
            "canonical_value":s.canonical_value,"match_mode":s.match_mode,
        } for s in sorted(scopes.values(),key=lambda a:a.scope_id)
          if s.match_mode=="SELF" and not s.broad_scope_acknowledged],
    }

def compile_expectations(snapshot,endpoint,entries):
    if not isinstance(entries,list) or len(entries)>100:
        raise MappingError("IAM_MCP_MAPPING_SIZE_INVALID")
    effects,scopes=_declared(snapshot,endpoint)
    mapped=set()
    result=[]
    for entry in entries:
        tool,eid=entry["tool_name"],entry["effect_id"]
        key=(tool,eid)
        if key not in effects:
            raise MappingError("IAM_MCP_MAPPING_NOT_IN_SIGNED_CONTRACT")
        effect=effects[key]
        mapped.add(key)
        precision=getattr(effect.declared_reference_precision,"value",
                          effect.declared_reference_precision)
        if precision!="EXPLICIT" or len(effect.resource_bindings)>1:
            raise MappingError("IAM_MCP_EFFECT_NOT_EXPLICIT")
        rtype=(effect.fixed_resource.resource_type if effect.fixed_resource
               else effect.resource_bindings[0].resource_type
               if len(effect.resource_bindings)==1 else None)
        scope=scopes.get(entry["scope_id"])
        if not rtype or scope is None or scope.match_mode!="SELF" or scope.broad_scope_acknowledged or scope.resource_type!=rtype:
            raise MappingError("IAM_MCP_SIGNED_SCOPE_MISMATCH")
        if effect.fixed_resource and effect.fixed_resource.canonical_value!=scope.canonical_value:
            raise MappingError("IAM_MCP_FIXED_RESOURCE_MISMATCH")
        template=entry["resource_template"]
        if "${scope}" not in template or "*" in template or "?" in template:
            raise MappingError("IAM_MCP_RESOURCE_TEMPLATE_UNSAFE")
        if "${" in _TOKEN.sub("",template) or "{" in _TOKEN.sub("",template) or "}" in _TOKEN.sub("",template):
            raise MappingError("IAM_MCP_TEMPLATE_UNRECOGNIZED_TOKEN")
        def expand(m):
            token=m.group(1)
            selected=scope if token=="scope" else scopes.get(token[6:])
            if selected is None or selected.match_mode!="SELF" or selected.broad_scope_acknowledged:
                raise MappingError("IAM_MCP_TEMPLATE_SCOPE_NOT_SIGNED")
            value=selected.canonical_value
            if not isinstance(value,str) or not value or "*" in value or "?" in value:
                raise MappingError("IAM_MCP_TEMPLATE_SCOPE_UNSAFE")
            return value
        resource=_TOKEN.sub(expand,template)
        if len(resource)>512 or not _RESOURCE.fullmatch(resource):
            raise MappingError("IAM_MCP_RENDERED_RESOURCE_INVALID")
        result.append({"tool":tool,"effect_id":eid,
                       "action":entry["action"],"resource":resource,
                       "status":"READY","reason":"ADMIN_APPROVED_SIGNED_SCOPE"})
    for tool,eid in sorted(set(effects)-mapped):
        result.append({"tool":tool,"effect_id":eid,"action":None,
                       "resource":None,"status":"UNKNOWN",
                       "reason":"IAM_MCP_EFFECT_NOT_MAPPED"})
    return result

def verify_approved_mapping(row,snapshot,endpoint,account_id):
    binding=row.configuration.get("source_binding")
    if binding != {"account_id":account_id,"server_endpoint":endpoint}:
        raise MappingError("IAM_MCP_MAPPING_CLOUD_OR_SERVER_BINDING_CHANGED")
    if row.status!="APPROVED" or not row.approved_by or not row.approved_at:
        raise MappingError("IAM_MCP_MAPPING_NOT_APPROVED")
    if row.signed_revision!=snapshot.revision_number or row.signed_content_hash!=snapshot.content_hash:
        raise MappingError("IAM_MCP_MAPPING_SIGNED_REVISION_CHANGED")
    if row.approval_digest!=mapping_digest(row):
        raise MappingError("IAM_MCP_MAPPING_APPROVAL_DIGEST_MISMATCH")
    return compile_expectations(snapshot,endpoint,row.configuration["entries"])
