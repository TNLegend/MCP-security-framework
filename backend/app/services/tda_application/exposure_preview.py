from common.tool_projection import render_tool_definition

"Render exact prospective tool values; this is not a served capture or grant."
import json
from hashlib import sha256
from common.canonical_json import sha256_canonical_json


def preview(definition, tool_name):
    from proxy.protocol_profiles import ProtocolProfileRegistry
    from proxy.tool_security_v2 import security_schema_projection
    from starlette.responses import JSONResponse

    description = definition.get("description", "")
    if not isinstance(description, str):
        raise ValueError("projection_description_not_text")
    tool = {
        "name": tool_name,
        "description": description,
        "input_schema": security_schema_projection(
            definition.get("input_schema") or {}
        ),
        "output_schema": definition.get("output_schema") or {},
        "annotations": definition.get("annotations") or {},
    }
    registry = ProtocolProfileRegistry()
    profiles = {}
    values = {}
    for profile_id in registry.supported_profile_ids():
        value = render_tool_definition(tool)
        data = JSONResponse(value).body
        digest = sha256(data).hexdigest()
        profiles[profile_id] = digest
        unique = {
            "utf8": data.decode("utf8"),
            "sha256_jcs": sha256_canonical_json(value),
        }
        if digest in values and values[digest] != unique:
            raise ValueError("projection_digest_collision")
        values[digest] = unique
    return {
        "schema": "tda-exposure-preview-v1",
        "scope": "RENDERED_PREVIEW_NOT_SERVED_CAPTURE",
        "renderer": "MCPGateway._tools_list_response/tool-value",
        "profiles": profiles,
        "values": values,
    }
