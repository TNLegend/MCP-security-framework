"""Pure tool value renderer; no admission, identity or authorization."""


def render_tool_definition(tool):
    return {
        "name": tool["name"],
        "description": tool.get("description") or "",
        "inputSchema": tool.get("input_schema") or {},
        **(
            {"outputSchema": tool["output_schema"]}
            if isinstance(tool.get("output_schema"), dict)
            else {}
        ),
        **(
            {"annotations": tool["annotations"]}
            if isinstance(tool.get("annotations"), dict)
            else {}
        ),
    }
