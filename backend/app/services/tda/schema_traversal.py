from __future__ import annotations
from typing import Any, Iterable

def iter_schema_fields(
    schema: dict[str, Any],
) -> Iterable[tuple[str, str, dict[str, Any]]]:
    yield from _walk_schema(schema, "$")


def _walk_schema(
    node: Any, path: str, *, field_name: str = ""
) -> Iterable[tuple[str, str, dict[str, Any]]]:
    if not isinstance(node, dict):
        return
    if field_name or any((key in node for key in ("description", "title"))):
        yield (path, field_name, node)
    properties = node.get("properties")
    if isinstance(properties, dict):
        for name, child in properties.items():
            if isinstance(child, dict):
                yield from _walk_schema(
                    child, f"{path}.properties.{name}", field_name=str(name)
                )
    for keyword in (
        "items",
        "contains",
        "additionalProperties",
        "not",
        "if",
        "then",
        "else",
    ):
        child = node.get(keyword)
        if isinstance(child, dict):
            yield from _walk_schema(child, f"{path}.{keyword}", field_name=field_name)
    for keyword in ("allOf", "anyOf", "oneOf", "prefixItems"):
        children = node.get(keyword)
        if isinstance(children, list):
            for index, child in enumerate(children):
                if isinstance(child, dict):
                    yield from _walk_schema(
                        child, f"{path}.{keyword}[{index}]", field_name=field_name
                    )
    for keyword in ("$defs", "definitions", "dependentSchemas", "patternProperties"):
        children = node.get(keyword)
        if isinstance(children, dict):
            for name, child in children.items():
                if isinstance(child, dict):
                    yield from _walk_schema(
                        child, f"{path}.{keyword}.{name}", field_name=str(name)
                    )
