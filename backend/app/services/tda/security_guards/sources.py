from __future__ import annotations
from app.services.tda.schema_traversal import iter_schema_fields
from app.services.tda.security_guards.facts import _TextSegment
from app.services.tda.security_guards.context import _humanize_identifier
from app.services.tda.security_guards.context import strip_documentation_examples
from typing import Any
from typing import Iterable




def _tool_segments(tool_snapshot: dict[str, Any]) -> Iterable[_TextSegment]:
    name = str(tool_snapshot.get("name") or "")
    if name:
        yield _TextSegment(
            "name", "$.name", _humanize_identifier(name), 0.55, "IDENTIFIER_HINT"
        )
    description = strip_documentation_examples(
        str(tool_snapshot.get("description") or "")
    )
    if description.strip():
        yield _TextSegment("description", "$.description", description, 0.82)
    for source, key in (
        ("input_schema", "input_schema"),
        ("output_schema", "output_schema"),
    ):
        schema = tool_snapshot.get(key)
        if not isinstance(schema, dict):
            continue
        for path, field_name, field in iter_schema_fields(schema):
            if field_name:
                yield _TextSegment(
                    source,
                    path,
                    _humanize_identifier(field_name),
                    0.76,
                    "IDENTIFIER_HINT",
                )
            for metadata_key in ("title", "description", "format", "const"):
                value = field.get(metadata_key)
                if isinstance(value, (str, int, float, bool)):
                    kind = (
                        "CLAIM_TEXT"
                        if metadata_key in {"title", "description"}
                        else "SCHEMA_VALUE"
                    )
                    yield _TextSegment(
                        source, f"{path}.{metadata_key}", str(value), 0.76, kind
                    )
            enum_values = field.get("enum")
            if isinstance(enum_values, list):
                for index, value in enumerate(enum_values[:20]):
                    yield _TextSegment(
                        source,
                        f"{path}.enum[{index}]",
                        str(value),
                        0.76,
                        "SCHEMA_VALUE",
                    )
    for source, key, confidence in (
        ("annotations", "annotations", 0.76),
        ("execution", "execution", 0.9),
    ):
        value = tool_snapshot.get(key)
        for path, text in _metadata_values(value, f"$.{key}"):
            yield _TextSegment(source, path, text, confidence)




def _metadata_values(value: Any, path: str) -> Iterable[tuple[str, str]]:
    if isinstance(value, str):
        yield (path, value)
    elif isinstance(value, (int, float, bool)):
        yield (path, str(value))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _metadata_values(child, f"{path}[{index}]")
    elif isinstance(value, dict):
        for key, child in value.items():
            yield from _metadata_values(child, f"{path}.{key}")
