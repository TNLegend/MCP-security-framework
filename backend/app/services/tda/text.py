from __future__ import annotations
from app.services.tda.schema_traversal import iter_schema_fields
from typing import Any


def _schema_field_text(field: dict[str, Any]) -> str:
    values: list[str] = []
    for key in ("title", "description"):
        value = field.get(key)
        if isinstance(value, str):
            values.append(value)
    enum_values = field.get("enum")
    if isinstance(enum_values, list):
        values.extend((str(item) for item in enum_values if isinstance(item, str)))
    return " ".join(values).lower()


def _annotation_text(value: Any) -> str:
    from typing import Any

    fragments: list[str] = []

    def visit(item: Any) -> None:
        if isinstance(item, str):
            fragments.append(item)
        elif isinstance(item, list):
            for child in item:
                visit(child)
        elif isinstance(item, dict):
            for child in item.values():
                visit(child)

    visit(value)
    return " ".join(fragments)


def _schema_properties(schema: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {path: value for path, _name, value in iter_schema_fields(schema)}


def _schema_field_name(path: str) -> str:
    return path.rsplit(".", 1)[-1].lower()


def _tokens(text: str) -> list[str]:
    import re

    return re.findall("[a-z0-9._-]+", text.lower())
