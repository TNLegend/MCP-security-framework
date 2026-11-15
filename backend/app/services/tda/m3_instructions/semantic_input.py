from __future__ import annotations
from app.services.tda.configuration import SEMANTIC_CATEGORIES
from app.services.tda.text import _annotation_text
from app.services.tda.text import _schema_field_text
from app.services.tda.schema_traversal import iter_schema_fields
from app.services.tda.m5_context.identity import normalize_description
from app.services.tda.linguistic_context import strip_documentation_examples
from app.services.tda.claim_context import metadata_texts
from typing import Any


def _semantic_input_with_coverage(
    tool_snapshot: dict[str, Any],
) -> tuple[str, dict[str, Any]]:
    from typing import Any

    fragments: list[str] = []
    fields: list[dict[str, Any]] = []

    def add_fragment(value: str, limit: int, source: str) -> None:
        normalized = normalize_description(value)
        offset = sum((len(part) for part in fragments)) + len(fragments)
        retained = min(len(normalized), limit, max(0, 8000 - offset))
        fields.append(
            {
                "source": source,
                "original_chars": len(normalized),
                "retained_chars": retained,
                "limit": limit,
                "semantic_start": offset,
                "complete": retained == len(normalized),
            }
        )
        if normalized:
            fragments.append(normalized[:limit])

    add_fragment(str(tool_snapshot.get("name") or ""), 240, "name")
    add_fragment(
        strip_documentation_examples(str(tool_snapshot.get("description") or "")),
        3000,
        "description",
    )
    for _path, name, field in iter_schema_fields(
        tool_snapshot.get("input_schema") or {}
    ):
        add_fragment(
            f"{name} {_schema_field_text(field)}", 320, f"input_schema:{_path}"
        )
    for _path, name, field in iter_schema_fields(
        tool_snapshot.get("output_schema") or {}
    ):
        add_fragment(
            f"{name} {_schema_field_text(field)}", 320, f"output_schema:{_path}"
        )
    annotation_text = _annotation_text(tool_snapshot.get("annotations") or {})
    if annotation_text:
        add_fragment(annotation_text, 1000, "annotations")
    execution_text = _annotation_text(tool_snapshot.get("execution") or {})
    if execution_text:
        add_fragment(execution_text, 1000, "execution")
    assembled = "\n".join(fragments)
    reasons = [
        f"field_character_budget:{x['source']}" for x in fields if not x["complete"]
    ]
    if len(assembled) > 8000:
        reasons.append("global_character_budget")
    raw_description = str(tool_snapshot.get("description") or "")
    if strip_documentation_examples(raw_description) != raw_description:
        reasons.append("documentation_examples_excluded_from_semantic_model")
    skipped_content = [
        {
            "source": path,
            "chars": len(value),
            "reason": "not_in_semantic_input",
            "poisoning_scan": True,
        }
        for path, value in metadata_texts(tool_snapshot)
        if value and any((f".{key}" in path for key in ("default", "examples")))
    ]
    if skipped_content:
        reasons.append("schema_default_or_example_text_not_semantically_classified")
    annotations = tool_snapshot.get("annotations") or {}
    claims = {
        key: {"value": value, "trusted": False, "source": f"annotations.{key}"}
        for key, value in annotations.items()
        if isinstance(value, bool)
    }
    return (
        assembled[:8000],
        {
            "version": "analysis-coverage-v1",
            "complete": not reasons,
            "fields": fields,
            "global_char_limit": 8000,
            "assembled_chars": len(assembled),
            "retained_chars": min(len(assembled), 8000),
            "incomplete_reasons": reasons,
            "annotation_claims": claims,
            "excluded_fields": [
                key for key in ("title", "icons", "_meta") if key in tool_snapshot
            ],
            "skipped_content": skipped_content,
            "scope": "semantic input character coverage; token coverage reported separately; not proof of remote behavior",
        },
    )


def _semantic_text(tool_snapshot: dict[str, Any]) -> str:
    return _semantic_input_with_coverage(tool_snapshot)[0]


def _semantic_categories(profile_snapshot: dict[str, Any] | None) -> list[str]:
    from proxy.security_packs import SecurityPackRegistry

    categories = list(SEMANTIC_CATEGORIES)
    pack = (profile_snapshot or {}).get("security_pack")
    declared_categories = (
        pack.get("semantic_categories") if isinstance(pack, dict) else None
    )
    if isinstance(declared_categories, (list, tuple)):
        categories.extend(
            (value for value in declared_categories if isinstance(value, str) and value)
        )
    pack_id = pack.get("id") if isinstance(pack, dict) else None
    if isinstance(pack_id, str):
        manifest = next(
            (value for value in SecurityPackRegistry().packs() if value.id == pack_id),
            None,
        )
        if manifest is not None:
            categories.extend(manifest.semantic_categories)
    return list(dict.fromkeys(categories))
