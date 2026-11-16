"""Read-only inventory of original MCP string values and JSON object keys.

Uses M1's source_fields/key_inventory; does not invent new raw/decoded origins.
Never normalizes original text or claims a transformed view was attested by M2.
"""
from __future__ import annotations
from dataclasses import dataclass
from hashlib import sha256

from app.services.tda.m1_sources.capture import AnalysisContext


@dataclass(frozen=True)
class M3Surface:
    pointer: str
    kind: str
    text: str
    parent_pointer: str = ""
    key: str | None = None
    view_id: str = ""
    source_digest: str = ""

    @property
    def text_sha256(self) -> str:
        return sha256(self.text.encode("utf8")).hexdigest()


def original_surfaces(context: AnalysisContext) -> tuple[M3Surface, ...]:
    """Canonical M1 inventory, without serializing schemas or losing paths."""
    result: list[M3Surface] = []
    view = context.original
    for f in context.source_fields:
        result.append(M3Surface(
            pointer=f.pointer, kind="VALUE", text=f.text,
            view_id=view.view_id, source_digest=view.sha256,
        ))
    for parent, key in context.key_inventory:
        parent_pointer = parent.pointer
        escaped = key.replace("~", "~0").replace("/", "~1")
        result.append(M3Surface(
            pointer=parent_pointer + "/" + escaped,
            parent_pointer=parent_pointer, kind="KEY",
            key=key, text=key, view_id=view.view_id, source_digest=view.sha256,
        ))
    return tuple(result)
