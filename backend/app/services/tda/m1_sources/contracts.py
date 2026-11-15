from dataclasses import dataclass
from enum import Enum
import json
from hashlib import sha256


class ViewKind(str, Enum):
    ORIGINAL = "ORIGINAL"
    EXPOSED = "EXPOSED"
    DERIVED = "DERIVED"


@dataclass(frozen=True)
class SourceView:
    view_id: str
    kind: ViewKind
    json_bytes: bytes
    derived_kind: str | None = None
    parent_view_id: str | None = None

    def __post_init__(self):
        if not isinstance(self.kind, ViewKind) or not self.view_id:
            raise ValueError("invalid_view")
        if not isinstance(self.json_bytes, bytes):
            raise ValueError("immutable_bytes_required")
        from proxy.strict_json import (
            parse_strict_json,
            MAX_UPSTREAM_RESPONSE_JSON_BYTES,
            MAX_UPSTREAM_RESPONSE_STRING_LENGTH,
        )

        parse_strict_json(
            self.json_bytes,
            max_bytes=MAX_UPSTREAM_RESPONSE_JSON_BYTES,
            max_string_length=MAX_UPSTREAM_RESPONSE_STRING_LENGTH,
        )
        if self.kind == ViewKind.DERIVED:
            if (
                self.derived_kind not in {"CONSISTENCY_MASK", "DECODED_ANALYSIS"}
                or not self.parent_view_id
            ):
                raise ValueError("derived_parent_required")
        elif self.derived_kind is not None or self.parent_view_id is not None:
            raise ValueError("unexpected_transform")

    @property
    def sha256(self):
        return sha256(self.json_bytes).hexdigest()


@dataclass(frozen=True)
class Evidence:
    view_id: str
    source_digest: str
    pointer: str
    start: int
    end: int
    excerpt: str

    def verify(self, view):
        if self.view_id != view.view_id or self.source_digest != view.sha256:
            raise ValueError("evidence_source_mismatch")
        from proxy.strict_json import (
            parse_strict_json,
            MAX_UPSTREAM_RESPONSE_JSON_BYTES,
            MAX_UPSTREAM_RESPONSE_STRING_LENGTH,
        )

        current = parse_strict_json(
            view.json_bytes,
            max_bytes=MAX_UPSTREAM_RESPONSE_JSON_BYTES,
            max_string_length=MAX_UPSTREAM_RESPONSE_STRING_LENGTH,
        )
        if self.pointer:
            if not self.pointer.startswith("/"):
                raise ValueError("invalid_pointer")
            for raw in self.pointer[1:].split("/"):
                import re

                if re.search("~(?![01])", raw):
                    raise ValueError("invalid_pointer_escape")
                key = raw.replace("~1", "/").replace("~0", "~")
                if isinstance(current, list):
                    if not re.fullmatch("0|[1-9][0-9]*", key):
                        raise ValueError("invalid_array_index")
                    current = current[int(key)]
                else:
                    current = current[key]
        if (
            not isinstance(current, str)
            or type(self.start) is not int
            or type(self.end) is not int
            or (not 0 <= self.start <= self.end <= len(current))
        ):
            raise ValueError("invalid_span")
        if current[self.start : self.end] != self.excerpt:
            raise ValueError("excerpt_mismatch")
        return True
