from __future__ import annotations
from app.services.tda.m1_sources.contracts import SourceView
from app.services.tda.m1_sources.contracts import ViewKind
from dataclasses import dataclass
from dataclasses import field


@dataclass(frozen=True)
class SourcePath:
    parent: SourcePath | None = field(repr=False)
    segment: str = field(repr=False)

    @property
    def pointer(self):
        parts = []
        node = self
        while node.parent is not None:
            parts.append(node.segment.replace("~", "~0").replace("/", "~1"))
            node = node.parent
        return "".join(("/" + x for x in reversed(parts)))


@dataclass(frozen=True)
class SourceField:
    path: SourcePath = field(repr=False)
    text: str = field(repr=False)

    @property
    def pointer(self):
        return self.path.pointer


@dataclass(frozen=True)
class AnalysisContext:
    context_id: str
    original: SourceView
    profile_json: bytes | None
    baseline_json: bytes | None
    canonical_original_sha256: str
    source_fields: tuple[SourceField, ...] = field(repr=False)
    key_inventory: tuple[tuple[SourcePath, str], ...] = field(repr=False)
    raw_sha256: str | None = None
    exposed_projection_sha256: str | None = None
    acquisition_scope: str = "PARSED_SNAPSHOT_ONLY"
    semantic_completeness: str = "NOT_VERIFIED"


def capture_context(snapshot, profile=None, baseline=None):
    """Freeze validated JSON values while retaining original field order.

    These serialized parsed values are NOT claimed to be transport raw bytes.
    Absence of an exposed projection remains explicit. No semantic roles are
    inferred by the source index, including for structural keys.
    """
    from common.canonical_json import canonical_json_bytes
    import json
    from hashlib import sha256

    def encode(value):
        from proxy.strict_json import (
            MAX_JSON_DEPTH,
            MAX_JSON_PROPERTIES,
            MAX_JSON_ARRAY_ITEMS,
            MAX_UPSTREAM_RESPONSE_STRING_LENGTH,
            MAX_UPSTREAM_RESPONSE_JSON_BYTES,
        )

        ancestors = set()
        budget = 0

        def keys(v, depth=0):
            nonlocal budget
            if isinstance(v, str) and len(v) > MAX_UPSTREAM_RESPONSE_STRING_LENGTH:
                raise ValueError("snapshot_string_exceeded")
            budget += 1
            if isinstance(v, str):
                budget += len(v.encode("utf8"))
            if budget > MAX_UPSTREAM_RESPONSE_JSON_BYTES:
                raise ValueError("snapshot_size_exceeded")
            if depth > MAX_JSON_DEPTH:
                raise ValueError("snapshot_depth_exceeded")
            if isinstance(v, str) and len(v) > MAX_UPSTREAM_RESPONSE_STRING_LENGTH:
                raise ValueError("snapshot_string_exceeded")
            if isinstance(v, (dict, list, tuple)):
                if id(v) in ancestors:
                    raise ValueError("snapshot_cycle")
                ancestors.add(id(v))
            if isinstance(v, dict):
                if len(v) > MAX_JSON_PROPERTIES:
                    raise ValueError("snapshot_properties_exceeded")
                if any(
                    (
                        not isinstance(k, str)
                        or len(k) > MAX_UPSTREAM_RESPONSE_STRING_LENGTH
                        for k in v
                    )
                ):
                    raise ValueError("non_json_key")
                budget += sum((len(k.encode("utf8")) for k in v))
                if budget > MAX_UPSTREAM_RESPONSE_JSON_BYTES:
                    raise ValueError("snapshot_size_exceeded")
                for x in v.values():
                    keys(x, depth + 1)
            elif isinstance(v, (list, tuple)):
                if len(v) > MAX_JSON_ARRAY_ITEMS:
                    raise ValueError("snapshot_array_exceeded")
                for x in v:
                    keys(x, depth + 1)
            if isinstance(v, (dict, list, tuple)):
                ancestors.remove(id(v))

        keys(value)
        return json.dumps(
            value, ensure_ascii=False, separators=(",", ":"), allow_nan=False
        ).encode("utf8")

    data = encode(snapshot)
    prof = encode(profile) if profile is not None else None
    base = encode(baseline) if baseline is not None else None
    fields = []
    names = []

    def walk(v, path):
        if isinstance(v, str):
            fields.append(SourceField(path, v))
        elif isinstance(v, dict):
            for key, x in v.items():
                names.append((path, key))
                walk(x, SourcePath(path, key))
        elif isinstance(v, list):
            for i, x in enumerate(v):
                walk(x, SourcePath(path, str(i)))

    chunks = [
        b"tda-context-v1\x00",
        data,
        prof or b"NULL_PROFILE",
        base or b"NULL_BASELINE",
    ]
    identity = sha256(
        b"".join((len(x).to_bytes(8, "big") + x for x in chunks))
    ).hexdigest()
    view = SourceView("original:" + identity, ViewKind.ORIGINAL, data)
    parsed = json.loads(data)
    walk(parsed, SourcePath(None, ""))
    return AnalysisContext(
        identity,
        view,
        prof,
        base,
        sha256(canonical_json_bytes(snapshot)).hexdigest(),
        tuple(fields),
        tuple(names),
    )
