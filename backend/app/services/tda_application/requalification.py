"""Read-only preparation. This module cannot mint or reconduct an approval."""

from dataclasses import dataclass
from hashlib import sha256
import json

IDENTITY_PATHS = frozenset(
    {
        "/analyzer_revision",
        "/model_versions/semantic/version",
        "/model_versions/embedding/version",
    }
)


def _bytes(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf8")


@dataclass(frozen=True)
class Difference:
    pointer: str
    before: bytes | None
    after: bytes | None


@dataclass(frozen=True)
class RequalificationPacket:
    source_context_json: bytes
    old_output_json: bytes
    candidate_output_json: bytes
    differences: tuple[Difference, ...]
    disposition: str
    authority: str = "NON_AUTHORITATIVE"
    required_action: str = "EXPLICIT_ADMIN_DECISION_PER_TOOL"

    @property
    def digest(self):
        chunks = [
            b"mcp/tda/requalification-preparation/v1\x00",
            self.source_context_json,
            self.old_output_json,
            self.candidate_output_json,
        ]
        return sha256(
            b"".join((len(x).to_bytes(8, "big") + x for x in chunks))
        ).hexdigest()


def prepare(old_output, candidate_output, *, source_context):
    required = {
        "observation_id",
        "protocol_profile_id",
        "tool_fingerprint",
        "contract_hash",
    }
    if not required <= source_context.keys() or any(
        (source_context[k] is None for k in required)
    ):
        raise ValueError("source_context_incomplete")
    old = json.loads(_bytes(old_output))
    new = json.loads(_bytes(candidate_output))
    diff = []

    def walk(a, b, path=""):
        if type(a) != type(b):
            diff.append(Difference(path, _bytes(a), _bytes(b)))
            return
        if isinstance(a, dict):
            for key in sorted(a.keys() | b.keys()):
                pointer = path + "/" + key.replace("~", "~0").replace("/", "~1")
                if key not in a:
                    diff.append(Difference(pointer, None, _bytes(b[key])))
                elif key not in b:
                    diff.append(Difference(pointer, _bytes(a[key]), None))
                else:
                    walk(a[key], b[key], pointer)
        elif isinstance(a, list):
            if a != b:
                diff.append(Difference(path, _bytes(a), _bytes(b)))
        elif a != b:
            diff.append(Difference(path, _bytes(a), _bytes(b)))

    walk(old, new)
    state = (
        "IDENTITY_ONLY_REQUIRES_EXPLICIT_REVIEW"
        if diff and all((d.pointer in IDENTITY_PATHS for d in diff))
        else "EXACT_REQUIRES_CURRENT_AUTHORITY_CHECK"
        if not diff
        else "INDIVIDUAL_REVIEW_REQUIRED"
    )
    return RequalificationPacket(
        _bytes(source_context), _bytes(old), _bytes(new), tuple(diff), state
    )
