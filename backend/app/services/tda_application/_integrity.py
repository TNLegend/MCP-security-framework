"""Shared canonical identity helpers for V1 and M4 V2 signed pipelines.

No model loading, filesystem mutation, authorization or module back edges.
"""
from hashlib import sha256
import json


class PipelineIntegrityError(ValueError):
    pass


def canonical(obj):
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf8")


def digest(obj):
    return sha256(canonical(obj)).hexdigest()


def file_digest(path):
    h = sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()
