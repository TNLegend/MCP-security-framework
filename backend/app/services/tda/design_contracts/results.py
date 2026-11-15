from dataclasses import dataclass
from enum import Enum
import json
from hashlib import sha256

DEPENDENCIES = {
    "M1": set(),
    "M2": {"M1"},
    "M5": {"M1"},
    "M3": {"M1", "M2", "M5"},
    "M4": {"M1", "M2", "M5"},
    "M6": {"M1", "M2", "M3", "M4", "M5"},
    "M7": {"M1", "M2", "M3", "M4", "M5", "M6"},
}


@dataclass(frozen=True)
class ModuleResult:
    module_id: str
    context_id: str
    execution: str
    payload_json: bytes
    dependency_ids: tuple[str, ...] = ()
    authority: str = "NON_AUTHORITATIVE"
    mode: str = "SHADOW"
    observation_ids: tuple[str, ...] = ()

    def __post_init__(self):
        if self.module_id not in DEPENDENCIES or not self.context_id:
            raise ValueError("invalid_module_context")
        if self.authority != "NON_AUTHORITATIVE" or self.mode != "SHADOW":
            raise ValueError("vnext_authority_forbidden")
        if self.execution not in {
            "COMPLETED",
            "PARTIAL",
            "UNSUPPORTED",
            "FAILED",
            "NOT_RUN",
        }:
            raise ValueError("invalid_execution")
        if not isinstance(self.payload_json, bytes):
            raise ValueError("immutable_payload_required")
        from proxy.strict_json import parse_strict_json

        parse_strict_json(self.payload_json)
        if len(set(self.observation_ids)) != len(self.observation_ids):
            raise ValueError("duplicate_observation")
        if any(
            (
                not x.startswith(self.module_id + ":") or x == self.module_id + ":"
                for x in self.observation_ids
            )
        ):
            raise ValueError("invalid_observation_id")
        for ref in self.dependency_ids:
            if ref.split(":")[0] not in DEPENDENCIES[self.module_id]:
                raise ValueError("forbidden_dependency")


def validate_results(results):
    by_id = {r.module_id: r for r in results}
    if len(by_id) != len(results):
        raise ValueError("duplicate_module")
    for r in results:
        for ref in r.dependency_ids:
            parent = by_id.get(ref.split(":")[0])
            if parent is None or parent.context_id != r.context_id:
                raise ValueError("dependency_context_mismatch")
            if ref not in parent.observation_ids:
                raise ValueError("dependency_observation_missing")
    return True
