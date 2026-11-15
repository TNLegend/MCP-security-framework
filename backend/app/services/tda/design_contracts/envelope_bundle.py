"""Cross-module envelope validation, experimental only.

A source reference with module-qualified ID is not validated by one isolated
envelope. validate_bundle proves it resolves to an observation in this
immutable seven-module experimental bundle. No runtime authorization.
"""

from __future__ import annotations
from app.services.tda.design_contracts.envelopes import validate_envelope
import json
from pathlib import Path

MODULES = tuple((f"M{i}" for i in range(1, 8)))
_REGISTRY = json.loads(
    (Path(__file__).resolve().parent / "contracts_v1.json").read_text(encoding="utf8")
)
_ALLOWED_DEPENDENCIES = {
    x["id"]: frozenset(x["depends_on"]) | {x["id"]} for x in _REGISTRY["modules"]
}
if set(_ALLOWED_DEPENDENCIES) != set(MODULES):
    raise ValueError("experimental registry must define exactly seven modules")
COMMON_CONTEXT_FIELDS = (
    "acquisition_id",
    "snapshot_id",
    "registration_id",
    "tool_name",
    "protocol_profile_id",
    "authority_id",
    "verified_principal_id",
    "catalog_generation",
    "observation_revision",
    "agent_view_id",
    "raw_sha256",
    "canonical_original_sha256",
    "exposed_projection_sha256",
    "legacy_tool_fingerprint",
)


def validate_bundle(bundle, *, original, exposed_snapshot_bytes=None):
    if len(bundle) != 7 or {x.get("module_id") for x in bundle} != set(MODULES):
        raise ValueError("bundle must contain exactly M1 through M7 once")
    byid = {x["module_id"]: x for x in bundle}
    for x in bundle:
        validate_envelope(
            x, original=original, exposed_snapshot_bytes=exposed_snapshot_bytes
        )
        if x["mode"] != "SHADOW" or x["authority"] != "NON_AUTHORITATIVE":
            raise ValueError("design bundle must remain shadow-only")
    root = byid["M1"]["source_context"]
    for x in bundle:
        for field in COMMON_CONTEXT_FIELDS:
            if x["source_context"][field] != root[field]:
                raise ValueError("cross-module source or identity mismatch: " + field)
    for field in ("contract_sha256", "policy_sha256", "analysis_context_sha256"):
        claims = {
            x["source_context"][field]
            for x in bundle
            if x["source_context"][field] is not None
        }
        if len(claims) > 1:
            raise ValueError("incompatible cross-module authority context: " + field)
    observations = {}
    proof_map = {x["module_id"]: {ev["id"]: ev for ev in x["evidence"]} for x in bundle}
    for x in bundle:
        mid = x["module_id"]
        for o in x["observations"]:
            oid = o["id"]
            if not oid.startswith(mid + ":"):
                raise ValueError("observation id not module-qualified")
            if oid in observations:
                raise ValueError("duplicate observation in bundle")
            if o["kind"] == "ESTABLISHED_DIRECTIVE":
                if o["support"] not in (
                    "MECHANICAL_VERIFIED",
                    "LINGUISTICALLY_SUPPORTED",
                ):
                    raise ValueError(
                        "A05: established directive cannot rely on unestablished support"
                    )
                if not o["evidence_ids"] or not all(
                    (proof_map[mid][ref]["verified"] for ref in o["evidence_ids"])
                ):
                    raise ValueError(
                        "A05: established directive requires exact verified source evidence"
                    )
            observations[oid] = o
    for x in bundle:
        for o in x["observations"]:
            for dep in o["dependency_ids"]:
                if dep not in observations:
                    raise ValueError(
                        "cross-module observation dependency is missing: " + dep
                    )
                if dep.split(":", 1)[0] not in _ALLOWED_DEPENDENCIES[x["module_id"]]:
                    raise ValueError(
                        "A04: dependency outside declared module graph: "
                        + x["module_id"]
                        + " -> "
                        + dep
                    )
    remaining = {oid: set(o["dependency_ids"]) for oid, o in observations.items()}
    resolved = set()
    while remaining:
        ready = {oid for oid, deps in remaining.items() if deps <= resolved}
        if not ready:
            raise ValueError("circular observation justification")
        resolved.update(ready)
        for oid in ready:
            del remaining[oid]
    for obs_ref in (
        r
        for kind in ("required_preconditions", "vetoes")
        for item in byid["M7"]["result"][kind]
        for r in item["source_observation_ids"]
    ):
        if obs_ref not in observations:
            raise ValueError("M7 references missing upstream observation: " + obs_ref)
    policy = byid["M7"]["result"]["policy_assessment"]
    for veto in byid["M7"]["result"]["vetoes"]:
        if not veto["active"]:
            continue
        refs = veto["source_observation_ids"]
        if not refs:
            if not (
                policy["evaluation_status"] == "NO_POLICY_CHANGE"
                and policy.get("baseline_status") == policy.get("proposed_status")
                and (policy.get("baseline_status") in ("BLOCKED", "QUARANTINED"))
            ):
                raise ValueError("A05: active new veto without an established source")
            continue
        if not any(
            (
                observations[ref]["support"]
                in ("MECHANICAL_VERIFIED", "LINGUISTICALLY_SUPPORTED")
                and observations[ref]["status"] == "OBSERVED"
                and bool(observations[ref]["evidence_ids"])
                and all(
                    (
                        proof_map[ref.split(":", 1)[0]][ev]["verified"]
                        for ev in observations[ref]["evidence_ids"]
                    )
                )
                for ref in refs
            )
        ):
            raise ValueError(
                "A05: unproved, model-only or unresolved observations cannot establish an active veto"
            )
    return True
