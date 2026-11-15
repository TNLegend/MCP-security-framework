"""Versioned pure Gate3B design-contract adapter, not operational authority.

The legacy V0 return/frozen evidence format stays unchanged. This validator
accepts design envelopes only from their source-owning caller. It does not
attest acquisition, authenticate principals, infer relations or issue grants.
The caller supplies ORIGINAL explicitly; EXPOSED always needs captured bytes.
"""

from __future__ import annotations
import json
from pathlib import Path
from jsonschema import Draft202012Validator

ADAPTER_REVISION = "tda-gate3b-contract-adapter-v1"
DESIGN_SCHEMA_VERSION = "1.0.1-closure-design"
SCHEMA = json.loads(
    (Path(__file__).parent / "module_envelope.schema.json").read_text(encoding="utf8")
)
_SCHEMA_VALIDATOR = Draft202012Validator(SCHEMA)
import hashlib
import json
import re

_ARRAY_INDEX = re.compile("(?:0|[1-9][0-9]*)\\Z")
_BAD_ESCAPE = re.compile("~(?![01])")


def resolve_pointer(document, pointer):
    """Resolve an RFC 6901 pointer. Reject Python negative/noncanonical list indices."""
    if not isinstance(pointer, str):
        raise ValueError("source path must be a JSON pointer string")
    if pointer == "":
        return document
    if not pointer.startswith("/"):
        raise ValueError("JSON pointer must start with '/'")
    current = document
    for raw in pointer[1:].split("/"):
        if _BAD_ESCAPE.search(raw):
            raise ValueError("invalid JSON pointer escape")
        token = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict):
            if token not in current:
                raise ValueError("unresolved object property in source")
            current = current[token]
        elif isinstance(current, list):
            if not _ARRAY_INDEX.fullmatch(token):
                raise ValueError("invalid or noncanonical JSON array index")
            index = int(token)
            if index >= len(current):
                raise ValueError("array index outside source")
            current = current[index]
        else:
            raise ValueError("JSON pointer traverses a non-container")
    return current


def _reject_duplicate_pairs(pairs):
    data = {}
    for key, value in pairs:
        if key in data:
            raise ValueError("ambiguous duplicate JSON key in exposed bytes")
        data[key] = value
    return data


def _reject_non_json_constant(value):
    raise ValueError("non-standard JSON value in exposed bytes: " + value)


def _decode_exposed_bytes(raw, expected_digest):
    if not isinstance(raw, bytes):
        raise ValueError("independently captured exposed projection bytes required")
    if not isinstance(expected_digest, str) or len(expected_digest) != 64:
        raise ValueError("missing valid exposed projection hash")
    if hashlib.sha256(raw).hexdigest() != expected_digest.lower():
        raise ValueError("exposed projection bytes do not match recorded SHA-256")
    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_non_json_constant,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid exposed projection JSON bytes") from exc


def validate_source_spans(envelope, original, *, exposed_snapshot_bytes=None):
    """Check verified offsets against the actual, distinct source/view domains.

    The design fixture supplies original explicitly via its adapter. A live
    integration must independently attest original and projection identities.
    In this isolated schema test the ORIGINAL SHA-256 is *not* revalidated.
    """
    context = envelope["source_context"]
    decoded_exposed = None
    for ev in envelope["evidence"]:
        if not ev["verified"]:
            continue
        if ev["snapshot_id"] != context["snapshot_id"]:
            raise ValueError("cross-snapshot evidence")
        role = ev["source_role"]
        if role == "ORIGINAL":
            if ev.get("view_id") is not None or ev.get("transform_chain"):
                raise ValueError(
                    "original evidence cannot claim an exposed/derived view"
                )
            document = original
        elif role == "EXPOSED":
            if (
                not context.get("agent_view_id")
                or ev.get("view_id") != context["agent_view_id"]
            ):
                raise ValueError("exposed proof has unbound or wrong view identity")
            if decoded_exposed is None:
                decoded_exposed = _decode_exposed_bytes(
                    exposed_snapshot_bytes, context.get("exposed_projection_sha256")
                )
            document = decoded_exposed
        else:
            raise ValueError("derived evidence requires attested source-offset mapping")
        source_text = resolve_pointer(document, ev["path"])
        start, end = (ev["start"], ev["end"])
        if (
            not isinstance(source_text, str)
            or not isinstance(start, int)
            or isinstance(start, bool)
            or (not isinstance(end, int))
            or isinstance(end, bool)
            or (start < 0)
            or (end <= start)
            or (end > len(source_text))
            or (source_text[start:end] != ev["excerpt"])
        ):
            raise ValueError("false or out-of-range evidence span")
    return None


def _ids_nonempty_and_exist(ids, known, what, require_verified=False):
    if not ids:
        raise ValueError(f"{what}: missing supporting evidence")
    for i in ids:
        if i not in known:
            raise ValueError(f"{what}: evidence id {i!r} missing")
        if require_verified and (not known[i]["verified"]):
            raise ValueError(f"{what}: cannot promote unverified evidence")


def validate_design_integrity(envelope):
    mid = envelope["module_id"]
    evidence = envelope["evidence"]
    known = {e["id"]: e for e in evidence}
    if len(known) != len(evidence):
        raise ValueError("duplicate evidence identifier")
    obs = envelope["observations"]
    obs_ids = {o["id"] for o in obs}
    if len(obs_ids) != len(obs):
        raise ValueError("duplicate observation identifier")
    for o in obs:
        for ev in o["evidence_ids"]:
            if ev not in known:
                raise ValueError("observation has unresolved evidence")
        for dep in o["dependency_ids"]:
            if dep not in obs_ids and (
                not dep.startswith(tuple((f"M{i}:" for i in range(1, 8))))
            ):
                raise ValueError("unqualified observation dependency")
        if o["support"] == "MECHANICAL_VERIFIED" and o["kind"] not in (
            "INFORMATION_LIMIT",
            "ANALYSIS_FAILURE",
        ):
            _ids_nonempty_and_exist(
                o["evidence_ids"], known, "mechanically verified observation", True
            )
    if envelope["analysis_status"] == "COMPLETE_IN_DECLARED_SCOPE" and (
        not envelope["coverage"]["semantic_complete"]
    ):
        raise ValueError("claimed full analysis but semantic scope was incomplete")
    res = envelope["result"]
    if mid == "M1":
        for field, digest in res["hash_domains"].items():
            if (
                field in envelope["source_context"]
                and digest != envelope["source_context"][field]
            ):
                raise ValueError(
                    "M1 hash domain contradicts its source context: " + field
                )
    if mid == "M3":
        directive_ids = set()
        for d in res["directives"]:
            if d["directive_id"] in directive_ids:
                raise ValueError("duplicate directive ID")
            directive_ids.add(d["directive_id"])
            _ids_nonempty_and_exist(
                d["evidence_ids"],
                known,
                "M3 directive",
                d["status"] == "MECHANICAL_VERIFIED",
            )
        for signal in res["raw_signals"]:
            _ids_nonempty_and_exist(signal["evidence_ids"], known, "M3 raw signal")
    elif mid == "M4":
        for event in res["events"]:
            _ids_nonempty_and_exist(
                event["operation_evidence_ids"],
                known,
                "M4 claimed operation",
                event["claim_role"] == "TOOL_EFFECT",
            )
            for link in event["links"]:
                _ids_nonempty_and_exist(
                    link["evidence_ids"],
                    known,
                    "M4 typed relation",
                    link["support"] == "MECHANICAL_VERIFIED",
                )
    elif mid == "M5":
        for field, value in res["catalog_identity"].items():
            if (
                field in envelope["source_context"]
                and value != envelope["source_context"][field]
            ):
                raise ValueError(
                    "M5 catalog identity contradicts source context: " + field
                )
        for resolution in res["reference_resolutions"]:
            refs = resolution["qualified_target_ids"]
            state = resolution["status"]
            if state == "EXACT":
                if len(refs) != 1:
                    raise ValueError("M5 EXACT requires one qualified target")
                _ids_nonempty_and_exist(
                    resolution["evidence_ids"], known, "M5 exact resolution", True
                )
            elif state == "AMBIGUOUS" and len(refs) < 2:
                raise ValueError("M5 AMBIGUOUS requires 2+ qualified candidate targets")
            elif state in ("ABSENT", "UNVERIFIED_IDENTITY") and refs:
                raise ValueError(
                    "M5 non-resolved reference cannot carry authoritative targets"
                )
    elif mid == "M6":
        ctx = envelope["source_context"]
        for assessment in res["contract_assessments"]:
            if (
                ctx["contract_sha256"] is None
                or assessment["contract_sha256"] != ctx["contract_sha256"]
            ):
                raise ValueError(
                    "M6 assessment is not bound to trusted contract revision"
                )
            if assessment["status"] == "COMPATIBLE_ON_OBSERVED_CLAIMS":
                _ids_nonempty_and_exist(
                    assessment["evidence_ids"],
                    known,
                    "M6 compatibility on observed claims",
                    True,
                )
    elif mid == "M7":
        policy = res["policy_assessment"]
        if policy["evaluation_status"] == "NO_POLICY_CHANGE":
            before = policy.get("baseline_status")
            after = policy.get("proposed_status")
            if before is None or after is None or before != after:
                raise ValueError(
                    "M7 NO_POLICY_CHANGE needs explicit identical before/after status"
                )
            if any((v["active"] for v in res["vetoes"])) and after not in (
                "BLOCKED",
                "QUARANTINED",
            ):
                raise ValueError(
                    "M7 active veto cannot coexist with permissive proposed disposition"
                )
        for item in res["required_preconditions"] + res["vetoes"]:
            for ref in item["source_observation_ids"]:
                if ref not in obs_ids and (
                    not ref.startswith(tuple((f"M{i}:" for i in range(1, 8))))
                ):
                    raise ValueError("M7 observation reference not qualified")
    return True


def validate_event_graph(envelope):
    if envelope["module_id"] != "M4":
        return
    events = envelope["result"]["events"]
    seen = set()
    targets = {
        "OPERATION_PAYLOAD": "PAYLOAD",
        "OPERATION_DESTINATION": "DESTINATION",
        "ACTOR_ATTRIBUTION": "ACTOR",
        "REFERENCE_RESOLUTION": "REFERENCE",
        "CONDITION_SCOPE": "CONDITION",
        "OPERATION_CHANNEL": "CHANNEL",
    }
    evid = {e["id"] for e in envelope["evidence"]}
    for event in events:
        eid = event["event_id"]
        if eid in seen:
            raise ValueError("duplicate event")
        seen.add(eid)
        for ref in event["operation_evidence_ids"]:
            if ref not in evid:
                raise ValueError("missing operation proof")
        for l in event["links"]:
            if l["from_event_id"] != eid:
                raise ValueError("global cross-event relation")
            if targets[l["type"]] != l["to_role"]:
                raise ValueError("invalid typed relation")
            if l["support"] == "MECHANICAL_VERIFIED" and (not l["evidence_ids"]):
                raise ValueError("established relation without source")
            if any((ref not in evid for ref in l["evidence_ids"])):
                raise ValueError("link with unknown source")


def validate_envelope(envelope, *, original, exposed_snapshot_bytes=None):
    """Structural parity with frozen Gate3B, with explicit source dependency.

    ORIGINAL provenance/digest verification belongs to M1/acquisition. This
    method checks spans against the supplied original, not server identity.
    """
    _SCHEMA_VALIDATOR.validate(envelope)
    validate_source_spans(
        envelope, original, exposed_snapshot_bytes=exposed_snapshot_bytes
    )
    validate_event_graph(envelope)
    if envelope["analysis_status"] == "COMPLETE_IN_DECLARED_SCOPE":
        if envelope["coverage"]["omissions"] or not envelope["coverage"]["complete"]:
            raise ValueError("silent omissions")
    if envelope["mode"] == "SHADOW" and envelope["authority"] != "NON_AUTHORITATIVE":
        raise ValueError("shadow cannot authorize")
    validate_design_integrity(envelope)
    return True
