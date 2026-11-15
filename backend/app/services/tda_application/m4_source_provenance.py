"""Source-bound Gate3B M4 adapter from recorded M1 PARSED snapshot.

This validates M1's parsed snapshot identity and evidence offsets. It is NOT
a transport-raw attestation, runtime permission, or signed deployment identity.
Require a matching persisted ToolProtocolObservation; never invent one.
"""
from __future__ import annotations

from hashlib import sha256
from typing import Any

from app.services.tda.m1_sources.capture import capture_context
from app.services.tda.m5_context.identity import (compute_tool_fingerprint,normalize_description)
from app.services.tda.design_contracts.envelopes import validate_envelope
from app.services.tda.m4_semantics.m4_envelope_adapter import to_envelope


class M4SourceProvenanceUnverified(ValueError):
    pass


def validate_recorded_source(tool: Any, version: Any, observation: Any) -> None:
    """No fuzzy names, silent normalization, or inferred observation identity."""
    if observation is None:
        raise M4SourceProvenanceUnverified("NO_MATCHING_PROTOCOL_OBSERVATION")
    snapshot=getattr(version,"snapshot",None)
    original=getattr(observation,"canonical_tool_definition",None)
    tool_id=getattr(tool,"id",None)
    fingerprint=getattr(version,"fingerprint",None)
    if not isinstance(snapshot,dict) or not isinstance(original,dict):
        raise M4SourceProvenanceUnverified("NOT_JSON_OBJECT_SNAPSHOT")
    if not isinstance(snapshot.get("description"),str) or not snapshot["description"].strip():
        raise M4SourceProvenanceUnverified("DESCRIPTION_EMPTY")
    if not isinstance(fingerprint,str) or len(fingerprint)!=64:
        raise M4SourceProvenanceUnverified("VERSION_FINGERPRINT_NOT_SHA256")
    if any(getattr(x,"tool_id",None)!=tool_id for x in (version,observation)):
        raise M4SourceProvenanceUnverified("TOOL_ID_MISMATCH")
    if (getattr(tool,"current_fingerprint",None)!=fingerprint or
        getattr(observation,"tool_fingerprint",None)!=fingerprint):
        raise M4SourceProvenanceUnverified("OBSERVATION_FINGERPRINT_MISMATCH")
    if not (getattr(tool,"name",None)==getattr(version,"tool_name",None)
            ==getattr(observation,"tool_name",None)
            ==snapshot.get("name")==original.get("tool_name")):
        raise M4SourceProvenanceUnverified("TOOL_NAME_MISMATCH")
    if (getattr(version,"server_ref",None)!=getattr(observation,"server_ref",None)):
        raise M4SourceProvenanceUnverified("SERVER_IDENTITY_MISMATCH")
    # Tool fingerprints are built from the normalized description; the
    # recorded snapshot may preserve formatting. Never rewrite source spans.
    if normalize_description(snapshot["description"])!=original.get("description"):
        raise M4SourceProvenanceUnverified("CANONICAL_OBSERVATION_DESCRIPTION_MISMATCH")
    for key in ("input_schema","output_schema","annotations","execution"):
        if (snapshot.get(key) or {})!=(original.get(key) or {}):
            raise M4SourceProvenanceUnverified("CANONICAL_SCHEMA_FIELD_MISMATCH:"+key)
    try:
        expected_fingerprint=compute_tool_fingerprint(original)
    except (ValueError,TypeError) as exc:
        raise M4SourceProvenanceUnverified("INVALID_CANONICAL_FINGERPRINT_SOURCE") from exc
    if expected_fingerprint!=fingerprint:
        raise M4SourceProvenanceUnverified("CANONICAL_FINGERPRINT_DIGEST_MISMATCH")
    profile=getattr(observation,"upstream_protocol_profile_id",None)
    if not isinstance(profile,str) or not profile.strip():
        raise M4SourceProvenanceUnverified("PROTOCOL_PROFILE_NOT_RECORDED")
    if getattr(observation,"analysis_state",None)=="STALE":
        raise M4SourceProvenanceUnverified("STALE_PROTOCOL_OBSERVATION")
    if not isinstance(getattr(version,"id",None),int) or not isinstance(getattr(observation,"id",None),int):
        raise M4SourceProvenanceUnverified("PERSISTED_VERSION_IDS_REQUIRED")


def m1_context_from_recorded_parsed_snapshot(tool:Any,version:Any,observation:Any):
    validate_recorded_source(tool,version,observation)
    snapshot=version.snapshot
    # M1 checks strict JSON, freezes parsed snapshot bytes and computes
    # canonical ORIGINAL parsed identity. These are NOT network raw bytes.
    ctx=capture_context(snapshot,profile=getattr(version,"profile_snapshot",None))
    if ctx.acquisition_scope!="PARSED_SNAPSHOT_ONLY":
        raise M4SourceProvenanceUnverified("UNEXPECTED_M1_ACQUISITION_SCOPE")
    if not any(f.pointer=="/description" and f.text==snapshot["description"]
               for f in ctx.source_fields):
        raise M4SourceProvenanceUnverified("DESCRIPTION_NOT_M1_SOURCE_FIELD")
    context={
      "acquisition_id":"m1-parsed:"+ctx.context_id,
      "snapshot_id":ctx.original.view_id,
      "registration_id":"persisted-tool:"+str(tool.id),
      "tool_name":tool.name,
      "protocol_profile_id":observation.upstream_protocol_profile_id,
      "authority_id":None,
      "verified_principal_id":None,
      "catalog_generation":None,
      "observation_revision":"persisted-observation:"+str(observation.id),
      "agent_view_id":None,
      "raw_sha256":None,
      "canonical_original_sha256":ctx.canonical_original_sha256,
      "exposed_projection_sha256":None,
      "legacy_tool_fingerprint":version.fingerprint,
      "contract_sha256":None,
      "policy_sha256":None,
      "analysis_context_sha256":None,
    }
    return context,ctx


def validate_neural_m4_with_recorded_m1(
    report:dict[str,Any],tool:Any,version:Any,observation:Any
)->dict[str,Any]:
    context,source=m1_context_from_recorded_parsed_snapshot(tool,version,observation)
    envelope=to_envelope(report,version.snapshot,context,source_path="/description")
    validate_envelope(envelope,original=version.snapshot)
    # Validate the canonical M1 identity against source once more.
    if context["canonical_original_sha256"]!=source.canonical_original_sha256:
        raise M4SourceProvenanceUnverified("ORIGINAL_CONTEXT_DIGEST_MISMATCH")
    return {
      "attestation_scope":"M1_PARSED_SNAPSHOT_ONLY_NOT_RAW_TRANSPORT",
      "transport_raw_attested":False,
      "official_original_source_validated_against_M1":True,
      "snapshot_id":source.original.view_id,
      "canonical_original_sha256":context["canonical_original_sha256"],
      "envelope":envelope,
    }
