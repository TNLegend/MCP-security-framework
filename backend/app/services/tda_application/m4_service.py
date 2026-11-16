"""Shared signed M4 inference and a read-only ADMIN view.

GLiNER/DeBERTa supply advisory text hypotheses only. M3/M6/M7 and
Proxy/Runtime retain decision authority. No automatic approvals or writes
through the administrative M4 endpoint.
"""
from __future__ import annotations
import os,threading
from pathlib import Path
from typing import Any
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.models.mcp_tool import MCPTool
from app.services.tda.m4_semantics.consumer_contract import project_m4_for_consumers
from app.services.tda.m7_assessment.m4_advisory import interpret_m4_directives_advisory
from app.services.tda.m6_comparison.consistency import inspect_m4_operations_advisory
from app.services.tda.m7_assessment.reduction import summarize_m4_evidence_advisory
from app.services.tda_application.m4_pipeline_integrity import configured_m4_identity
from app.models.tool_analysis import ToolObservedVersion, ToolProtocolObservation
from app.services.tda_application.m4_source_provenance import (
    M4SourceProvenanceUnverified,validate_recorded_source,
    validate_neural_m4_with_recorded_m1,
)

_INIT_LOCK=threading.Lock()
_INFER_LOCK=threading.Lock()
_ENGINE=None
_ENGINE_KEY=None

class M4NotConfigured(RuntimeError):
 pass

class M4Busy(RuntimeError):
 pass

def is_enabled()->bool:
 return os.environ.get("ANALYZER_M4_V2_ENABLED","0")=="1"

def _configured_paths():
 if any(name.startswith("M4_NEURAL_SHADOW_") for name in os.environ):
  raise M4NotConfigured("RETIRED_M4_ENVIRONMENT_VARIABLES_REFUSED")
 if not is_enabled():
  raise M4NotConfigured("M4_SEMANTICS_DISABLED")
 raw=os.environ.get("M4_SEMANTICS_MODEL_ROOT","").strip()
 if not raw:raise M4NotConfigured("MISSING_M4_SEMANTICS_MODEL_ROOT")
 root=Path(raw).expanduser().resolve(strict=True)
 if not root.is_dir():raise M4NotConfigured("INVALID_M4_NEURAL_MODEL_BUNDLE")
 # One self-contained exact bundle, no implicit dependency on old Codex paths.
 gl=root/"GLINER"
 db=root/"DEBERTA_V2"
 tok=db
 cfg=db/"config.json"
 if not (root/"M4_BUNDLE_SHA256_MANIFEST.json").is_file():
  raise M4NotConfigured("MODEL_BUNDLE_SHA256_MANIFEST_MISSING")
 for legacy,expected in (("M4_SEMANTICS_TOKENIZER_DIR",tok),
                         ("M4_SEMANTICS_CONFIG_FILE",cfg)):
  other=os.environ.get(legacy,"").strip()
  if other and Path(other).expanduser().resolve()!=expected:
   raise M4NotConfigured("SPLIT_MODEL_BUNDLE_ASSETS_FORBIDDEN")
 for path in (gl/"model.safetensors",db/"best_model.safetensors",
              db/"LABELS_FOUR_HEADS.json",tok/"spm.model",cfg):
  if not path.is_file():raise M4NotConfigured("FROZEN_ASSET_MISSING")
 return (gl,db,tok,cfg)

def _engine():
 global _ENGINE,_ENGINE_KEY
 paths=_configured_paths()
 # One signed M4 model identity. E5 stays in M6 and has its own binding.
 gl,db,tok,cfg=paths
 repo_root=Path(__file__).resolve().parents[4]
 identity=configured_m4_identity(repo_root,gl.parent)
 key=(paths,identity.identity)
 if _ENGINE is not None and _ENGINE_KEY==key:
  return _ENGINE
 with _INIT_LOCK:
  if _ENGINE is not None and _ENGINE_KEY==key:return _ENGINE
  from app.services.tda.m4_semantics.v2_fourhead_inference import DebertaV2Predictor
  from app.services.tda.m4_semantics.m4_neural_candidates import M4NeuralCandidates
  db_classifier=DebertaV2Predictor(weights=db/"best_model.safetensors",
       labels_path=db/"LABELS_FOUR_HEADS.json",config_path=cfg,
       tokenizer_dir=tok,verify=True)
  new=M4NeuralCandidates(gliner_dir=gl,db_predictor=db_classifier,verify=True)
  # Detect weights/source changed during model initialization.
  identity.verify()
  new._m4_verified_identity=identity
  _ENGINE=new;_ENGINE_KEY=key
  return _ENGINE

def infer_m4_signed_description(text: str, *, require_signed_identity: bool = True):
 """One shared, bounded GLiNER/DeBERTa inference for main and ADMIN paths.

 Protects runtime resources from concurrent independent model inference.
 The caller separately binds the description to its M1 observed tool version.
 """
 from app.services.tda_application.pipeline import PipelineIntegrityError
 if not _INFER_LOCK.acquire(blocking=False):
  raise M4Busy("M4_NEURAL_INFERENCE_ALREADY_RUNNING")
 try:
  active_engine=_engine()
  identity=getattr(active_engine,"_m4_verified_identity",None)
  if require_signed_identity and identity is None:
   raise PipelineIntegrityError("M4_SIGNED_IDENTITY_REQUIRED")
  result=active_engine.analyze(text,source_path="/description")
  if identity is not None:
   identity.verify()
  return result,identity
 finally:
  _INFER_LOCK.release()


def analyze_observed_version_readonly(db:Session,tool_id:int)->dict[str,Any]:
 """Select a saved observed version; no ability to analyze arbitrary URL/user text."""
 if not is_enabled():
  raise M4NotConfigured("M4_SEMANTICS_DISABLED")
 tool=db.get(MCPTool,tool_id)
 if tool is None:raise LookupError("TOOL_NOT_FOUND")
 if not isinstance(tool.current_fingerprint,str) or not tool.current_fingerprint:
  raise LookupError("NO_CURRENT_VERIFIED_TOOL_VERSION")
 version=db.scalar(
  select(ToolObservedVersion)
  .where(ToolObservedVersion.tool_id==tool_id)
  .where(ToolObservedVersion.fingerprint==tool.current_fingerprint)
  .order_by(ToolObservedVersion.id.desc()))
 if version is None:
  raise LookupError("CURRENT_VERSION_SNAPSHOT_NOT_FOUND")
 if version.tool_id != tool_id or version.fingerprint != tool.current_fingerprint:
  raise LookupError("STALE_OR_CROSS_TOOL_OBSERVED_VERSION")
 snapshot=version.snapshot
 if not isinstance(snapshot,dict) or not isinstance(snapshot.get("description"),str):
  raise ValueError("ORIGINAL_TOOL_SNAPSHOT_DESCRIPTION_NOT_AVAILABLE")
 if snapshot.get("name",snapshot.get("tool_name")) not in (None,tool.name):
  raise ValueError("TOOL_SNAPSHOT_NAME_MISMATCH")
 observation=db.scalar(
  select(ToolProtocolObservation)
  .where(ToolProtocolObservation.tool_id==tool_id)
  .where(ToolProtocolObservation.tool_fingerprint==version.fingerprint)
  .order_by(ToolProtocolObservation.last_seen_at.desc(),ToolProtocolObservation.id.desc()))
 provenance_issue=None
 try:
  validate_recorded_source(tool,version,observation)
 except M4SourceProvenanceUnverified as exc:
  provenance_issue=str(exc)
 # Both the controlling analyzer and the ADMIN read-only endpoint share
 # one bounded signed-model inference lock; no duplicate model worker.
 result,identity=infer_m4_signed_description(
  snapshot["description"],require_signed_identity=False
 )
 # Fail closed if an ADMIN or scanner replaced the current tool version
 # while the CPU model was running. A stale result must not be displayed
 # as analysis of the current fingerprint.
 if isinstance(db,Session):
  db.refresh(tool,attribute_names=["current_fingerprint"])
 if tool.current_fingerprint != version.fingerprint:
  raise LookupError("SOURCE_VERSION_CHANGED_DURING_M4_INFERENCE")
 # Validate against actual M1 parsed snapshot only when provenance is recorded.
 # No DB add/flush/commit and no invented transport-raw attestation.
 proof=None
 if provenance_issue is None:
  proof=validate_neural_m4_with_recorded_m1(result,tool,version,observation)
 consumer_views=project_m4_for_consumers(result,snapshot["description"])
 downstream_views={
  "m3":interpret_m4_directives_advisory(consumer_views["m3"]),
  "m6":inspect_m4_operations_advisory(consumer_views["m6"]),
  "m7":summarize_m4_evidence_advisory(consumer_views["m7"]),
 }
 return {
  "mode":"SHADOW","authority":"NON_AUTHORITATIVE",
  "administrative_action":"NONE",
  "source_kind":"PERSISTED_OBSERVED_MCP_TOOL",
  "tool_id":tool_id,"version_id":version.id,
  "source_fingerprint":version.fingerprint,
  "source_description_sha256":result["source_sha256"],
  "envelope_validation_status":("M1_PARSED_SNAPSHOT_VALIDATED"
         if proof is not None else "PENDING_VERIFIABLE_SOURCE_OBSERVATION"),
  "provenance_limitation":provenance_issue,
  "m1_parsed_source_proof":proof,
  "effects_on_approval_or_dispatch":"NONE",
  "m4_signed_pipeline_sha256":(getattr(identity,"identity",None)),
  "model_output":result,
  "m4_advisory_module_views":consumer_views,
  "m4_downstream_advisory":downstream_views,
 }
