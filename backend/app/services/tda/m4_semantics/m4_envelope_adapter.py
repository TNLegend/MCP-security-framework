"""Strict, non-authoritative M4 envelope adapter for the existing Gate3B schema.

The trusted caller supplies the original M1 snapshot and its source_context;
never fabricate acquisition/identity hashes or an actor permission grant.
"""
from __future__ import annotations
import hashlib
from pathlib import Path
from typing import Any
from .m4_neural_candidates import text_digest

SCHEMA_VERSION="1.0.1-closure-design"
MODEL_IDENTITY="GLINER2.5_BASE_PASS10+DEBERTA_V3_SMALL_V2"
LINK_MAP={
 "HAS_OBJECT":("PAYLOAD","OPERATION_PAYLOAD"),
 "HAS_DESTINATION":("DESTINATION","OPERATION_DESTINATION"),
 "HAS_CONDITION":("CONDITION","CONDITION_SCOPE"),
}
SCHEMA_ACTOR={"TOOL":"TOOL","THIRD_PARTY":"THIRD_PARTY"}
SCHEMA_POLARITY={"AFFIRMED":"POSITIVE","DENIED":"NEGATIVE"}
SCHEMA_FRAMING={"CLAIM":"ASSERTION","DIRECTIVE":"INSTRUCTION"}

def to_envelope(report:dict[str,Any],original:dict[str,Any],source_context:dict[str,Any],
                source_path:str="/description")->dict[str,Any]:
 if report.get("mode")!="SHADOW" or report.get("authority")!="NON_AUTHORITATIVE":
  raise ValueError("NON_SHADOW_REPORT_REFUSED")
 if report.get("source_path")!=source_path:raise ValueError("M4_SOURCE_POINTER_MISMATCH")
 if source_path!="/description":
  # Narrow integration candidate; arbitrary pointers require a separate test.
  raise ValueError("NON_DESCRIPTION_SOURCE_NOT_QUALIFIED")
 if not isinstance(original,dict) or not isinstance(original.get("description"),str):
  raise ValueError("TRUSTED_ORIGINAL_SNAPSHOT_REQUIRED")
 text=original["description"]
 if report.get("source_sha256")!=text_digest(text):
  raise ValueError("REPORT_SNAPSHOT_SOURCE_HASH_MISMATCH")
 snapshot_id=source_context.get("snapshot_id")
 if not isinstance(snapshot_id,str) or not snapshot_id:
  raise ValueError("M1_SOURCE_IDENTITY_REQUIRED")
 # Check remaining structure through official repository validator before export.
 ev_list=[];proof={};observations=[];omissions=[]
 def mkproof(span,role):
  a,b=span.get("start"),span.get("end")
  if not(type(a)==int and type(b)==int and 0<=a<b<=len(text)
       and text[a:b]==span.get("text")):
   raise ValueError("INEXACT_OR_SYNTHETIC_EVIDENCE_REFUSED")
  hid=hashlib.sha256((snapshot_id+"|"+source_path+"|"+str(a)+"|"+str(b)).encode("utf8")).hexdigest()[:22]
  evidence_id="m4_ev_"+hid
  if evidence_id not in proof:
   proof[evidence_id]={"id":evidence_id,"snapshot_id":snapshot_id,
     "path":source_path,"start":a,"end":b,"excerpt":span["text"],
     "verified":True,"source_role":"ORIGINAL","view_id":None,"transform_chain":[]}
  return evidence_id
 for row in report.get("events",[]):
  predicate=row.get("predicate")
  if not isinstance(predicate,dict):raise ValueError("EVENT_MISSING_PREDICATE")
  pid=mkproof(predicate,"OPERATION")
  cls=row.get("classification") or {}
  raw=cls.get("heads") or {}
  def label(name):
   val=raw.get(name)
   return val.get("label") if isinstance(val,dict) else None
  speech,actor,polarity=label("speech_act"),label("actor"),label("polarity")
  reasons=list(row.get("uncertainty_reasons") or [])
  if cls.get("status")!="MODEL_HYPOTHESIS":
   reasons.append("DEBERTA_V2_UNRESOLVED")
  if actor not in SCHEMA_ACTOR:
   reasons.append("ACTOR_NOT_EXACTLY_MAPPABLE_TO_GATE3B")
  if polarity not in SCHEMA_POLARITY:
   reasons.append("POLARITY_NOT_EXACTLY_MAPPABLE_TO_GATE3B")
  if speech not in SCHEMA_FRAMING:
   reasons.append("FRAMING_NOT_EXACTLY_MAPPABLE_TO_GATE3B")
  mapped_actor=SCHEMA_ACTOR.get(actor,"UNKNOWN")
  mapped_framing=SCHEMA_FRAMING.get(speech,"UNKNOWN")
  # AI-only classification is never mechanical evidence of an actual tool effect.
  # Preserve predicted TOOL/CLAIM labels, but never promote them to TOOL_EFFECT.
  claim_role="UNRESOLVED"
  reasons.append("MODEL_ONLY_EFFECT_CLAIM_NOT_VERIFIED")
  links=[]
  for link in row.get("links",[]):
   role=link["role"]
   if role not in LINK_MAP:
    reasons.append("UNREPRESENTABLE_RELATION_"+str(role))
    omissions.append({"path":source_path,
      "reason":"M4_TYPE_SYSTEM_HAS_NO_EXACT_"+str(role)+"_LINK_MAPPING"})
    continue
   head_id=mkproof(link["head"],"RELATION_HEAD")
   tail_id=mkproof(link["tail"],"RELATION_TAIL")
   if head_id!=pid:
    # A relation attached to the wrong predicate must not be emitted as a fact.
    reasons.append("RELATION_EVENT_PREDICATE_MISMATCH")
    continue
   to_role,typ=LINK_MAP[role]
   links.append({"from_event_id":row["event_id"],"to_role":to_role,"type":typ,
     "support":("MODEL_HYPOTHESIS" if link.get("support")=="MODEL_HYPOTHESIS"
                   else "UNRESOLVED"),"evidence_ids":[head_id,tail_id]})
  ev={"event_id":row["event_id"],"operation":predicate["text"],
   "polarity":SCHEMA_POLARITY.get(polarity,"UNKNOWN"),
   "framing":mapped_framing,"actor":mapped_actor,
   "claim_role":claim_role,
   "declared_boundary":"UNKNOWN",
   "authorized_boundary":"NOT_EVALUATED",
   "operation_evidence_ids":[pid],
   "links":links,
   "uncertainty_reasons":sorted(set(reasons+[
       "MODEL_PREDICTIONS_ARE_UNTRUSTED_METADATA",
       "DECLARED_BEHAVIOR_NOT_RUNTIME_PERMISSION"]))}
  ev_list.append(ev)
  observations.append({"id":"M4:"+row["event_id"],
    "kind":"SEMANTIC_HYPOTHESIS","support":"MODEL_HYPOTHESIS",
    "status":"OBSERVED","evidence_ids":[pid],"dependency_ids":[],
    "scope":source_path,"reason":None,
    "method_id":"gliner-pass10+deberta-v2",
    "method_version":"candidate-v1"})
 for u in report.get("unresolved_predictions",[]):
  kind=str(u.get("kind","UNKNOWN"))
  omissions.append({"path":source_path,"reason":"UNRESOLVED_"+kind})
 # Explicitly maintain incomplete semantic coverage while AI labels and
 # relation mapping are not independently qualified.
 omissions.append({"path":source_path,
   "reason":"SEMANTIC_COMPLETENESS_NOT_INDEPENDENTLY_VERIFIED"})
 for item in omissions:
  if not item["reason"]:raise ValueError("EMPTY_OMISSION_REASON")
 # The schema permits "PARTIAL" and incomplete coverage. A ML confidence
 # alone is never promoted to "COMPLETE_IN_DECLARED_SCOPE".
 src_file=Path(__file__)
 analyzer_identity={"name":"m4-semantics-v19",
     "version":"candidate-v1",
     "source_sha256":hashlib.sha256(src_file.read_bytes()).hexdigest(),
     "model_identity":MODEL_IDENTITY}
 env={"schema_version":SCHEMA_VERSION,"module_id":"M4","mode":"SHADOW",
      "authority":"NON_AUTHORITATIVE","source_context":dict(source_context),
      "analyzer_identity":analyzer_identity,"analysis_status":"PARTIAL",
      "coverage":{"scope":[source_path],"complete":False,"semantic_complete":False,
      "entries":[{"path":source_path,"state":"INTERPRETED",
         "reason":"MODEL_HYPOTHESES_ONLY_UNQUALIFIED_SEMANTIC_SCOPE"}],
      "omissions":list({(x["path"],x["reason"]):x for x in omissions}.values())},
      "evidence":list(proof.values()),"observations":observations,
      "result":{"events":ev_list,"legacy_transfer_signal":{}},
      "limitations":["MODEL_IS_CONSULTATIVE_ONLY",
        "NOT_AN_AUTHORIZED_CAPABILITY_OR_RUNTIME_PERMISSION",
        "ANNOTATIONS_AI_ONLY_NOT_HUMAN_GOLD",
        "ENGLISH_ONLY_MODEL_NOT_MULTILINGUAL_QUALIFIED",
        "UNREPRESENTED_SOURCE_AND_QUALIFIER_ROLES_STAY_UNRESOLVED",
        "LONG_RANGE_RELATIONS_MAY_BE_MISSED"]}
 return env
