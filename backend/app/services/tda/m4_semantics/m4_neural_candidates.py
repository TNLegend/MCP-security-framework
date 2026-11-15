"""M4 research pipeline: autonomous GLiNER PASS10 -> frozen DeBERTa V2.

Outputs grounded, consultative candidates. No human-gold anchor is supplied.
No policy authority, network access, database, runtime permission, or repo mutations.
"""
from __future__ import annotations
import hashlib,json
from pathlib import Path
from collections import defaultdict
from typing import Any

from .v2_fourhead_inference import DebertaV2Predictor,digest,V2_SHA,TOKENIZER_JSON_SHA

GLSHA="6621bd9f90b9439d4b0883333c05a002bdae77b75b3e78d15f085830dd777130"
GL_FILE_SHA={
 "config.json":"5dee87c98247b89596b99994e957cf8eaa6f264b6ab1cc058234bae0d96bd312",
 "encoder_config/config.json":"9e0dc30d76a04a9dcbe1952637db55b0a3f7c1a0fe8c847c10a87355af3d60b0",
 "tokenizer_config.json":"8b3c1969bb7eb4be436b91fd5231b1136d8c89a210f3505dd5f7dc9126319032",
 "tokenizer.json":"cbc8ae6037812709c9c26f2a160f8dc48b0440bcb79c8141804259ae2d6adac3"}
ENTITIES=("predicate","object","source","destination","condition","qualifier")
ROLES=("HAS_OBJECT","HAS_SOURCE","HAS_DESTINATION","HAS_CONDITION","HAS_QUALIFIER")
ARG_TYPES={"HAS_OBJECT":"object","HAS_SOURCE":"source","HAS_DESTINATION":"destination",
           "HAS_CONDITION":"condition","HAS_QUALIFIER":"qualifier"}
RELATION_SETTINGS={"pair_cap":128,"argument_threshold":0.0,"heads_per_relation":32,"tails_per_relation":32}
MAX_WORDPIECES_PER_WINDOW=190
STRIDE_WORDPIECES=128
MAX_SOURCE_CHARACTERS=20_000
MAX_WINDOWS=32
def text_digest(text:str)->str:
 return hashlib.sha256(text.encode("utf-8")).hexdigest()

def _valid_span(s:dict,text:str)->bool:
 if not isinstance(s,dict):return False
 a,b=s.get("start"),s.get("end")
 return (type(a) is int and type(b) is int and
         0<=a<b<=len(text) and s.get("text")==text[a:b])
def _global_span(s:dict,window_text:str,base:int,full_text:str)->dict:
 if not _valid_span(s,window_text):raise ValueError("SPAN_NOT_EXACT_WINDOW_SOURCE")
 start,end=int(s["start"])+base,int(s["end"])+base
 if full_text[start:end]!=s["text"]:raise ValueError("SPAN_NOT_EXACT_ORIGINAL_SOURCE")
 return {"start":start,"end":end,"text":s["text"],
         "confidence":s.get("confidence")}

def _make_windows(text:str,tok)->list[dict]:
 encoding=tok(text,return_offsets_mapping=True,add_special_tokens=False,truncation=False)
 offsets=encoding["offset_mapping"]
 if not offsets:return []
 if len(offsets)>MAX_WORDPIECES_PER_WINDOW+(MAX_WINDOWS-1)*STRIDE_WORDPIECES:
  raise ValueError("SOURCE_EXCEEDS_EXPLICIT_MAX_WINDOWS_NO_TRUNCATION")
 windows=[];next_start=0
 while next_start<len(offsets):
  left=next_start;right=min(len(offsets),left+MAX_WORDPIECES_PER_WINDOW)
  # Padding whitespace is part of the original source but is not interpreted
  # by the tokenizer. No source text is rewritten or normalized.
  valid=[(a,b) for a,b in offsets[left:right] if b>a]
  if not valid:
   raise ValueError("TOKENIZER_WINDOW_WITHOUT_VALID_CHAR_OFFSETS")
  a,b=valid[0][0],valid[-1][1]
  if not(0<=a<b<=len(text)):raise ValueError("TOKENIZER_OFFSETS_OUTSIDE_SOURCE")
  win=text[a:b]
  # Tokenization at window borders can differ slightly. Enforce a bounded
  # headroom for GLiNER's label queries and assert no local source truncation.
  local=tok(win,add_special_tokens=False,truncation=False)["input_ids"]
  while len(local)>MAX_WORDPIECES_PER_WINDOW+5 and right-left>40:
   right-=8
   b=offsets[right-1][1]
   win=text[a:b]
   local=tok(win,add_special_tokens=False,truncation=False)["input_ids"]
  if len(local)>MAX_WORDPIECES_PER_WINDOW+5:
   raise ValueError("LOCAL_RETOKENIZATION_EXCEEDS_WINDOW_LIMIT")
  windows.append({"start":a,"end":b,"text":win,
     "source_token_start":left,"source_token_end":right,
     "actual_tokens":len(local)})
  if right==len(offsets):break
  next_start=min(left+STRIDE_WORDPIECES,right-1)
  if next_start<=left:raise RuntimeError("WINDOW_NONPROGRESS")
 if not windows or windows[-1]["source_token_end"]!=len(offsets):
  raise ValueError("INCOMPLETE_SOURCE_TOKEN_COVERAGE")
 if len(windows)>MAX_WINDOWS:raise ValueError("EXPLICIT_MAX_WINDOWS_EXCEEDED")
 return windows

class M4NeuralCandidates:
 def __init__(self,gliner_dir=None,db_predictor=None,verify=True):
  if gliner_dir is None or db_predictor is None:
   raise ValueError("EXPLICIT_FROZEN_GLINER_AND_DEBERTA_REQUIRED")
  import torch
  from gliner2 import AutoExtractor
  from gliner2.models.boundary.relations import RelationProposalSettings
  from transformers import AutoTokenizer
  gliner_dir=Path(gliner_dir)
  if verify:
   if digest(gliner_dir/"model.safetensors")!=GLSHA:
    raise ValueError("FROZEN_PASS10_WEIGHTS_MISMATCH")
   for name,expected in GL_FILE_SHA.items():
    if digest(gliner_dir/name)!=expected:
     raise ValueError("FROZEN_GLINER_CONFIG_OR_TOKENIZER_MISMATCH:"+name)
  self.tokenizer=AutoTokenizer.from_pretrained(
   str(gliner_dir),local_files_only=True,use_fast=True)
  if not self.tokenizer.is_fast:raise ValueError("GLINER_FAST_TOKENIZER_REQUIRED")
  self.gliner=AutoExtractor.from_pretrained(
    str(gliner_dir),local_files_only=True).to("cpu").eval()
  if not(self.gliner.architecture=="boundary" and self.gliner.enable_relations):
   raise ValueError("GLINER_ARCHITECTURE_MISMATCH")
  old=self.gliner.relation_pair_generator.settings
  if (old.heads_per_relation,old.tails_per_relation)!=(32,32):
   raise ValueError("PASS10_RELATION_HEAD_TAIL_SETTINGS_MISMATCH")
  self.gliner.relation_pair_generator.settings=RelationProposalSettings(
     heads_per_relation=32,tails_per_relation=32,pair_cap=128,argument_threshold=0.0)
  self.db=db_predictor if db_predictor is not None else DebertaV2Predictor(verify=verify)
  self.torch=torch

 def analyze(self,text:str,source_path:str="/description")->dict[str,Any]:
  if not isinstance(text,str) or not text.strip():raise ValueError("NONEMPTY_SOURCE_TEXT_REQUIRED")
  if len(text)>MAX_SOURCE_CHARACTERS:raise ValueError("SOURCE_TOO_LONG_REFUSED_NO_TRUNCATION")
  if not source_path.startswith("/") or "~" in source_path and not source_path.count("~0") and not source_path.count("~1"):
   raise ValueError("RFC6901_SOURCE_PATH_REQUIRED")
  windows=_make_windows(text,self.tokenizer)
  entities={k:{} for k in ENTITIES}
  relations={}
  unresolved=[]
  window_meta=[]
  with self.torch.inference_mode():
   for wi,w in enumerate(windows):
    body=w["text"];base=w["start"]
    # Exact predicate head set matches the fixed-label inference comparison.
    pred=self.gliner.extract_entities(body,["predicate"],threshold=.5,
        include_spans=True,include_confidence=True,max_len=256)
    args=self.gliner.extract_entities(body,list(ENTITIES[1:]),threshold=.5,
        include_spans=True,include_confidence=True,max_len=256)
    edge=self.gliner.extract_relations(body,list(ROLES),threshold=.5,
        include_spans=True,include_confidence=True,max_len=256)
    if not ("entities" in pred and "entities" in args and "relation_extraction" in edge):
     raise ValueError("UNEXPECTED_GLINER_OUTPUT_SHAPE")
    for typ,items in (("predicate",pred["entities"].get("predicate",[])),):
     for si,sp in enumerate(items):
      try:glob=_global_span(sp,body,base,text)
      except (ValueError,TypeError):
       unresolved.append({"kind":"INVALID_PREDICATE_SPAN","window":wi,"raw":sp})
       continue
      key=(glob["start"],glob["end"])
      before=entities[typ].get(key)
      if before is None or (glob.get("confidence") or 0)>(before.get("confidence") or 0):
       entities[typ][key]=glob
    for typ,items in args["entities"].items():
     if typ not in ENTITIES[1:]:
      unresolved.append({"kind":"UNKNOWN_ENTITY_TYPE","window":wi,"type":typ})
      continue
     for sp in items:
      try:glob=_global_span(sp,body,base,text)
      except (ValueError,TypeError):
       unresolved.append({"kind":"INVALID_ARGUMENT_SPAN","window":wi,"type":typ,"raw":sp})
       continue
      key=(glob["start"],glob["end"])
      before=entities[typ].get(key)
      if before is None or (glob.get("confidence") or 0)>(before.get("confidence") or 0):
       entities[typ][key]=glob
    for role,items in edge["relation_extraction"].items():
     if role not in ROLES:
      unresolved.append({"kind":"UNKNOWN_RELATION_TYPE","window":wi,"role":role})
      continue
     for r in items:
      try:
       h=_global_span(r["head"],body,base,text)
       t=_global_span(r["tail"],body,base,text)
      except (ValueError,KeyError,TypeError):
       unresolved.append({"kind":"INVALID_RELATION_OFFSET","window":wi,"role":role,"raw":r})
       continue
      key=(role,h["start"],h["end"],t["start"],t["end"])
      entry={"role":role,"head":h,"tail":t,"confidence":r.get("confidence"),
             "source_window_ids":[wi]}
      before=relations.get(key)
      if before is None:relations[key]=entry
      else:
       before["source_window_ids"].append(wi)
       if (entry.get("confidence") or 0)>(before.get("confidence") or 0):
        before["confidence"]=entry.get("confidence")
    window_meta.append({k:w[k] for k in ("start","end","source_token_start","source_token_end","actual_tokens")})
  pred_spans=set(entities["predicate"])
  edge_pairs=defaultdict(set)
  for k in relations:edge_pairs[k[1:]].add(k[0])
  event_map={}
  for (a,b),p in sorted(entities["predicate"].items()):
   eid="m4_evt_"+hashlib.sha256((source_path+":"+str(a)+":"+str(b)+":"+p["text"]).encode("utf8")).hexdigest()[:18]
   classif=self.db.predict(text,(a,b))
   event_map[(a,b)]={"event_id":eid,"predicate":p,"classification":classif,
                     "links":[],"uncertainty_reasons":[],
                     "source_path":source_path}
   if classif["status"]!="MODEL_HYPOTHESIS":
    event_map[(a,b)]["uncertainty_reasons"].append(classif.get("reason","CLASSIFICATION_UNRESOLVED"))
  for key,edge in sorted(relations.items()):
   role,ha,hb,ta,tb=key
   h=(ha,hb);t=(ta,tb)
   row=dict(edge)
   row["target_entity_detected"]=t in entities[ARG_TYPES[role]]
   row["multiple_roles_same_pair"]=len(edge_pairs[(ha,hb,ta,tb)])>1
   row["head_predicate_detected"]=h in pred_spans
   row["support"]="MODEL_HYPOTHESIS" if (row["target_entity_detected"]
        and not row["multiple_roles_same_pair"] and row["head_predicate_detected"]) else "UNRESOLVED"
   if not row["head_predicate_detected"]:
    unresolved.append({"kind":"ORPHAN_RELATION_HEAD","role":role,
      "head":edge["head"],"tail":edge["tail"],"confidence":edge.get("confidence")})
    continue
   if row["support"]=="UNRESOLVED":
    event_map[h]["uncertainty_reasons"].append("RELATION_AMBIGUOUS_OR_UNMATCHED_ARGUMENT")
   event_map[h]["links"].append(row)
  events=list(event_map.values())
  for e in events:
   e["uncertainty_reasons"]=sorted(set(e["uncertainty_reasons"]))
  return {"status":"RESEARCH_SHADOW_NOT_AUTHORIZED_FOR_SECURITY_DECISIONS",
    "mode":"SHADOW","authority":"NON_AUTHORITATIVE",
    "models":{"GLINER":"GLINER2.5_BASE_PASS10","DEBERTA":"DEBERTA_V3_SMALL_V2"},
    "model_artifacts_sha256":{"GLINER_weights":GLSHA,
       "DEBERTA_weights":V2_SHA,"DEBERTA_tokenizer":TOKENIZER_JSON_SHA},
    "model_thresholds":{"GLINER":0.5},"source_path":source_path,
    "source_sha256":text_digest(text),"source_length":len(text),
    "language_scope":"EN_ONLY","language_verified":False,
    "coverage":{"windows":window_meta,"source_tokens_covered":True,
                "complete_semantics_verified":False,"truncation_permitted":False,
                "unresolved_count":len(unresolved)},
    "events":events,"unresolved_predictions":unresolved,
    "raw_entity_counts":{k:len(v) for k,v in entities.items()},
    "raw_relation_count":len(relations),
    "warnings":["AI_ANNOTATED_TRAIN_DEV_NOT_HUMAN_GOLD",
      "SOURCE_METADATA_IS_NOT_EXECUTABLE_AUTHORITY",
      "LOW_CONFIDENCE_IS_NOT_CALIBRATED_PROBABILITY",
      "RELATION_SCOPE_CAN_BE_MISSED_ACROSS_WINDOWS",
      "SOURCE_AND_QUALIFIER_RELATIONS_REQUIRE_EXPLICIT_ADAPTER"]}
