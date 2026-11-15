"""Frozen DeBERTa-v3-small V2: exact 4-head architecture and inference alignment.

Reproduces PASS7 V2 model's CLS + mean predicate span -> Linear/GELU/LayerNorm/Dropout -> 4 heads.
No training, no labels provided to inference, no test/reserve access.
"""
from __future__ import annotations
import hashlib,json
from pathlib import Path
from typing import Any

HEADS=("speech_act","actor","polarity","directive_force")
V2_SHA="331750fe70452dba7461d1dc1bc77cfc38726de59828d06588ae3c5c467c936d"
LABEL_SHA="9d27b331dde992b4f20714228b76c46556391af92cb73ca0b0e4aa37667ac6b1"
CONFIG_SHA="b0bb1caf90a50aa67d1085130508dfbf8646ac5a11928305e280b07a36e100ae"
TOKENIZER_SPM_SHA="c679fbf93643d19aab7ee10c0b99e460bdbc02fedf34b92b05af343b4af586fd"
TOKENIZER_JSON_SHA="e9ddd853a4a31023721c993458663f2019e3154a05dacf0d2b3c217e53d9bdc8"
TOKENIZER_CONFIG_SHA="28efde3273ceba3743712cfafd411e0a969507147b0cc8240a7089c18c9db2b4"

def digest(path: Path)->str:
 h=hashlib.sha256()
 with path.open("rb") as f:
  for b in iter(lambda:f.read(4*1024*1024),b""):h.update(b)
 return h.hexdigest()

def _nn():
 import torch
 from torch import nn
 from transformers import DebertaV2Config,DebertaV2Model
 class Model(nn.Module):
  def __init__(self, config_path, label_vocabulary):
   super().__init__()
   config=DebertaV2Config.from_pretrained(str(config_path),local_files_only=True)
   self.encoder=DebertaV2Model(config).float()
   hidden=self.encoder.config.hidden_size
   self.fuse=nn.Sequential(nn.Linear(hidden*2,hidden),nn.GELU(),nn.LayerNorm(hidden),nn.Dropout(.1))
   self.heads=nn.ModuleDict({h:nn.Linear(hidden,len(label_vocabulary[h])) for h in HEADS})
  def forward(self,ids,mask,span):
   z=self.encoder(input_ids=ids,attention_mask=mask).last_hidden_state
   ix=torch.arange(z.size(1),device=z.device)[None,:]
   select=(ix>=span[:,0,None])&(ix<span[:,1,None])&mask.bool()
   if not bool(select.any(1).all()):
    raise ValueError("PREDICATE_TOKEN_COVERAGE_EMPTY")
   pooled=(z*select.unsqueeze(-1)).sum(1)/select.sum(1).clamp_min(1).unsqueeze(1)
   feature=self.fuse(torch.cat([z[:,0],pooled],dim=-1))
   return {h:self.heads[h](feature) for h in HEADS}
 return Model

class DebertaV2Predictor:
 def __init__(self,weights=None,tokenizer_dir=None,config_path=None,
              labels_path=None,verify=True):
  if any(x is None for x in (weights,tokenizer_dir,config_path,labels_path)):
   raise ValueError("EXPLICIT_SIGNED_ASSET_PATHS_REQUIRED")
  import torch
  from safetensors.torch import load_file
  from transformers import AutoTokenizer
  self.weights=Path(weights)
  self.labels=json.loads(Path(labels_path).read_text(encoding="utf-8"))
  if tuple(self.labels)!=HEADS:raise ValueError("FOUR_HEAD_VOCAB_ORDER_CHANGED")
  if verify:
   if digest(self.weights)!=V2_SHA:raise ValueError("DEBERTA_V2_CHECKPOINT_HASH_MISMATCH")
   if digest(Path(labels_path))!=LABEL_SHA:raise ValueError("FOUR_HEAD_LABEL_HASH_MISMATCH")
   if digest(Path(config_path))!=CONFIG_SHA:
    raise ValueError("DEBERTA_V2_CONFIG_HASH_MISMATCH")
   for name,expected in (("spm.model",TOKENIZER_SPM_SHA),("tokenizer.json",TOKENIZER_JSON_SHA),
                         ("tokenizer_config.json",TOKENIZER_CONFIG_SHA)):
    if digest(Path(tokenizer_dir)/name)!=expected:
     raise ValueError("DEBERTA_V2_TOKENIZER_HASH_MISMATCH:"+name)
  self.tokenizer=AutoTokenizer.from_pretrained(str(tokenizer_dir),use_fast=True,local_files_only=True)
  if not self.tokenizer.is_fast or (self.tokenizer.cls_token_id,self.tokenizer.sep_token_id)!=(1,2):
   raise ValueError("DEBERTA_V2_TOKENIZER_INCOMPATIBLE")
  Model=_nn()
  self.model=Model(config_path,self.labels)
  state=load_file(str(self.weights),device="cpu")
  self.model.load_state_dict(state,strict=True)
  del state
  self.model.eval()
  self.torch=torch
 def align(self,text:str,span:tuple[int,int])->dict[str,Any]:
  start,end=span
  if not (isinstance(text,str) and 0<=start<end<=len(text)):
   return {"status":"INVALID_SOURCE_SPAN"}
  if not text[start:end].strip():
   return {"status":"EMPTY_PREDICATE"}
  enc=self.tokenizer(text,add_special_tokens=False,return_offsets_mapping=True,
                     return_attention_mask=False,truncation=False)
  seq=enc["input_ids"];offsets=enc["offset_mapping"];L=len(seq)
  hits=[i for i,(a,b) in enumerate(offsets) if b>a and b>start and a<end]
  if not hits:return {"status":"NO_MATCHING_TOKENS","original_token_count":L}
  lo,hi=hits[0],hits[-1]+1
  if offsets[lo][0]>start or offsets[hi-1][1]<end:
   return {"status":"INCOMPLETE_TOKEN_COVERAGE","original_token_count":L}
  if (text[offsets[lo][0]:start]+text[end:offsets[hi-1][1]]).strip():
   return {"status":"NONWHITESPACE_BOUNDARY","original_token_count":L}
  if hi-lo>254:return {"status":"PREDICATE_EXCEEDS_254_TOKENS","original_token_count":L}
  # Match training-time "center window around predicate" exactly, without truncation.
  cap=254
  left=max(0,min(lo-(cap-(hi-lo))//2,max(0,L-cap)))
  right=min(L,left+cap)
  if not(left<=lo<hi<=right):
   return {"status":"ANCHOR_NOT_IN_TOKEN_WINDOW","original_token_count":L}
  ids=[self.tokenizer.cls_token_id]+seq[left:right]+[self.tokenizer.sep_token_id]
  span_tokens=(lo-left+1,hi-left+1)
  if not (len(ids)<=256 and 1<=span_tokens[0]<span_tokens[1]<=len(ids)-1):
   return {"status":"INVALID_TOKEN_WINDOW","original_token_count":L}
  return {"status":"OK","input_ids":ids,
   "predicate_token_range_exclusive":span_tokens,
   "original_token_count":L,"token_window":[left,right],
   "source_span":[start,end],"source_excerpt":text[start:end]}
 def predict(self,text:str,span:tuple[int,int])->dict[str,Any]:
  aligned=self.align(text,span)
  if aligned["status"]!="OK":
   return {"status":"UNRESOLVED","reason":aligned["status"],
           "source_span":list(span),"source_excerpt":text[span[0]:span[1]] if 0<=span[0]<span[1]<=len(text) else ""}
  ids=self.torch.tensor([aligned["input_ids"]],dtype=self.torch.long)
  mask=self.torch.ones_like(ids)
  pred=self.torch.tensor([aligned["predicate_token_range_exclusive"]],dtype=self.torch.long)
  with self.torch.inference_mode():
   logits=self.model(ids,mask,pred)
  results={}
  for h in HEADS:
   probabilities=self.torch.softmax(logits[h][0].float(),dim=-1)
   k=int(probabilities.argmax().item())
   results[h]={"label":self.labels[h][k],"id":k,
      "confidence":round(float(probabilities[k].item()),7),
      "probabilities":[round(float(x),7) for x in probabilities.tolist()]}
  return {"status":"MODEL_HYPOTHESIS","heads":results,
    "source_span":list(span),"source_excerpt":text[span[0]:span[1]],
    "token_window":aligned["token_window"],
    "token_alignment_status":"SAFE_WHITESPACE_ONLY"}
