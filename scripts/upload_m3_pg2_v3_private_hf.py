"""Publish frozen Prompt Guard 2 V3 to PRIVATE Hugging Face (owner action).

Default dry-run verifies exact five-file allowlist, bytes and SHA256 only.
--upload requires a cached HF write token and refuses any public repository.
Prints immutable uploaded commit SHA to pin into install_m3_pg2_v3.py.
Never prints tokens, model weights, or user descriptions.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import tempfile
import shutil

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/"backend")]
from scripts.install_m3_pg2_v3 import (
    EXPECTED,HF_REPO_ID,digest,verify_files,_private_hf_token,
)

def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source",type=Path,required=True)
    parser.add_argument("--upload",action="store_true",
                        help="explicitly create/upload to PRIVATE Hugging Face")
    args=parser.parse_args()
    verify_files(args.source)
    if not args.upload:
        print(json.dumps({
          "status":"DRY_RUN_VERIFIED_NO_UPLOAD",
          "repo_id":HF_REPO_ID,
          "private_required":True,
          "expected_files":len(EXPECTED),
          "sha256_weights":EXPECTED["model.safetensors"][0],
        },sort_keys=True))
        return 0
    from huggingface_hub import HfApi,hf_hub_download
    from huggingface_hub.utils import RepositoryNotFoundError
    api=HfApi()
    token=_private_hf_token()
    try:
        info=api.model_info(HF_REPO_ID,token=token)
        if info.private is not True:
            raise RuntimeError("REFUSE_UPLOAD_TO_PUBLIC_MODEL_REPOSITORY")
    except RepositoryNotFoundError:
        api.create_repo(repo_id=HF_REPO_ID,repo_type="model",
                        private=True,token=token,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="m3-v3-hf-allowlist-") as tmp:
        dest=Path(tmp)
        for name in EXPECTED:
            shutil.copyfile(args.source/name,dest/name)
        verify_files(dest)
        commit=api.upload_folder(
            folder_path=str(dest),
            repo_id=HF_REPO_ID,
            repo_type="model",
            token=token,
            commit_message="Freeze Prompt Guard 2 V3 M3 advisory research weights",
        )
    info=api.model_info(HF_REPO_ID,token=token)
    immutable_revision=info.sha
    if info.private is not True or not isinstance(immutable_revision,str) or len(immutable_revision)!=40:
        raise RuntimeError("HF_UPLOAD_DID_NOT_PROVE_PRIVATE_IMMUTABLE_REVISION")
    remote_files=set(api.list_repo_files(
        HF_REPO_ID,repo_type="model",revision=immutable_revision,token=token))
    # HF LFS may create .gitattributes automatically; allow only this
    # metadata (and an optional README), never extra weights/checkpoints.
    unexpected=remote_files-set(EXPECTED)-{".gitattributes","README.md"}
    if unexpected or not set(EXPECTED).issubset(remote_files):
        raise RuntimeError("HF_PRIVATE_REPO_CONTAINS_UNEXPECTED_FILES")
    for name,(sha,size) in EXPECTED.items():
        path=Path(hf_hub_download(
            repo_id=HF_REPO_ID,repo_type="model",filename=name,
            revision=immutable_revision,token=token))
        if path.stat().st_size!=size or digest(path)!=sha:
            raise RuntimeError("HF_REDOWNLOAD_NOT_MATCHING_CHECKPOINT:"+name)
    print(json.dumps({
      "status":"PRIVATE_HF_UPLOAD_VERIFIED",
      "repo_id":HF_REPO_ID,
      "revision":immutable_revision,
      "private":True,
      "sha256_weights":EXPECTED["model.safetensors"][0],
      "files_verified":len(EXPECTED),
      "next":"Pin this immutable revision in HF_FROZEN_REVISION and test startup",
    },sort_keys=True))
    return 0

if __name__=="__main__":
    raise SystemExit(main())
