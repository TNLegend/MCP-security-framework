"""Locally computed SHA-256 identity for the EN-only GLiNER/DeBERTa M4.

The pinned checkpoint and bundled-file SHA checks remain strict; a digest
identifies bytes but does not authenticate a publisher or authorize a tool.
No owner signing keys, signature files or approval ceremony are required.
M6 E5 drift remains a separate dependency.
"""
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path, PurePosixPath
from typing import Any

from app.services.tda_application._integrity import (
    PipelineIntegrityError, digest, file_digest,
)
from common.source_closure import is_private_qa_source

SCHEMA="m4_semantic_model_identity_v2"
MODEL_FILES=frozenset({
 "GLINER/model.safetensors",
 "GLINER/config.json",
 "GLINER/encoder_config/config.json",
 "GLINER/tokenizer.json",
 "GLINER/tokenizer_config.json",
 "DEBERTA_V2/best_model.safetensors",
 "DEBERTA_V2/LABELS_FOUR_HEADS.json",
 "DEBERTA_V2/spm.model",
 "DEBERTA_V2/tokenizer.json",
 "DEBERTA_V2/tokenizer_config.json",
 "DEBERTA_V2/config.json",
 "M4_BUNDLE_SHA256_MANIFEST.json",
})
SOURCE_ROOTS=(
 "backend/app",
 "proxy",
 "common",
 "agent",
 "scanners",
 "policies",
 "frontend/src",
 "frontend/index.html",
 "frontend/package.json",
 "backend/requirements.txt",
 "scripts",
)
SOURCE_SUFFIXES=frozenset({
 ".py",".js",".jsx",".ts",".tsx",".json",".yaml",".yml",".toml",
 ".txt",".rego",".sql",".html",".css",".sh",".ps1",
})
RELATION_PARAMETERS={"pair_cap":128,"argument_threshold":0.0,
                     "heads_per_relation":32,"tails_per_relation":32}
MODELS={"GLINER":"GLINER2.5_BASE_PASS10","DEBERTA":"DEBERTA_V3_SMALL_V2"}
FROZEN_WEIGHTS_SHA256={
 "GLINER/model.safetensors":"6621bd9f90b9439d4b0883333c05a002bdae77b75b3e78d15f085830dd777130",
 "DEBERTA_V2/best_model.safetensors":"331750fe70452dba7461d1dc1bc77cfc38726de59828d06588ae3c5c467c936d",
}
HEADS=["speech_act","actor","polarity","directive_force"]


def valid_relpath(value: str) -> PurePosixPath:
    if not isinstance(value,str) or not value or "\\" in value or ":" in value:
        raise PipelineIntegrityError("m4_invalid_artifact_path")
    p=PurePosixPath(value)
    if p.is_absolute() or any(x in ("..",".","") for x in p.parts):
        raise PipelineIntegrityError("m4_invalid_artifact_path")
    if p.as_posix()!=value:
        raise PipelineIntegrityError("m4_noncanonical_artifact_path")
    return p


def secure_file(root: Path, rel: str) -> Path:
    value=valid_relpath(rel)
    root=root.resolve(strict=True)
    probe=root
    for part in value.parts:
        probe=probe/part
        if probe.is_symlink() or getattr(probe,"is_junction",lambda:False)():
            raise PipelineIntegrityError("m4_linked_artifact_not_allowed")
    try:
        path=probe.resolve(strict=True)
        path.relative_to(root)
    except (OSError,ValueError) as exc:
        raise PipelineIntegrityError("m4_artifact_outside_root_or_missing") from exc
    if not path.is_file():
        raise PipelineIntegrityError("m4_artifact_not_a_file")
    return path


def source_inventory(repo_root: Path) -> dict[str,dict[str,Any]]:
    """Full declared source-root closure including GUI and executable M4 code."""
    result={}
    repo_root=Path(repo_root).resolve(strict=True)
    for rel in SOURCE_ROOTS:
        root=repo_root/rel
        if root.is_symlink() or getattr(root,"is_junction",lambda:False)() or not root.exists():
            raise PipelineIntegrityError("m4_source_root_missing_or_linked")
        candidates=[root] if root.is_file() else sorted(root.rglob("*"))
        for p in candidates:
            if "__pycache__" in p.parts or p.name.startswith("."):
                continue
            if p.is_symlink() or getattr(p,"is_junction",lambda:False)():
                raise PipelineIntegrityError("m4_linked_source_rejected")
            if not p.is_file() or p.suffix.lower() not in SOURCE_SUFFIXES:
                continue
            # Developer-only QA files are ignored by Git and absent from
            # portable installs; never bind runtime identity to their bytes.
            if is_private_qa_source(p):
                continue
            key=p.relative_to(repo_root).as_posix()
            secure_file(repo_root,key)
            result[key]={"bytes":p.stat().st_size,"sha256":file_digest(p)}
    if not result:
        raise PipelineIntegrityError("m4_no_source_files")
    return result


def artifact_inventory(model_root: Path) -> dict[str,dict[str,Any]]:
    root=Path(model_root).resolve(strict=True)
    files=[]
    for p in sorted(root.rglob("*")):
        if p.is_symlink() or getattr(p,"is_junction",lambda:False)():
            raise PipelineIntegrityError("m4_linked_model_artifact")
        if p.is_file():
            files.append(p.relative_to(root).as_posix())
    if set(files)!=MODEL_FILES or len(files)!=len(MODEL_FILES):
        raise PipelineIntegrityError("m4_model_bundle_files_changed")
    # Every artifact is still fully SHA-256 checked, including the frozen
    # checkpoint files. Independent hashes can run concurrently; this does
    # not trust timestamps, byte counts or a previous request's cache.
    validated = [(name, secure_file(root,name)) for name in files]

    def _hash_entry(entry):
        name, path = entry
        return name, {"bytes": path.stat().st_size, "sha256": file_digest(path)}

    with ThreadPoolExecutor(max_workers=min(3, len(validated))) as pool:
        return dict(pool.map(_hash_entry, validated))


def build_research_candidate(repo_root:Path,model_root:Path)->dict[str,Any]:
    """Fingerprint installed M4 files and sources; no signing/approval implied."""
    assets=artifact_inventory(model_root)
    for file,expected in FROZEN_WEIGHTS_SHA256.items():
        if assets[file]["sha256"]!=expected:
            raise PipelineIntegrityError("m4_selected_checkpoint_sha_changed")
    recorded=json.loads((Path(model_root)/"M4_BUNDLE_SHA256_MANIFEST.json").read_text(encoding="utf8"))
    if set(recorded.get("files",{}))!=MODEL_FILES-{"M4_BUNDLE_SHA256_MANIFEST.json"}:
        raise PipelineIntegrityError("m4_frozen_research_bundle_invalid")
    for name,entry in recorded["files"].items():
        if assets[name]["sha256"]!=entry.get("sha256") or assets[name]["bytes"]!=entry.get("bytes"):
            raise PipelineIntegrityError("m4_bundle_manifest_hash_mismatch")
    return {
        "schema":SCHEMA,
        "purpose":"EN_ONLY_STRUCTURED_M4_SEMANTICS_ADVISORY",
        "model_names":MODELS.copy(),
        "model_artifacts":assets,
        "source_roots":list(SOURCE_ROOTS),
        "source_artifacts":source_inventory(repo_root),
        "decoder":{"GLINER_relations":RELATION_PARAMETERS.copy(),
                   "GLINER_entity_threshold":0.5,
                   "DeBERTa_heads":HEADS.copy()},
        "primary_semantic_engine":"GLINER2.5_PASS10_PLUS_DEBERTA_V2_ONLY",
        "policy_authority":"NONE",
        "model_lineage":"GLINER_PASS10_DEBERTA_V2_EN_ONLY",
    }


class VerifiedM4SemanticIdentity:
    """Local content fingerprint; never authorization or publisher attestation."""

    def __init__(self, manifest:dict, repo_root:Path, model_root:Path):
        self._bind_contract(manifest,repo_root,model_root)
        self.verify()

    @classmethod
    def from_fresh_local_inventory(cls,repo_root:Path,model_root:Path):
        """Compute one complete SHA-256 snapshot before binding this identity.

        build_research_candidate already checks every frozen artifact hash,
        manifest entry, and eligible source file. A second immediate read of
        those identical files adds latency without an independent trust anchor.
        Direct construction and explicit verify() still check current bytes.
        """
        manifest=build_research_candidate(repo_root,model_root)
        identity=cls.__new__(cls)
        identity._bind_contract(manifest,repo_root,model_root)
        return identity

    def _bind_contract(self,manifest:dict,repo_root:Path,model_root:Path):
        if not isinstance(manifest,dict) or manifest.get("schema")!=SCHEMA:
            raise PipelineIntegrityError("m4_invalid_identity_schema")
        if (manifest.get("purpose")!="EN_ONLY_STRUCTURED_M4_SEMANTICS_ADVISORY"
                or manifest.get("model_names")!=MODELS
                or manifest.get("policy_authority")!="NONE"
                or manifest.get("primary_semantic_engine")!="GLINER2.5_PASS10_PLUS_DEBERTA_V2_ONLY"):
            raise PipelineIntegrityError("m4_unsafe_semantic_contract")
        if manifest.get("source_roots")!=list(SOURCE_ROOTS):
            raise PipelineIntegrityError("m4_source_roots_changed")
        if manifest.get("decoder")!={
            "GLINER_relations":RELATION_PARAMETERS,
            "GLINER_entity_threshold":0.5,
            "DeBERTa_heads":HEADS,
        }:
            raise PipelineIntegrityError("m4_decoder_settings_changed")
        self.repo_root=Path(repo_root)
        self.model_root=Path(model_root)
        self.manifest=manifest
        self.identity=digest(manifest)

    def verify(self)->str:
        # The public bundle contains frozen per-file hashes; known checkpoint
        # weights also match the independent pins in this module. Other
        # sources are fingerprinted to detect changes in one process.
        observed=build_research_candidate(self.repo_root,self.model_root)
        if observed!=self.manifest:
            raise PipelineIntegrityError("m4_local_source_or_artifact_changed")
        return self.identity


def configured_m4_identity(repo_root:Path,model_root:Path)->VerifiedM4SemanticIdentity:
    """Use installed model/source bytes, never owner keys or signature env."""
    import os
    if any(name.startswith("M4_NEURAL_SHADOW_") for name in os.environ):
        raise PipelineIntegrityError("retired_m4_environment_variables_refused")
    return VerifiedM4SemanticIdentity.from_fresh_local_inventory(repo_root,model_root)
