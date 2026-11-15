r"""Prepare, sign and verify the V19.3 TDA M4 release with an owner key.

No training, no private key export, no DB write, no automatic activation.
Only the operator executing the SIGN command can grant a code/model identity.
This does not grant MCP execution permissions or approve a ToolAnalysis.

Examples (from repository root, using the project's backend venv):
  python scripts/sign_tda_m4_v193.py keygen --owner-keystore C:\owner-private\TDA_Keys
  python scripts/sign_tda_m4_v193.py prepare --preparation release\tda\m4_v193\unsigned
  python scripts/sign_tda_m4_v193.py sign --preparation release\tda\m4_v193\unsigned --owner-keystore C:\owner-private\TDA_Keys --signed-output release\tda\m4_v193\signed
  python scripts/sign_tda_m4_v193.py verify --preparation release\tda\m4_v193\unsigned --owner-keystore C:\owner-private\TDA_Keys --signed-output release\tda\m4_v193\signed

A private signing key MUST be stored outside this repository; the public
fingerprint must be pinned independently by the deployment owner before launch.
"""
from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile


ROOT=Path(__file__).resolve().parents[1]
MODEL_ROOT=ROOT/".runtime/models/m4_semantics"
for entry in (ROOT/"backend",ROOT):
    if str(entry) not in sys.path:
        sys.path.insert(0,str(entry))
PRIVATE_NAME="tda-owner-deployment-ed25519-private.pem"
# Existing owner keypairs may use the historical encrypted PEM name.
LEGACY_ENCRYPTED_PRIVATE_NAME="tda-owner-deployment-ed25519-encrypted.pem"
PUBLIC_NAME="tda-owner-deployment-ed25519-public.pem"
M4_MANIFEST="M4_MODEL_MANIFEST_UNSIGNED.json"
V2_MANIFEST="M4_ANALYZER_V2_MANIFEST_UNSIGNED.json"
M4_SIGNATURE="m4-model-signature.base64"
V2_SIGNATURE="tda-owner-signature.base64"
APPROVAL="tda-owner-approval.json"
RELEASE_REVISION="tool-description-analyzer-v19.3-signed-semantic-m4-replay-presence-fix"


class ReleaseRefused(RuntimeError):
    pass


def refuse(message: str):
    raise ReleaseRefused(message)


def outside_repo(path: Path) -> Path:
    path=path.expanduser().resolve()
    if path == ROOT or ROOT in path.parents:
        refuse("owner_private_key_directory_must_be_outside_repository")
    return path


def modules():
    from app.services.tda_application import pipeline as P
    from app.services.tda_application import m4_pipeline_integrity as M
    from app.services.tda.configuration import ANALYZER_REVISION
    if ANALYZER_REVISION != RELEASE_REVISION:
        refuse("analyzer_revision_not_this_release")
    if os.getenv("ANALYZER_PIPELINE_BINDINGS"):
        refuse("legacy_v1_model_bindings_present")
    if any(key.startswith("M4_NEURAL_SHADOW_") for key in os.environ):
        refuse("retired_m4_environment_variables_present")
    return P,M


def json_file(path: Path, value: object):
    data=(json.dumps(value,sort_keys=True,indent=2,
                     ensure_ascii=False,allow_nan=False)+"\n").encode("utf8")
    try:
        with path.open("xb") as fp:
            fp.write(data)
    except FileExistsError:
        refuse("existing_output_refused_no_overwrite:"+str(path))


def text_file(path: Path, value: str):
    try:
        with path.open("x",encoding="ascii",newline="\n") as fp:
            fp.write(value.strip()+"\n")
    except FileExistsError:
        refuse("existing_output_refused_no_overwrite:"+str(path))


def verify_path_source(model_root: Path):
    model_root=model_root.expanduser().resolve(strict=True)
    if model_root != MODEL_ROOT.resolve(strict=True):
        refuse("unexpected_m4_model_bundle_location")
    return model_root


def signed_m4_environment(manifest, key, public_key: Path, P, M):
    signature=base64.b64encode(key.sign(M.DOMAIN+P.canonical(manifest))).decode("ascii")
    return {
        "M4_SEMANTICS_MODEL_ROOT":str(MODEL_ROOT.resolve(strict=True)),
        "M4_SEMANTICS_IDENTITY_MANIFEST":None,
        "M4_SEMANTICS_APPROVED_SHA256":P.digest(manifest),
        "M4_SEMANTICS_SIGNATURE":signature,
        "M4_SEMANTICS_TRUST_KEY":str(public_key),
    }


def build_manifests(P,M,key,public_key: Path,model_root:Path,qa_root:Path):
    """Build V2 with an in-memory temporary signed M4 identity.

    This proves a candidate V2 manifest can be computed. No signer approval
    is implied until a human subsequently confirms the exact V2 digest.
    """
    m4=M.build_research_candidate(ROOT,model_root)
    m4path=qa_root/"m4-candidate-proposal.json"
    m4path.write_text(json.dumps(m4,sort_keys=True,ensure_ascii=False),encoding="utf8")
    values=signed_m4_environment(m4,key,public_key,P,M)
    values["M4_SEMANTICS_IDENTITY_MANIFEST"]=str(m4path)
    envnames=("M4_SEMANTICS_IDENTITY_MANIFEST","M4_SEMANTICS_APPROVED_SHA256",
              "M4_SEMANTICS_SIGNATURE","M4_SEMANTICS_TRUST_KEY",
              "M4_SEMANTICS_MODEL_ROOT")
    previous={name:os.environ.get(name) for name in envnames}
    try:
        os.environ.update(values)
        v2=P.build_m4_pipeline_v2_manifest(ROOT,model_root)
    finally:
        for name,val in previous.items():
            if val is None:os.environ.pop(name,None)
            else:os.environ[name]=val
    if v2.get("policy_authority")!="NONE" or m4.get("policy_authority")!="NONE":
        refuse("m4_policy_authority_nonempty")
    if v2.get("m6_embedding",{}).get("name")!="intfloat/multilingual-e5-small":
        refuse("m6_e5_signature_binding_missing")
    if not v2.get("m6_embedding",{}).get("files"):
        refuse("m6_e5_artifacts_not_verified")
    return m4,v2


def keygen(args):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    directory=outside_repo(args.owner_keystore)
    if directory.exists() and not directory.is_dir():
        refuse("owner_keystore_not_directory")
    directory.mkdir(parents=True,exist_ok=True)
    private=directory/PRIVATE_NAME
    historical_private=directory/LEGACY_ENCRYPTED_PRIVATE_NAME
    public=directory/PUBLIC_NAME
    if private.exists() or historical_private.exists() or public.exists():
        refuse("existing_owner_key_material_refused_no_overwrite_use_sign")
    password=getpass.getpass("New owner private-key passphrase: ")
    again=getpass.getpass("Confirm passphrase: ")
    if len(password)<12 or password!=again:
        refuse("passphrase_must_match_and_have_at_least_12_characters")
    key=Ed25519PrivateKey.generate()
    encrypted=key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(password.encode("utf8"))
    )
    publicbytes=key.public_key().public_bytes(
        serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo
    )
    fd=os.open(private,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,"wb") as fp:fp.write(encrypted)
    fd=os.open(public,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,"wb") as fp:fp.write(publicbytes)
    print("KEYPAIR_CREATED_OUTSIDE_REPO",directory)
    print("OWNER_PUBLIC_KEY_SHA256",hashlib.sha256(publicbytes).hexdigest())
    print("Keep private key and password safe; restrict Windows ACLs to the owner.")
    print("No code/model release has been approved or signed.")
    return 0


def read_key(directory):
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    directory=outside_repo(directory)
    private=directory/PRIVATE_NAME
    historical_private=directory/LEGACY_ENCRYPTED_PRIVATE_NAME
    public=directory/PUBLIC_NAME
    if private.is_file() and historical_private.is_file():
        refuse("ambiguous_owner_private_key_files_refused")
    if not private.is_file() and historical_private.is_file():
        private=historical_private
    if not private.is_file() or not public.is_file():
        refuse("existing_owner_private_and_public_key_required")
    try:
        pw=getpass.getpass("Owner private-key passphrase: ")
        key=load_pem_private_key(private.read_bytes(),pw.encode("utf8"))
    except Exception as exc:
        raise ReleaseRefused("private_key_or_passphrase_invalid") from exc
    if not isinstance(key,Ed25519PrivateKey):
        refuse("only_ed25519_private_key_supported")
    expected=key.public_key().public_bytes(
        serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo
    )
    if expected!=public.read_bytes():
        refuse("public_key_not_derived_from_private_key")
    return key,public


def load_review(preparation:Path,P):
    m4path=preparation/M4_MANIFEST
    v2path=preparation/V2_MANIFEST
    if not m4path.is_file() or not v2path.is_file():
        refuse("prepared_unsigned_model_and_analyzer_manifests_required")
    try:
        m4=json.loads(m4path.read_text(encoding="utf8"))
        v2=json.loads(v2path.read_text(encoding="utf8"))
    except (ValueError,OSError) as exc:
        raise ReleaseRefused("invalid_unsigned_preparation") from exc
    if not isinstance(m4,dict) or not isinstance(v2,dict):
        refuse("invalid_unsigned_manifest")
    if v2.get("m4_signed_identity_sha256")!=P.digest(m4):
        refuse("analyzer_manifest_not_linked_to_m4_model")
    if v2.get("execution",{}).get("analyzer_revision")!=RELEASE_REVISION:
        refuse("incorrect_signed_analyzer_revision")
    return m4,v2


def prepare(args):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    P,M=modules()
    model=verify_path_source(MODEL_ROOT)
    prep=args.preparation.expanduser().resolve()
    if prep==ROOT or not prep.is_relative_to(ROOT):
        refuse("preparation_must_be_under_repository_release_directory")
    prep.mkdir(parents=True,exist_ok=True)
    if (prep/M4_MANIFEST).exists() or (prep/V2_MANIFEST).exists():
        refuse("existing_preparation_refused_use_new_output_directory")
    key=Ed25519PrivateKey.generate()
    with tempfile.TemporaryDirectory(prefix="tda-m4-v193-prepare-") as td:
        scratch=Path(td)
        pub=scratch/"ephemeral-public.pem"
        pub.write_bytes(key.public_key().public_bytes(
            serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo
        ))
        m4,v2=build_manifests(P,M,key,pub,model,scratch)
    json_file(prep/M4_MANIFEST,m4)
    json_file(prep/V2_MANIFEST,v2)
    print("UNSIGNED_PREPARATION_COMPLETE_NOT_APPROVED")
    print("M4_MODEL_SHA256",P.digest(m4))
    print("V193_ANALYZER_SHA256",P.digest(v2))
    print("MODEL_ARTIFACTS",len(m4["model_artifacts"]),"E5_ARTIFACTS",len(v2["m6_embedding"]["files"]))
    print("Review manifest/source/weights and all limitations before signing.")
    return 0


def deploy_environment(preparation:Path,signed_dir:Path,public_key:Path,m4,v2,P):
    return {
      "ANALYZER_M4_V2_ENABLED":"1",
      "M4_SEMANTICS_MODEL_ROOT":str(MODEL_ROOT.resolve(strict=True)),
      "M4_SEMANTICS_IDENTITY_MANIFEST":str(preparation/M4_MANIFEST),
      "M4_SEMANTICS_APPROVED_SHA256":P.digest(m4),
      "M4_SEMANTICS_SIGNATURE":(signed_dir/M4_SIGNATURE).read_text("ascii").strip(),
      "M4_SEMANTICS_TRUST_KEY":str(public_key),
      "ANALYZER_PIPELINE_MANIFEST":str(preparation/V2_MANIFEST),
      "ANALYZER_PIPELINE_APPROVED_SHA256":P.digest(v2),
      "ANALYZER_PIPELINE_SIGNATURE":(signed_dir/V2_SIGNATURE).read_text("ascii").strip(),
      "ANALYZER_PIPELINE_TRUST_KEY":str(public_key),
      "HF_HUB_OFFLINE":"1","TRANSFORMERS_OFFLINE":"1",
    }


def verify_signed(preparation,signed_dir,public_key,m4,v2,P,M):
    from app.services.tda_application.pipeline import configured_pipeline
    from app.services.tda_application.m4_pipeline_integrity import configured_m4_identity
    settings=deploy_environment(preparation,signed_dir,public_key,m4,v2,P)
    previous={name:os.environ.get(name) for name in settings}
    try:
        os.environ.update(settings)
        verified=configured_m4_identity(ROOT,MODEL_ROOT)
        pipeline=configured_pipeline()
        if pipeline.identity!=P.digest(v2) or verified.identity!=P.digest(m4):
            refuse("verified_signed_digest_mismatch")
        if pipeline.model_versions["embedding"]["name"]!="intfloat/multilingual-e5-small":
            refuse("m6_e5_model_not_bound")
        return pipeline
    finally:
        for name,val in previous.items():
            if val is None:os.environ.pop(name,None)
            else:os.environ[name]=val


def sign(args):
    P,M=modules()
    model=verify_path_source(MODEL_ROOT)
    preparation=args.preparation.expanduser().resolve(strict=True)
    signed_dir=args.signed_output.expanduser().resolve()
    if signed_dir==preparation or preparation in signed_dir.parents:
        refuse("signed_output_must_be_sibling_not_child_of_preparation")
    if signed_dir==ROOT or not signed_dir.is_relative_to(ROOT):
        refuse("signed_output_must_be_under_repository_release_directory")
    if signed_dir.exists() and any(signed_dir.iterdir()):
        refuse("signed_release_directory_must_be_empty")
    m4,v2=load_review(preparation,P)
    key,pub=read_key(args.owner_keystore)
    with tempfile.TemporaryDirectory(prefix="tda-m4-v193-final-") as td:
        new_m4,new_v2=build_manifests(P,M,key,pub,model,Path(td))
    if new_m4!=m4 or new_v2!=v2:
        refuse("source_artifacts_dependencies_or_e5_changed_since_preparation")
    owner_sha=hashlib.sha256(pub.read_bytes()).hexdigest()
    computed=P.digest(v2)
    print("MODEL_DIGEST",P.digest(m4))
    print("ANALYZER_DIGEST",computed)
    print("OWNER_PUBLIC_KEY_SHA256",owner_sha)
    print("LIMITATIONS: advisory M4, no new independent blind EN evaluation.")
    print("LIMITATIONS: does not authorize any MCP tool, production DB or runtime.")
    acknowledgement=input("Type SIGN "+computed+" to approve exactly these source/model bytes: ").strip()
    if acknowledgement!="SIGN "+computed:
        refuse("owner_explicit_signature_acknowledgement_missing")
    signed_dir.mkdir(parents=True,exist_ok=True)
    model_sig=base64.b64encode(key.sign(M.DOMAIN+P.canonical(m4))).decode("ascii")
    v2_sig=base64.b64encode(key.sign(P.M4_V2_DOMAIN+P.canonical(v2))).decode("ascii")
    text_file(signed_dir/M4_SIGNATURE,model_sig)
    text_file(signed_dir/V2_SIGNATURE,v2_sig)
    # Verify signature, local model bytes, source closure, dependencies, E5 before
    # writing owner-approval. Signatures alone do not enable a generation.
    pipeline=verify_signed(preparation,signed_dir,pub,m4,v2,P,M)
    approval={
      "status":"OWNER_SIGNED_NOT_ACTIVATED",
      "analyzer_revision":RELEASE_REVISION,
      "manifest_identity":pipeline.identity,
      "model_manifest_identity":P.digest(m4),
      "signer_public_key_sha256":owner_sha,
      "policy_authority":"NONE",
      "new_independent_en_test_status":"NOT_PERFORMED_BY_USER_DECISION",
      "production_activated":False,
    }
    json_file(signed_dir/APPROVAL,approval)
    print("OWNER_SIGNATURES_VALIDATED_RELEASE_FILES_PREPARED")
    print("M4_V193_APPROVED_PIPELINE_SHA256="+pipeline.identity)
    print("M4_V193_OWNER_PUBLIC_KEY_SHA256="+owner_sha)
    print("No process started, no database row modified, no MCP tool approved.")
    return 0


def verify(args):
    P,M=modules()
    prep=args.preparation.expanduser().resolve(strict=True)
    signed=args.signed_output.expanduser().resolve(strict=True)
    _,pub=outside_repo(args.owner_keystore),outside_repo(args.owner_keystore)/PUBLIC_NAME
    if not pub.is_file():refuse("owner_public_key_missing")
    m4,v2=load_review(prep,P)
    approval=json.loads((signed/APPROVAL).read_text(encoding="utf8"))
    if (approval.get("status")!="OWNER_SIGNED_NOT_ACTIVATED" or
        approval.get("manifest_identity")!=P.digest(v2) or
        approval.get("model_manifest_identity")!=P.digest(m4) or
        approval.get("signer_public_key_sha256")!=hashlib.sha256(pub.read_bytes()).hexdigest()):
        refuse("owner_approval_record_not_bound_to_this_release")
    pipeline=verify_signed(prep,signed,pub,m4,v2,P,M)
    print("V193_OWNER_SIGNATURE_VERIFY_PASS",pipeline.identity)
    print("NO_PRODUCTION_ACTIVATION")
    return 0


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    commands=parser.add_subparsers(dest="mode",required=True)
    key=commands.add_parser("keygen",help="create an encrypted Ed25519 owner key outside repo")
    key.add_argument("--owner-keystore",type=Path,required=True)
    prep=commands.add_parser("prepare",help="write unsigned model and analyzer manifests")
    prep.add_argument("--preparation",type=Path,required=True)
    for mode in ("sign","verify"):
        sub=commands.add_parser(mode)
        sub.add_argument("--preparation",type=Path,required=True)
        sub.add_argument("--owner-keystore",type=Path,required=True)
        sub.add_argument("--signed-output",type=Path,required=True)
    args=parser.parse_args()
    if args.mode=="keygen":return keygen(args)
    if args.mode=="prepare":return prepare(args)
    if args.mode=="sign":return sign(args)
    return verify(args)


if __name__=="__main__":
    try:
        raise SystemExit(main())
    except (ReleaseRefused,OSError,ValueError) as exc:
        print("TDA_V193_SIGNING_REFUSED:",str(exc),file=sys.stderr)
        raise SystemExit(2) from exc