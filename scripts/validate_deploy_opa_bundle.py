"""Qualify a pinned two-policy OPA bundle without touching a live OPA service.

--freeze updates the local manifest only during an explicitly reviewed release.
Default mode validates manifest and runs both Runtime and Deploy checks.
No AWS, database or policy upload action is performed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
POLICIES = ROOT / "policies/opa"
MANIFEST = POLICIES / "deploy_bundle_manifest.json"
FILES = ("runtime_policy.rego", "deploy_security.rego")
RUNTIME = "data.mcp.security.runtime.decision"
DEPLOY = "data.mcp.security.deploy.decision"


def digest(path: Path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def manifest_payload():
    return {
        "format": "deploy-opa-local-bundle-v1",
        "policy_revision": "opa-deploy-security-advisory-v1",
        "runtime_decision_path": RUNTIME,
        "deploy_decision_path": DEPLOY,
        "policy_sha256": {name: digest(POLICIES/name) for name in FILES},
    }


def verify(opa: str | None):
    if not MANIFEST.is_file():
        raise RuntimeError("BUNDLE_MANIFEST_MISSING")
    expected=manifest_payload()
    try:
        pinned=json.loads(MANIFEST.read_text(encoding="utf-8"))
    except (ValueError,UnicodeError) as exc:
        raise RuntimeError("BUNDLE_MANIFEST_INVALID") from exc
    if pinned != expected:
        raise RuntimeError("BUNDLE_MANIFEST_HASH_OR_VERSION_DRIFT")
    other={p.name for p in POLICIES.glob("*.rego")}-set(FILES)
    if other:
        raise RuntimeError("UNPINNED_REGO_POLICIES_PRESENT")
    if opa is None:
        raise RuntimeError("OPA_BINARY_REQUIRED_FOR_RELEASE_QUALIFICATION")
    check=subprocess.run([opa,"check","--strict",str(POLICIES)],
                         capture_output=True,text=True,timeout=20)
    if check.returncode:
        raise RuntimeError("OPA_BUNDLE_COMPILE_FAILED")

    def decision(files, query):
        with tempfile.TemporaryDirectory() as folder:
            inp=Path(folder)/"empty_input.json"
            inp.write_text("{}",encoding="utf-8")
            cmd=[opa,"eval","--format=json","--strict",
                 "--input",str(inp)]
            for file in files:
                cmd.extend(["--data",str(file)])
            cmd.append(query)
            result=subprocess.run(cmd,capture_output=True,text=True,timeout=20)
            if result.returncode:
                raise RuntimeError("OPA_DECISION_EVAL_FAILED")
            parsed=json.loads(result.stdout)
            return parsed["result"][0]["expressions"][0]["value"]

    runtime_alone=decision([POLICIES/FILES[0]],RUNTIME)
    runtime_together=decision([POLICIES/FILES[0],POLICIES/FILES[1]],RUNTIME)
    if runtime_alone!=runtime_together:
        raise RuntimeError("OPA_RUNTIME_DECISION_CHANGED_AFTER_ADDING_DEPLOY")
    deploy=decision([POLICIES/FILES[0],POLICIES/FILES[1]],DEPLOY)
    if not isinstance(deploy,dict) or deploy.get("runtime_enforcement") is not False:
        raise RuntimeError("OPA_DEPLOY_ADVISORY_BOUNDARY_FAILED")
    print("OPA_DUAL_POLICY_BUNDLE_VALID",expected["policy_revision"])
    return expected


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--freeze",action="store_true",
                        help="Update pinned hashes during reviewed release")
    parser.add_argument("--opa",default=shutil.which("opa"))
    args=parser.parse_args()
    try:
        if args.freeze:
            MANIFEST.write_text(json.dumps(
                manifest_payload(),sort_keys=True,indent=2)+"\n",encoding="utf-8")
        verify(args.opa)
    except (RuntimeError,OSError,subprocess.TimeoutExpired,KeyError,IndexError) as exc:
        print("OPA_BUNDLE_QUALIFICATION_FAILED",str(exc),file=sys.stderr)
        return 1
    return 0


if __name__=="__main__":
    raise SystemExit(main())
