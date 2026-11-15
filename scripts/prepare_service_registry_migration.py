"""Lot62: controlled, minimally scoped public service-identity migration.

The installed registry is READ ONLY. Generates a separate candidate under
an explicitly named path after source-byte SHA256 pin and real Ed25519
private/public identity match. Never prints PEM, reads user tokens, changes
private keys, or writes to the active registry path.

The candidate must be approved/deployed separately after preflight.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey,Ed25519PublicKey

from app.core.config import settings
from app.services.signed_service_request import (
    SERVICE_ID_PROXY,SERVICE_ID_DISCOVERY,
    PERMISSION_RUNTIME_DISPATCH_ADMIT,
)
from scripts.check_signed_service_registry import (
    REQUIRED_PERMISSIONS,check_service_registry_permissions,
)


class RegistryMigrationError(RuntimeError):
    pass


def _private_matches_public(private_path: Path, registered_key: dict) -> bool:
    try:
        private=serialization.load_pem_private_key(private_path.read_bytes(),password=None)
        public=serialization.load_pem_public_key(
            registered_key["public_key_pem"].encode("utf-8"))
    except (KeyError,TypeError,ValueError,OSError):
        return False
    if not isinstance(private,Ed25519PrivateKey) or not isinstance(public,Ed25519PublicKey):
        return False
    return (
        private.public_key().public_bytes(
            serialization.Encoding.Raw,serialization.PublicFormat.Raw
        ) == public.public_bytes(
            serialization.Encoding.Raw,serialization.PublicFormat.Raw
        )
    )


def plan_registry_migration(
    source: Path,*,expected_sha256: str,
    proxy_private_path: Path,discovery_private_path: Path,
    proxy_key_id: str,discovery_key_id: str,
) -> tuple[dict,dict]:
    try:
        raw=source.read_bytes()
    except OSError as exc:
        raise RegistryMigrationError("registry_source_missing") from exc
    digest=sha256(raw).hexdigest()
    if len(expected_sha256)!=64 or expected_sha256!=digest:
        raise RegistryMigrationError("registry_source_digest_changed")
    try:
        current=json.loads(raw)
    except ValueError as exc:
        raise RegistryMigrationError("registry_source_invalid") from exc
    services=current.get("services") if isinstance(current,dict) else None
    if not isinstance(services,dict) or set(services)!={SERVICE_ID_PROXY,SERVICE_ID_DISCOVERY}:
        raise RegistryMigrationError("registry_services_unexpected")
    key_configs={
        SERVICE_ID_PROXY:(proxy_key_id,proxy_private_path),
        SERVICE_ID_DISCOVERY:(discovery_key_id,discovery_private_path),
    }
    for service,(key_id,key_path) in key_configs.items():
        item=services[service]
        if not isinstance(item,dict):
            raise RegistryMigrationError("registry_service_invalid")
        perms=item.get("permissions")
        if (
            not isinstance(perms,list) or not all(isinstance(p,str) for p in perms)
            or len(set(perms))!=len(perms)
        ):
            raise RegistryMigrationError("registry_permissions_invalid")
        expected=set(REQUIRED_PERMISSIONS[service])
        before=expected-{PERMISSION_RUNTIME_DISPATCH_ADMIT} if service==SERVICE_ID_PROXY else expected
        if set(perms)!=before:
            raise RegistryMigrationError("registry_privilege_delta_unexpected")
        keys=item.get("keys")
        if (
            not isinstance(keys,list) or len(keys)!=1 or not isinstance(keys[0],dict)
            or keys[0].get("key_id")!=key_id
            or not _private_matches_public(key_path,keys[0])
        ):
            raise RegistryMigrationError("registry_signer_binding_invalid")

    # JSON object is a new object, never mutate any loaded external state.
    modified=json.loads(raw)
    modified["services"][SERVICE_ID_PROXY]["permissions"]=[
        *modified["services"][SERVICE_ID_PROXY]["permissions"],
        PERMISSION_RUNTIME_DISPATCH_ADMIT,
    ]
    before_keys={name:services[name]["keys"] for name in key_configs}
    after_keys={name:modified["services"][name]["keys"] for name in key_configs}
    assert before_keys==after_keys,"registry_keys_changed"
    assert modified["services"][SERVICE_ID_DISCOVERY]==services[SERVICE_ID_DISCOVERY]
    assert set(modified["services"][SERVICE_ID_PROXY]["permissions"])==set(
        REQUIRED_PERMISSIONS[SERVICE_ID_PROXY]
    )
    summary={
        "status":"CANDIDATE_READY_NOT_DEPLOYED",
        "source_sha256":digest,
        "added_permission":PERMISSION_RUNTIME_DISPATCH_ADMIT,
        "changed_service":SERVICE_ID_PROXY,
        "unchanged_service":SERVICE_ID_DISCOVERY,
        "public_key_material_unchanged":True,
        "private_public_signatures_match":True,
        "candidate_bytes_sha256":sha256(
            (json.dumps(modified,ensure_ascii=False,sort_keys=True,indent=2)+"\n")
            .encode("utf-8")
        ).hexdigest(),
    }
    return modified,summary


def write_candidate(
    source:Path,target:Path,*,expected_sha256:str,
    proxy_private_path:Path,discovery_private_path:Path,
    proxy_key_id:str,discovery_key_id:str,
) -> dict:
    resolved_source=source.resolve(strict=True)
    resolved_target=target.resolve()
    if resolved_source==resolved_target:
        raise RegistryMigrationError("candidate_cannot_replace_installed_registry")
    if target.exists() or target.is_symlink() or not target.parent.is_dir():
        raise RegistryMigrationError("candidate_target_not_new")
    modified,summary=plan_registry_migration(
        source,expected_sha256=expected_sha256,
        proxy_private_path=proxy_private_path,
        discovery_private_path=discovery_private_path,
        proxy_key_id=proxy_key_id,discovery_key_id=discovery_key_id,
    )
    output=json.dumps(modified,ensure_ascii=False,sort_keys=True,indent=2)+"\n"
    # Exclusive creation; never overwrite an existing file even on a race.
    fd=os.open(str(target),os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    try:
        with os.fdopen(fd,"w",encoding="utf-8",newline="\n") as handle:
            handle.write(output)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        target.unlink(missing_ok=True)
        raise
    assert sha256(target.read_bytes()).hexdigest()==summary["candidate_bytes_sha256"]
    assert check_service_registry_permissions(
        target,proxy_key_id=proxy_key_id,discovery_key_id=discovery_key_id,
    )["status"]=="PASS"
    return dict(summary,candidate_path=str(target))


def main()->int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source",type=Path,default=Path(settings.internal_service_public_keys_path))
    parser.add_argument("--expected-sha256",required=True)
    parser.add_argument("--target",type=Path)
    parser.add_argument("--write-candidate",action="store_true")
    args=parser.parse_args()
    try:
        if args.write_candidate:
            if args.target is None:raise RegistryMigrationError("candidate_target_required")
            result=write_candidate(
                args.source,args.target,expected_sha256=args.expected_sha256,
                proxy_private_path=Path(settings.mcp_proxy_service_private_key_path),
                discovery_private_path=Path(settings.mcp_discovery_service_private_key_path),
                proxy_key_id=settings.mcp_proxy_service_key_id,
                discovery_key_id=settings.mcp_discovery_service_key_id,
            )
        else:
            _,result=plan_registry_migration(
                args.source,expected_sha256=args.expected_sha256,
                proxy_private_path=Path(settings.mcp_proxy_service_private_key_path),
                discovery_private_path=Path(settings.mcp_discovery_service_private_key_path),
                proxy_key_id=settings.mcp_proxy_service_key_id,
                discovery_key_id=settings.mcp_discovery_service_key_id,
            )
        print(json.dumps(result,sort_keys=True))
        return 0
    except RegistryMigrationError as exc:
        print(json.dumps({"status":"REFUSED","reason":str(exc)},sort_keys=True))
        return 2


if __name__=="__main__":
    raise SystemExit(main())
