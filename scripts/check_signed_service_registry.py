"""Read-only release gate for signed internal-service registry permissions.

Verifies the installed public-key registry grants precisely the minimum
permissions required by this code's signed endpoints. Does not provision
keys, modify files, start services, or expose PEMs or secret key material.
"""
from __future__ import annotations

import json
from pathlib import Path

from app.core.config import settings
from app.services.signed_service_request import (
    PERMISSION_EMERGENCY_DENY_CHECK,
    PERMISSION_INTERNAL_INVENTORY_SERVERS_READ,
    PERMISSION_INTERNAL_INVENTORY_TOOLS_READ,
    PERMISSION_INVENTORY_IMPORT_DISCOVERY,
    PERMISSION_RUNTIME_LOGS_WRITE,
    PERMISSION_RUNTIME_DISPATCH_ADMIT,
    SERVICE_ID_DISCOVERY, SERVICE_ID_PROXY,
)

REQUIRED_PERMISSIONS = {
    SERVICE_ID_PROXY: {
        PERMISSION_INTERNAL_INVENTORY_SERVERS_READ,
        PERMISSION_INTERNAL_INVENTORY_TOOLS_READ,
        PERMISSION_RUNTIME_LOGS_WRITE,
        PERMISSION_EMERGENCY_DENY_CHECK,
        PERMISSION_RUNTIME_DISPATCH_ADMIT,
    },
    SERVICE_ID_DISCOVERY: {PERMISSION_INVENTORY_IMPORT_DISCOVERY},
}


def check_service_registry_permissions(
    path: Path | None = None,
    *,
    proxy_key_id: str | None = None,
    discovery_key_id: str | None = None,
) -> dict[str, object]:
    registry_path=path or Path(settings.internal_service_public_keys_path)
    if not registry_path.is_file():
        return {"status":"FAIL", "reason":"service_public_registry_missing"}
    try:
        value=json.loads(registry_path.read_text(encoding="utf-8"))
    except (ValueError,OSError):
        return {"status":"FAIL","reason":"service_public_registry_invalid"}
    if not isinstance(value,dict) or not isinstance(value.get("services"),dict):
        return {"status":"FAIL","reason":"service_public_registry_invalid"}

    expected_ids={
        SERVICE_ID_PROXY:proxy_key_id or settings.mcp_proxy_service_key_id,
        SERVICE_ID_DISCOVERY:discovery_key_id or settings.mcp_discovery_service_key_id,
    }
    findings={}
    for service_name,required in REQUIRED_PERMISSIONS.items():
        entry=value["services"].get(service_name)
        if not isinstance(entry,dict):
            findings[service_name]={"service_missing":True}
            continue
        permissions=entry.get("permissions")
        if not isinstance(permissions,list) or not all(isinstance(p,str) for p in permissions):
            findings[service_name]={"permissions_invalid":True}
            continue
        missing=sorted(required.difference(permissions))
        keys=entry.get("keys")
        has_expected_key=(
            isinstance(keys,list)
            and any(
                isinstance(item,dict)
                and item.get("key_id")==expected_ids[service_name]
                and isinstance(item.get("public_key_pem"),str)
                and bool(item.get("public_key_pem").strip())
                for item in keys
            )
        )
        if missing or not has_expected_key:
            findings[service_name]={
                "missing_permissions":missing,
                "matching_public_signer_key_present":has_expected_key,
            }
    return {
        "status":"PASS" if not findings else "FAIL",
        "reason":"ready" if not findings else "internal_service_registry_outdated",
        "services_checked":len(REQUIRED_PERMISSIONS),
        "findings":findings,
    }


def main()->int:
    result=check_service_registry_permissions()
    print(json.dumps(result,sort_keys=True))
    return 0 if result["status"]=="PASS" else 1


if __name__=="__main__":
    raise SystemExit(main())
