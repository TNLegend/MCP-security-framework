from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = PROJECT_ROOT / "backend"
for path in (str(PROJECT_ROOT), str(BACKEND_DIR)):
    if path not in sys.path:
        sys.path.insert(0, path)

from proxy.tool_security_v2 import SecurityModelError, SupportedSchemaProfileV1  # noqa: E402
from proxy.protocol_revisions import ProtocolRevisionRegistry  # noqa: E402


def evaluate_inventory(payload: dict[str, Any]) -> dict[str, Any]:
    server = payload.get("server") or {}
    registry = ProtocolRevisionRegistry()
    supported_versions = tuple(server.get("supported_protocol_versions") or ())
    evaluations = []
    for tool in payload.get("tools") or []:
        name = str(tool.get("name") or "")
        profile = str(tool.get("upstream_protocol_profile_id") or "unknown")
        reasons: list[str] = []
        try:
            SupportedSchemaProfileV1.validate(tool.get("input_schema"))
        except SecurityModelError as exc:
            reasons.append(exc.code)
        evaluations.append(
            {
                "tool": name,
                "protocol_profile": profile,
                "schema_supported": not reasons,
                "generically_onboardable": not reasons,
                "rejection_reasons": reasons,
                "tool_specific_python_authorization_loc": _specific_auth_loc(name, "python"),
                "tool_specific_rego_loc": _specific_auth_loc(name, "rego"),
            }
        )
    return {
        "report_version": "1",
        "server": {
            "endpoint": server.get("endpoint"),
            "transport": server.get("transport"),
            "detected_era": server.get("detected_protocol_era"),
            "negotiated_mcp_version": server.get("negotiated_protocol_version")
            or server.get("protocol_version"),
            "preferred_mcp_version": server.get("preferred_protocol_version"),
            "protocol_transport_kind": server.get("protocol_transport_kind"),
            "server_supported_versions": list(supported_versions),
            "supported_protocol_profiles": server.get("supported_protocol_profiles") or [],
        },
        "supported_mcp_revisions": len(
            [version for version in supported_versions if registry.is_framework_supported(version)]
        ),
        "legacy_revisions_supported": len(
            [
                version
                for version in supported_versions
                if registry.is_framework_supported(version)
                and registry.get(version).era.value == "legacy"
            ]
        ),
        "modern_revisions_supported": len(
            [
                version
                for version in supported_versions
                if registry.is_framework_supported(version)
                and registry.get(version).era.value == "modern"
            ]
        ),
        "tools_discovered": len(evaluations),
        "tools_generically_onboardable": sum(
            1 for item in evaluations if item["generically_onboardable"]
        ),
        "tools_rejected": sum(1 for item in evaluations if not item["generically_onboardable"]),
        "tools": evaluations,
    }


def _specific_auth_loc(tool_name: str, language: str) -> int:
    if not tool_name:
        return 0
    escaped = re.escape(tool_name)
    patterns = (
        re.compile(rf"tool_name\s*==\s*['\"]{escaped}['\"]"),
        re.compile(rf"input\.tool(?:_name)?\s*==\s*['\"]{escaped}['\"]"),
    )
    if language == "rego":
        files = (PROJECT_ROOT / "policies" / "opa").glob("*.rego")
    else:
        files = (
            path
            for root in (PROJECT_ROOT / "proxy", PROJECT_ROOT / "backend" / "app")
            for path in root.rglob("*.py")
            if path.name != "lab_tool_compat.py"
        )
    count = 0
    for path in files:
        for line in path.read_text(encoding="utf-8").splitlines():
            if any(pattern.search(line) for pattern in patterns):
                count += 1
    return count


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate a saved MCP discovery payload against the generic v2 boundary."
    )
    parser.add_argument("inventory_json", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    payload = json.loads(args.inventory_json.read_text(encoding="utf-8"))
    report = evaluate_inventory(payload)
    rendered = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
