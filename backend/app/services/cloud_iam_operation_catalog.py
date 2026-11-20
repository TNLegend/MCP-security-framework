"""Compile read-only AWS IAM *candidates* from static MCP code observations.

This is a pre-approval preview. It never creates signed contract effects, grants
IAM access or claims AWS authorization. A checked-in snapshot of the official
AWS Service Authorization Reference provides provenance and version pinning.
"""
from __future__ import annotations

import json
from pathlib import Path

PROTOTYPE_CATALOG = Path(__file__).parent / "data" / "cloud_aws_authorization_prototype_v1.json"
MAX_CATALOG_BYTES = 5_000_000


class CatalogError(ValueError):
    pass


def load_prototype_catalog(path=PROTOTYPE_CATALOG):
    target = Path(path)
    if not target.is_file() or target.is_symlink() or target.stat().st_size > MAX_CATALOG_BYTES:
        raise CatalogError("AWS_CATALOG_UNAVAILABLE_OR_OVERSIZED")
    content = json.loads(target.read_text(encoding="utf-8"))
    if (not isinstance(content, dict) or
        content.get("schema_version") != "aws-sdk-action-candidates-prototype-v1" or
        content.get("sdk") != "Boto3" or
        not isinstance(content.get("services"), dict)):
        raise CatalogError("AWS_CATALOG_INVALID_SCHEMA")
    return content


def candidate_preview(report, catalog=None):
    if catalog is None:
        catalog = load_prototype_catalog()
    if report.get("schema_version") != "static-aws-discovery-prototype-v1":
        raise CatalogError("STATIC_REPORT_VERSION_UNSUPPORTED")
    results = []
    for observation in report.get("operations", []):
        service, method = observation.get("service"), observation.get("operation")
        destination = observation.get("destination")
        service_entry = catalog.get("services", {}).get(service, {})
        operation_entry = service_entry.get("operations", {}).get(method)
        actions = (
            operation_entry.get("authorized_action_candidates") or []
            if isinstance(operation_entry, dict) else []
        )
        candidate = None
        status = "UNKNOWN"
        reason = "AWS_CATALOG_OPERATION_NOT_MAPPED"
        if destination == "LOCAL":
            reason = "NON_AWS_LOCAL_ENDPOINT"
            status = "NO_PRODUCTION_IAM_PROPOSED"
        elif destination != "AWS_DEFAULT":
            reason = "AWS_DESTINATION_NOT_VERIFIED"
        elif not actions:
            reason = "AWS_CATALOG_OPERATION_NOT_MAPPED"
        else:
            api_operation = operation_entry.get("api_operation", "")
            same_service = [x for x in actions if x.get("action", "").startswith(service + ":")]
            exact = [
                x for x in same_service
                if x["action"].split(":", 1)[1] == api_operation
            ]
            if len(exact) == 1:
                candidate = exact[0]
                reason = "AWS_OPERATION_NAME_CORRESPONDENCE"
            elif api_operation.startswith("List"):
                listings = [
                    x for x in same_service
                    if x.get("properties", {}).get("IsList") is True
                ]
                if len(listings) == 1:
                    candidate = listings[0]
                    reason = "AWS_LIST_OPERATION_CLASSIFICATION"
            if candidate is not None:
                status = "CANDIDATE_REQUIRES_REVIEW"
            else:
                reason = "MULTIPLE_CONTEXT_DEPENDENT_ACTIONS"
                status = "ALTERNATIVES_REQUIRE_REVIEW"

        results.append({
            "tool": observation.get("tool"), "file": observation.get("file"),
            "line": observation.get("line"), "call_chain": observation.get("call_chain"),
            "branch": observation.get("branch"), "service": service, "operation": method,
            "destination": destination, "resource_parameters": observation.get("resource_parameters"),
            "status": status, "reason": reason,
            "suggested_action": candidate.get("action") if candidate else None,
            "suggested_resource_types": candidate.get("resource_types", []) if candidate else [],
            "other_possible_actions": [
                x.get("action") for x in actions
                if candidate is None or x.get("action") != candidate.get("action")
            ] if destination == "AWS_DEFAULT" else [],
            "context_dependent": bool(len(actions) > 1 and destination == "AWS_DEFAULT"),
            "catalog_url": service_entry.get("source_url"),
            "catalog_sha256": service_entry.get("source_sha256"),
            "catalog_version": service_entry.get("service_version"),
        })
    return {
        "version": "iam-candidate-preview-prototype-v1",
        "source_sha256": report.get("source_sha256"),
        "source_files": report.get("source_files", []),
        "mapping_approved": False,
        "audit_eligible": False,
        "operations": results,
        "gaps": list(report.get("gaps", [])),
        "note": "Candidates are context-dependent; not effective IAM grants or approved MCP needs.",
    }
