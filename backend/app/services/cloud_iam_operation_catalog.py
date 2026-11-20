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
        elif (not observation.get("request_parameters_complete", True)
              and len(actions) > 1):
            reason = "AWS_REQUEST_PARAMETERS_UNRESOLVED"
            status = "ALTERNATIVES_REQUIRE_REVIEW"
        elif (service == "s3" and method == "get_object"
              and str(observation.get("resource_parameters", {}).get("VersionId", "")).startswith(
                  ("UNKNOWN", "$"+"{", "<")
              )):
            reason = "AWS_S3_VERSION_ID_UNRESOLVED"
            status = "ALTERNATIVES_REQUIRE_REVIEW"
        else:
            api_operation = operation_entry.get("api_operation", "")
            same_service = [x for x in actions if x.get("action", "").startswith(service + ":")]
            exact = [
                x for x in same_service
                if x["action"].split(":", 1)[1] == api_operation
            ]
            if (service == "s3" and method == "get_object"
                    and observation.get("resource_parameters", {}).get("VersionId")
                    and not str(observation["resource_parameters"]["VersionId"]).startswith(
                        ("UNKNOWN", "$"+"{", "<")
                    )):
                versioned = [
                    x for x in actions if x.get("action") == "s3:GetObjectVersion"
                ]
                if len(versioned) == 1:
                    candidate = versioned[0]
                    reason = "AWS_S3_EXPLICIT_VERSION_ID"
            if candidate is None and len(exact) == 1:
                candidate = exact[0]
                reason = "AWS_OPERATION_NAME_CORRESPONDENCE"
            elif candidate is None and api_operation.startswith("List"):
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
            "request_parameters_complete": observation.get("request_parameters_complete", True),
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
        "tools": list(report.get("tools", [])),
        "tool_coverage": dict(report.get("tool_coverage", {})),
        "tool_registration_status": report.get("tool_registration_status", "UNKNOWN"),
        "assurance": report.get("assurance", "UNKNOWN"),
        "analysis_limits": report.get("analysis_limits", {}),
        "mapping_approved": False,
        "audit_eligible": False,
        "operations": results,
        "gaps": list(report.get("gaps", [])),
        "note": "Candidates are context-dependent; not effective IAM grants or approved MCP needs.",
    }


def dynamic_sdk_candidate_preview(report, catalog=None):
    """Map source-derived SDK candidate operations to possible IAM actions.

    Strictly read-only and non-authoritative: neither dynamic tools/list nor
    the deployed AWS SDK, resource/role binding, or signed contract is proven.
    """
    if catalog is None:
        catalog = load_prototype_catalog()
    if report.get("schema_version") != "dynamic-sdk-tools-preview-v1":
        raise CatalogError("DYNAMIC_REPORT_VERSION_UNSUPPORTED")

    def possibilities(service, method):
        service_item = catalog.get("services", {}).get(service, {})
        operation = service_item.get("operations", {}).get(method, {})
        return {
            "service": service,
            "sdk_method": method,
            "action_candidates": [
                x["action"] for x in operation.get("authorized_action_candidates", [])
                if isinstance(x, dict) and isinstance(x.get("action"), str)
            ],
            "catalog_sha256": service_item.get("source_sha256"),
            "catalog_url": service_item.get("source_url"),
        }

    tools = []
    for item in report.get("tools", []):
        service = item["service"]
        main = item.get("main_operation")
        calls = []
        if item.get("main_operation_proven") and main:
            calls.append({"role": "PRIMARY", **possibilities(service, main)})
        for aux in item.get("auxiliary_operations", []):
            calls.append({
                "role": "VALIDATOR_OR_AUXILIARY",
                "source_file": aux.get("file"),
                "source_line": aux.get("line"),
                "callback": aux.get("callback"),
                **possibilities(service, aux["operation"]),
            })
        item_out = dict(item)
        item_out["iam_calls"] = calls
        item_out["binding_status"] = "REQUIRES_VERIFIED_SDK_CONFIG_TOOLS_LIST_AND_SIGNED_CONTRACT"
        tools.append(item_out)

    return {
        "version": "dynamic-sdk-iam-candidate-preview-v1",
        "exposure_confirmed": False,
        "mapping_approved": False,
        "audit_eligible": False,
        "dynamic_tools": tools,
        "source_files": report.get("source_files", []),
        "gaps": report.get("gaps", []),
        "warning": "SDK-model and source-derived candidates, NOT deployed tool inventory or approved IAM permissions.",
    }
