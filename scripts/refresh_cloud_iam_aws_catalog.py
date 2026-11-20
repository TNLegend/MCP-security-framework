"""Generate a bounded offline AWS IAM action candidate snapshot from AWS public JSON.

Only calls the public AWS Service Authorization Reference HTTPS endpoint, never
AWS account APIs. Intended for explicitly reviewed catalogue refreshes, not
runtime fetching or IAM policy modification.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import urlopen

BASE = "https://servicereference.us-east-1.amazonaws.com/v1/"
MAX_DOWNLOAD = 8_000_000


def load_public_json(url):
    parsed = urlparse(url)
    if (parsed.scheme != "https" or
        parsed.hostname != "servicereference.us-east-1.amazonaws.com" or
        not parsed.path.startswith("/v1/") or not parsed.path.endswith(".json")):
        raise ValueError("AWS_CATALOG_SOURCE_URL_NOT_ALLOWED")
    with urlopen(url, timeout=20) as response:
        payload = response.read(MAX_DOWNLOAD + 1)
    if len(payload) > MAX_DOWNLOAD:
        raise ValueError("AWS_CATALOG_SOURCE_TOO_LARGE")
    return json.loads(payload), hashlib.sha256(payload).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--method", action="append", required=True,
                        help="Boto3 service:method, e.g. s3:get_object")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    requested = {}
    for value in args.method:
        service, sep, method = value.partition(":")
        if not sep or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", service) or not method.isidentifier():
            parser.error("Invalid service:method")
        requested.setdefault(service, set()).add(method)
    mapping, mapping_digest = load_public_json(BASE + "mapping.json")
    directory = mapping["SDK"]["Python"]["Boto3"]
    snapshot = {
        "schema_version": "aws-sdk-action-candidates-prototype-v1",
        "sdk": "Boto3",
        "disclaimer": "AuthorizedActions are possible IAM actions, not an unconditional list of required grants.",
        "mapping_url": BASE + "mapping.json",
        "mapping_sha256": mapping_digest,
        "services": {},
    }
    for service in sorted(requested):
        item = directory.get(service)
        if not isinstance(item, dict) or not isinstance(item.get("url"), str):
            raise ValueError("AWS_CATALOG_SERVICE_NOT_FOUND:" + service)
        catalog, digest = load_public_json(item["url"])
        details = {
            x["Name"]: x for x in catalog.get("Actions", [])
            if isinstance(x, dict) and isinstance(x.get("Name"), str)
        }
        operations = {}
        for operation in catalog.get("Operations", []):
            if not isinstance(operation, dict):
                continue
            matches = [
                x["Method"] for x in operation.get("SDK", [])
                if isinstance(x, dict) and x.get("Package") == "Boto3" and
                   x.get("Name") == service and x.get("Method") in requested[service]
            ]
            if not matches:
                continue
            options = []
            for action in operation.get("AuthorizedActions") or []:
                if not isinstance(action, dict):
                    continue
                name, prefix = action.get("Name"), action.get("Service")
                if not isinstance(name, str) or not isinstance(prefix, str):
                    continue
                action_meta = details.get(name, {}) if prefix == catalog.get("Name") else {}
                options.append({
                    "action": prefix + ":" + name,
                    "resource_types": [
                        ref["Name"] for ref in action_meta.get("Resources", [])
                        if isinstance(ref, dict) and isinstance(ref.get("Name"), str)
                    ],
                    "properties": action_meta.get("Annotations", {}).get("Properties", {}),
                })
            for method in matches:
                if method in operations:
                    raise ValueError("DUPLICATE_SDK_METHOD:" + service + ":" + method)
                operations[method] = {
                    "api_operation": operation.get("Name"),
                    "authorized_action_candidates": sorted(options, key=lambda x: x["action"]),
                }
        snapshot["services"][service] = {
            "source_url": item["url"],
            "source_sha256": digest,
            "service_version": catalog.get("Version"),
            "operations": operations,
            "unmapped_requested_methods": sorted(requested[service] - set(operations)),
        }
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(snapshot, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
                      encoding="utf-8")
    print("snapshot=" + str(output))
    for service, data in snapshot["services"].items():
        print(service, "methods=" + str(len(data["operations"])),
              "missing=" + str(data["unmapped_requested_methods"]))


if __name__ == "__main__":
    main()
