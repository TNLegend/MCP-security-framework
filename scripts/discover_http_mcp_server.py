from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import urllib.parse
import urllib.request

REPO_ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = REPO_ROOT / "backend"
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(BACKEND_DIR))

from app.services.mcp_discovery import (  # noqa: E402
    DEFAULT_PROTOCOL_VERSION,
    discover_http_mcp_server,
)
from app.services.signed_service_request import (  # noqa: E402
    SignedServiceRequestSigner,
    canonical_json_body,
)


DEFAULT_MCP_ENDPOINT = "http://127.0.0.1:9000/mcp"
DEFAULT_BACKEND_URL = "http://127.0.0.1:8000/api/v1/inventory/import-discovery"


def main() -> int:
    args = parse_args()
    try:
        discovery = discover_http_mcp_server(
            mcp_endpoint=args.mcp_endpoint,
            protocol_version=args.protocol_version,
            auth_mode=args.auth_mode,
            credential_ref=args.credential_ref,
        )
        import_summary = import_inventory(
            args.backend_url,
            discovery["payload"],
            timeout_seconds=args.backend_timeout,
        )
    except Exception as exc:
        print(f"Discovery failed: {exc}", file=sys.stderr)
        return 1

    print("protocol discovery OK")
    print("tools/list OK for approved protocol probes")
    print("discovered tools:")
    for tool_name in discovery["tool_names"]:
        print(f"- {tool_name}")
    print("backend import OK")
    print(json.dumps(import_summary, indent=2))
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Discover an MCP Streamable HTTP server.")
    parser.add_argument("--mcp-endpoint", default=DEFAULT_MCP_ENDPOINT)
    parser.add_argument("--backend-url", default=DEFAULT_BACKEND_URL)
    parser.add_argument("--protocol-version", default=DEFAULT_PROTOCOL_VERSION)
    parser.add_argument("--auth-mode", choices=("NONE", "BEARER"), default="NONE")
    parser.add_argument("--credential-ref")
    parser.add_argument("--backend-timeout", type=float, default=120.0)
    return parser.parse_args()


def discover_server(
    mcp_endpoint: str,
    protocol_version: str = DEFAULT_PROTOCOL_VERSION,
    *,
    auth_mode: str = "NONE",
    credential_ref: str | None = None,
) -> dict:
    return discover_http_mcp_server(
        mcp_endpoint=mcp_endpoint,
        protocol_version=protocol_version,
        auth_mode=auth_mode,
        credential_ref=credential_ref,
    )


def import_inventory(
    backend_url: str,
    payload: dict,
    *,
    timeout_seconds: float = 120.0,
) -> dict:
    body = canonical_json_body(payload)
    parsed_path = urllib.parse.urlsplit(backend_url)
    request_path = parsed_path.path
    if parsed_path.query:
        request_path = f"{request_path}?{parsed_path.query}"
    signer = SignedServiceRequestSigner.for_discovery()
    request = urllib.request.Request(
        backend_url,
        data=body,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            **signer.signed_headers(
                method="POST",
                path=request_path,
                body=body,
            ),
        },
        method="POST",
    )

    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
        return json.loads(response.read().decode("utf-8"))


if __name__ == "__main__":
    raise SystemExit(main())
