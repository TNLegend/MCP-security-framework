from __future__ import annotations

import argparse
import http.client
import json
from pathlib import Path
import sys
import urllib.error
import urllib.parse
import urllib.request
from uuid import UUID

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
        generation = reserve_inventory(
            args.backend_url, args.mcp_endpoint,
            protocol_version=args.protocol_version,
            auth_mode=args.auth_mode,
            credential_ref=args.credential_ref,
            timeout_seconds=args.backend_timeout,
        )
        discovery = discover_http_mcp_server(
            mcp_endpoint=args.mcp_endpoint,
            protocol_version=args.protocol_version,
            auth_mode=args.auth_mode,
            credential_ref=args.credential_ref,
        )
        # Only this exact signed, pre-network reserved generation may
        # publish results. A later reservation supersedes this job.
        payload = {
            **discovery["payload"],
            "generation_id": generation["generation_id"],
            "reserved_protocol_version": args.protocol_version,
        }
        try:
            import_summary = import_inventory(
                args.backend_url,
                payload,
                timeout_seconds=args.backend_timeout,
            )
        except (OSError, TimeoutError, http.client.HTTPException) as exc:
            # A lost HTTP response says NOTHING about whether the backend
            # transaction committed. Query the already reserved generation
            # using a separate signed GET. Never replay the import request.
            print("Import response uncertain; checking committed generation status.",
                  file=sys.stderr)
            try:
                durable = read_discovery_generation_status(
                    args.backend_url, generation["generation_id"],
                    timeout_seconds=args.backend_timeout,
                )
            except Exception as status_exc:
                raise RuntimeError(
                    "discovery_import_outcome_unknown_no_retry"
                ) from status_exc
            if durable["status"] != "PUBLISHED":
                raise RuntimeError(
                    "discovery_import_not_confirmed_no_retry:"
                    + durable["status"]
                ) from exc
            import_summary = {
                "generation_id": generation["generation_id"],
                "status": "PUBLISHED",
                "note": "Commit confirmed by signed status after response loss; "
                        "tool count not available from lost response.",
            }
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


def reserve_inventory(
    backend_import_url: str,
    endpoint: str,
    *,
    protocol_version: str | None = None,
    auth_mode: str = "NONE",
    credential_ref: str | None = None,
    timeout_seconds: float = 120.0,
) -> dict:
    parsed = urllib.parse.urlsplit(backend_import_url)
    if not parsed.path.endswith("/import-discovery"):
        raise ValueError("discovery_backend_import_endpoint_invalid")
    reserve_path = parsed.path.removesuffix("import-discovery") + "reserve-discovery"
    reserve_url = urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, reserve_path, parsed.query, parsed.fragment)
    )
    result = _signed_discovery_request(
        reserve_url,
        {
            "endpoint": endpoint, "transport": "streamable_http",
            "protocol_version": protocol_version,
            "auth_mode": auth_mode, "credential_ref": credential_ref,
        },
        timeout_seconds=timeout_seconds,
    )
    if not isinstance(result, dict) or not isinstance(result.get("generation_id"), str):
        raise ValueError("discovery_reservation_invalid")
    return result


def read_discovery_generation_status(
    backend_import_url: str,
    generation_id: str,
    *,
    timeout_seconds: float = 120.0,
) -> dict:
    """Signed read-only reconciliation; never authorizes another import."""
    try:
        normalized = str(UUID(generation_id))
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValueError("discovery_generation_id_invalid") from exc
    parsed = urllib.parse.urlsplit(backend_import_url)
    if not parsed.path.endswith("/import-discovery"):
        raise ValueError("discovery_backend_import_endpoint_invalid")
    new_path = (
        parsed.path.removesuffix("import-discovery")
        + "discovery-generations/" + normalized
    )
    target = urllib.parse.urlunsplit((
        parsed.scheme, parsed.netloc, new_path, parsed.query, "",
    ))
    request_path = new_path + ("?" + parsed.query if parsed.query else "")
    signed = SignedServiceRequestSigner.for_discovery().signed_headers(
        method="GET", path=request_path, body=b"",
    )
    request = urllib.request.Request(
        target, headers={"Accept":"application/json",**signed}, method="GET",
    )
    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
        raw = response.read()
    try:
        state = json.loads(raw.decode("utf-8"))
    except (ValueError, AttributeError, TypeError, UnicodeError) as exc:
        raise ValueError("discovery_status_invalid") from exc
    if (
        not isinstance(state, dict)
        or state.get("generation_id") != normalized
        or state.get("status") not in (
            "RUNNING", "FAILED", "SUPERSEDED", "PUBLISHED",
        )
        or state.get("may_retry_import") is not False
    ):
        raise ValueError("discovery_status_invalid")
    return state


def import_inventory(
    backend_url: str,
    payload: dict,
    *,
    timeout_seconds: float = 120.0,
) -> dict:
    if not isinstance(payload.get("generation_id"), str):
        raise ValueError("discovery_generation_required")
    return _signed_discovery_request(
        backend_url, payload, timeout_seconds=timeout_seconds,
    )


def _signed_discovery_request(
    backend_url: str,
    payload: dict,
    *,
    timeout_seconds: float,
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
