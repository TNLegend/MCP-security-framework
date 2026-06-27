import argparse
import json
import sys
import urllib.error
import urllib.request
import uuid

DEFAULT_MCP_ENDPOINT = "http://127.0.0.1:9000/mcp"
DEFAULT_BACKEND_URL = "http://127.0.0.1:8000/api/v1/inventory/import-discovery"
DEFAULT_PROTOCOL_VERSION = "2025-11-25"
DISCOVERY_CLIENT_NAME = "mcp-security-framework-discovery"
DISCOVERY_CLIENT_VERSION = "0.1.0"
MCP_ACCEPT_HEADER = "application/json, text/event-stream"


def main() -> int:
    args = parse_args()

    try:
        discovery = discover_server(
            mcp_endpoint=args.mcp_endpoint,
            protocol_version=args.protocol_version,
        )
        import_summary = import_inventory(args.backend_url, discovery["payload"])
    except Exception as exc:
        print(f"Discovery failed: {exc}", file=sys.stderr)
        return 1

    print("initialize OK")
    print("initialized notification OK")
    print("tools/list OK")
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
    return parser.parse_args()


def discover_server(mcp_endpoint: str, protocol_version: str) -> dict:
    initialize_response = send_json_rpc(
        url=mcp_endpoint,
        payload={
            "jsonrpc": "2.0",
            "id": new_request_id(),
            "method": "initialize",
            "params": {
                "protocolVersion": protocol_version,
                "capabilities": {},
                "clientInfo": {
                    "name": DISCOVERY_CLIENT_NAME,
                    "version": DISCOVERY_CLIENT_VERSION,
                },
            },
        },
    )
    initialize_result = parse_json_rpc_result(initialize_response["body"])
    negotiated_protocol_version = initialize_result.get(
        "protocolVersion",
        protocol_version,
    )
    session_id = initialize_response["headers"].get("MCP-Session-Id")

    send_initialized_notification(
        mcp_endpoint=mcp_endpoint,
        protocol_version=negotiated_protocol_version,
        session_id=session_id,
    )

    tools = list_tools(
        mcp_endpoint=mcp_endpoint,
        protocol_version=negotiated_protocol_version,
        session_id=session_id,
    )

    return {
        "tool_names": [tool.get("name", "unknown") for tool in tools],
        "payload": build_import_payload(
            mcp_endpoint=mcp_endpoint,
            initialize_result=initialize_result,
            tools=tools,
        ),
    }


def send_initialized_notification(
    mcp_endpoint: str,
    protocol_version: str,
    session_id: str | None,
) -> None:
    response = send_json_rpc(
        url=mcp_endpoint,
        payload={
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
        },
        protocol_version=protocol_version,
        session_id=session_id,
        expected_statuses={202},
    )
    if response["status"] != 202:
        raise RuntimeError("notifications/initialized was not accepted")


def list_tools(
    mcp_endpoint: str,
    protocol_version: str,
    session_id: str | None,
) -> list[dict]:
    tools = []
    cursor = None

    while True:
        params = {}
        if cursor:
            params["cursor"] = cursor

        response = send_json_rpc(
            url=mcp_endpoint,
            payload={
                "jsonrpc": "2.0",
                "id": new_request_id(),
                "method": "tools/list",
                "params": params,
            },
            protocol_version=protocol_version,
            session_id=session_id,
        )
        result = parse_json_rpc_result(response["body"])
        tools.extend(result.get("tools", []))
        cursor = result.get("nextCursor")
        if not cursor:
            return tools


def build_import_payload(
    mcp_endpoint: str,
    initialize_result: dict,
    tools: list[dict],
) -> dict:
    server_info = initialize_result.get("serverInfo") or {}

    return {
        "server": {
            "endpoint": mcp_endpoint,
            "transport": "streamable_http",
            "protocol_version": initialize_result.get("protocolVersion"),
            "server_info_name": server_info.get("name"),
            "server_info_title": server_info.get("title"),
            "server_info_version": server_info.get("version"),
            "server_info_description": server_info.get("description"),
            "server_info_icons": server_info.get("icons"),
            "server_info_website_url": server_info.get("websiteUrl"),
            "capabilities": initialize_result.get("capabilities"),
            "instructions": initialize_result.get("instructions"),
            "raw_initialize_result": initialize_result,
        },
        "tools": [map_tool(tool) for tool in tools],
    }


def map_tool(tool: dict) -> dict:
    return {
        "name": tool.get("name"),
        "title": tool.get("title"),
        "description": tool.get("description"),
        "icons": tool.get("icons"),
        "input_schema": tool.get("inputSchema"),
        "output_schema": tool.get("outputSchema"),
        "annotations": tool.get("annotations"),
        "execution": tool.get("execution"),
        "raw_tool_definition": tool,
    }


def import_inventory(backend_url: str, payload: dict) -> dict:
    request = urllib.request.Request(
        backend_url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


def send_json_rpc(
    url: str,
    payload: dict,
    protocol_version: str | None = None,
    session_id: str | None = None,
    expected_statuses: set[int] | None = None,
) -> dict:
    expected_statuses = expected_statuses or {200}
    headers = {
        "Accept": MCP_ACCEPT_HEADER,
        "Content-Type": "application/json",
    }
    if protocol_version:
        headers["MCP-Protocol-Version"] = protocol_version
    if session_id:
        headers["MCP-Session-Id"] = session_id

    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            body = response.read().decode("utf-8")
            if response.status not in expected_statuses:
                raise RuntimeError(f"Unexpected HTTP status {response.status}: {body}")
            return {
                "status": response.status,
                "headers": response.headers,
                "body": json.loads(body) if body else None,
            }
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8")
        raise RuntimeError(f"HTTP {exc.code}: {body}") from exc


def parse_json_rpc_result(message: dict | None) -> dict:
    if not isinstance(message, dict):
        raise RuntimeError("Expected a JSON-RPC response body")

    if message.get("jsonrpc") != "2.0":
        raise RuntimeError("Invalid JSON-RPC version")

    if "error" in message:
        raise RuntimeError(f"JSON-RPC error: {message['error']}")

    result = message.get("result")
    if not isinstance(result, dict):
        raise RuntimeError("JSON-RPC response does not contain an object result")

    return result


def new_request_id() -> str:
    return str(uuid.uuid4())


if __name__ == "__main__":
    raise SystemExit(main())
