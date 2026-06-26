from json import JSONDecodeError
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse

MCP_PROTOCOL_VERSION = "2025-11-25"
ALLOWED_ORIGINS = {
    "http://127.0.0.1:5173",
    "http://localhost:5173",
    "http://127.0.0.1:8000",
}
TEST_DATA_DIR = (Path(__file__).resolve().parent / "test_data").resolve()

app = FastAPI(title="MCP HTTP Lab Server", version="0.1.0")


READ_FILE_TOOL = {
    "name": "read_file",
    "title": "Read File",
    "description": "Read a file from the local MCP lab test data directory.",
    "inputSchema": {
        "type": "object",
        "properties": {
            "path": {
                "type": "string",
                "description": "Relative path under the lab test data directory.",
            },
        },
        "required": ["path"],
        "additionalProperties": False,
    },
    "outputSchema": {
        "type": "object",
        "properties": {
            "path": {"type": "string"},
            "content": {"type": "string"},
        },
        "required": ["path", "content"],
    },
    "annotations": {
        "readOnlyHint": True,
    },
}

LIST_FILES_TOOL = {
    "name": "list_files",
    "title": "List Files",
    "description": "List files available in the local MCP lab test data directory.",
    "inputSchema": {
        "type": "object",
        "properties": {},
        "additionalProperties": False,
    },
    "outputSchema": {
        "type": "object",
        "properties": {
            "files": {
                "type": "array",
                "items": {"type": "string"},
            },
        },
        "required": ["files"],
    },
    "annotations": {
        "readOnlyHint": True,
    },
}

TOOLS = {
    READ_FILE_TOOL["name"]: READ_FILE_TOOL,
    LIST_FILES_TOOL["name"]: LIST_FILES_TOOL,
}


class ToolArgumentError(Exception):
    pass


class ToolExecutionError(Exception):
    pass


@app.get("/mcp")
def mcp_get() -> Response:
    return Response(status_code=status.HTTP_405_METHOD_NOT_ALLOWED)


@app.post("/mcp")
async def mcp_post(
    request: Request,
    origin: str | None = Header(default=None),
    accept: str | None = Header(default=None),
    content_type: str | None = Header(default=None),
    mcp_protocol_version: str | None = Header(default=None, alias="MCP-Protocol-Version"),
) -> Response:
    validate_origin(origin)
    validate_headers(accept=accept, content_type=content_type)

    try:
        message = await request.json()
    except JSONDecodeError:
        return JSONResponse(
            {
                "jsonrpc": "2.0",
                "id": None,
                "error": {
                    "code": -32700,
                    "message": "Parse error.",
                },
            },
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    if not isinstance(message, dict):
        return json_rpc_error(None, -32600, "Invalid JSON-RPC request.")

    method = message.get("method")
    request_id = message.get("id")

    if method != "initialize":
        validate_protocol_version(mcp_protocol_version)

    if method == "notifications/initialized":
        return Response(status_code=status.HTTP_202_ACCEPTED)

    if method == "initialize":
        return json_rpc_result(request_id, initialize_result())

    if method == "tools/list":
        return json_rpc_result(request_id, {"tools": list(TOOLS.values())})

    if method == "tools/call":
        return handle_tools_call(request_id, message.get("params"))

    return json_rpc_error(request_id, -32601, f"Unsupported method: {method}")


def validate_origin(origin: str | None) -> None:
    if origin is not None and origin not in ALLOWED_ORIGINS:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Unexpected Origin header.",
        )


def validate_headers(accept: str | None, content_type: str | None) -> None:
    media_type = (content_type or "").split(";", maxsplit=1)[0].strip().lower()
    if media_type != "application/json":
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="Content-Type must be application/json.",
        )

    accept_value = (accept or "").lower()
    if "application/json" not in accept_value or "text/event-stream" not in accept_value:
        raise HTTPException(
            status_code=status.HTTP_406_NOT_ACCEPTABLE,
            detail="Accept must include application/json and text/event-stream.",
        )


def validate_protocol_version(mcp_protocol_version: str | None) -> None:
    if mcp_protocol_version != MCP_PROTOCOL_VERSION:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"MCP-Protocol-Version must be {MCP_PROTOCOL_VERSION}.",
        )


def initialize_result() -> dict[str, Any]:
    return {
        "protocolVersion": MCP_PROTOCOL_VERSION,
        "capabilities": {
            "tools": {},
        },
        "serverInfo": {
            "name": "mcp-security-http-lab",
            "title": "MCP Security HTTP Lab",
            "version": "0.1.0",
            "description": "Local Streamable HTTP lab server for MCP security tests.",
        },
        "instructions": "Use this local server only for MCP Streamable HTTP lab tests.",
    }


def handle_tools_call(request_id: Any, params: Any) -> JSONResponse:
    if not isinstance(params, dict):
        return json_rpc_error(request_id, -32602, "tools/call params must be an object.")

    tool_name = params.get("name")
    if not isinstance(tool_name, str):
        return json_rpc_error(request_id, -32602, "tools/call requires a string tool name.")

    arguments = params.get("arguments") or {}
    if not isinstance(arguments, dict):
        return json_rpc_error(request_id, -32602, "tools/call arguments must be an object.")

    if tool_name == "read_file":
        try:
            return json_rpc_result(request_id, read_file(arguments))
        except ToolArgumentError as exc:
            return json_rpc_error(request_id, -32602, str(exc))
        except ToolExecutionError as exc:
            return json_rpc_result(request_id, tool_error_result(str(exc)))

    if tool_name == "list_files":
        return json_rpc_result(request_id, list_files())

    return json_rpc_error(request_id, -32602, f"Unknown tool: {tool_name}")


def read_file(arguments: dict[str, Any]) -> dict[str, Any]:
    raw_path = arguments.get("path")
    if not isinstance(raw_path, str) or not raw_path:
        raise ToolArgumentError("read_file requires a non-empty string path.")

    file_path = resolve_lab_path(raw_path)
    content = file_path.read_text(encoding="utf-8")
    relative_path = file_path.relative_to(TEST_DATA_DIR).as_posix()
    structured_content = {
        "path": relative_path,
        "content": content,
    }

    return {
        "content": [
            {
                "type": "text",
                "text": content,
            },
        ],
        "structuredContent": structured_content,
        "isError": False,
    }


def list_files() -> dict[str, Any]:
    files = [
        path.relative_to(TEST_DATA_DIR).as_posix()
        for path in sorted(TEST_DATA_DIR.rglob("*"))
        if path.is_file() and ".env" not in path.relative_to(TEST_DATA_DIR).parts
    ]
    structured_content = {"files": files}

    return {
        "content": [
            {
                "type": "text",
                "text": "\n".join(files),
            },
        ],
        "structuredContent": structured_content,
        "isError": False,
    }


def resolve_lab_path(raw_path: str) -> Path:
    candidate = Path(raw_path)
    if candidate.is_absolute():
        raise ToolExecutionError("Absolute paths are not allowed.")

    normalized_parts = candidate.parts
    if ".." in normalized_parts:
        raise ToolExecutionError("Path traversal is not allowed.")

    if ".env" in normalized_parts:
        raise ToolExecutionError("Reading .env files is not allowed.")

    resolved_path = (TEST_DATA_DIR / candidate).resolve()
    try:
        resolved_path.relative_to(TEST_DATA_DIR)
    except ValueError:
        raise ToolExecutionError("Path traversal outside lab test data is not allowed.")

    if not resolved_path.is_file():
        raise ToolExecutionError("Requested file does not exist.")

    return resolved_path


def tool_error_result(message: str) -> dict[str, Any]:
    return {
        "content": [
            {
                "type": "text",
                "text": message,
            },
        ],
        "isError": True,
    }


def json_rpc_result(request_id: Any, result: dict[str, Any]) -> JSONResponse:
    return JSONResponse(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": result,
        }
    )


def json_rpc_error(request_id: Any, code: int, message: str) -> JSONResponse:
    return JSONResponse(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {
                "code": code,
                "message": message,
            },
        }
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("server:app", host="127.0.0.1", port=9000)
