from typing import Any

from pydantic import BaseModel


class DiscoveredMCPServer(BaseModel):
    endpoint: str
    transport: str = "streamable_http"
    protocol_version: str | None = None
    server_info_name: str | None = None
    server_info_title: str | None = None
    server_info_version: str | None = None
    server_info_description: str | None = None
    server_info_icons: list[dict[str, Any]] | None = None
    server_info_website_url: str | None = None
    capabilities: dict[str, Any] | None = None
    instructions: str | None = None
    raw_initialize_result: dict[str, Any] | None = None


class DiscoveredMCPTool(BaseModel):
    name: str
    title: str | None = None
    description: str | None = None
    icons: list[dict[str, Any]] | None = None
    input_schema: dict[str, Any] | None = None
    output_schema: dict[str, Any] | None = None
    annotations: dict[str, Any] | None = None
    execution: dict[str, Any] | None = None
    raw_tool_definition: dict[str, Any] | None = None


class DiscoveryImportPayload(BaseModel):
    server: DiscoveredMCPServer
    tools: list[DiscoveredMCPTool] = []
