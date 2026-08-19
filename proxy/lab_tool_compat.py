from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class LabToolDescriptor:
    name: str
    operation: str
    required_capability: str
    resource_type: str
    resource_adapter: str = "filesystem"


LAB_READ_TOOL = "read_file"
LAB_LIST_TOOL = "list_files"

_LAB_TOOL_DESCRIPTORS = {
    LAB_READ_TOOL: LabToolDescriptor(
        name=LAB_READ_TOOL,
        operation="read",
        required_capability="filesystem.read",
        resource_type="file",
    ),
    LAB_LIST_TOOL: LabToolDescriptor(
        name=LAB_LIST_TOOL,
        operation="list",
        required_capability="filesystem.list",
        resource_type="directory",
    ),
}


def lab_tool_descriptor(tool_name: str) -> LabToolDescriptor | None:
    return _LAB_TOOL_DESCRIPTORS.get(tool_name)


def is_lab_directory_listing_tool(tool_name: str) -> bool:
    return tool_name == LAB_LIST_TOOL


def is_lab_file_read_tool(tool_name: str) -> bool:
    return tool_name == LAB_READ_TOOL
