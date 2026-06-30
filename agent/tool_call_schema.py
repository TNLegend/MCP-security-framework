import json
from typing import Any


ALLOWED_PROPOSAL_KEYS = {
    "should_call_tool",
    "tool_name",
    "arguments",
    "user_message",
    "rationale",
}


class ToolProposalValidationError(Exception):
    pass


def normalize_tool_proposal(
    raw_proposal: dict[str, Any] | str,
    available_tools: list[dict[str, Any]],
) -> dict[str, Any]:
    proposal = parse_proposal(raw_proposal)
    known_values = {
        key: proposal.get(key)
        for key in ALLOWED_PROPOSAL_KEYS
    }

    raw_should_call_tool = known_values.get("should_call_tool", False)
    if not isinstance(raw_should_call_tool, bool):
        raise ToolProposalValidationError("should_call_tool must be a boolean.")

    should_call_tool = raw_should_call_tool
    tool_name = known_values.get("tool_name")
    arguments = known_values.get("arguments")
    user_message = known_values.get("user_message")
    rationale = known_values.get("rationale")

    if not isinstance(arguments, dict):
        arguments = {}

    normalized = {
        "should_call_tool": should_call_tool,
        "tool_name": tool_name if isinstance(tool_name, str) and tool_name else None,
        "arguments": arguments,
        "user_message": (
            user_message
            if isinstance(user_message, str) and user_message
            else "No tool call is required."
        ),
        "rationale": (
            rationale
            if isinstance(rationale, str) and rationale
            else "The provider did not include a rationale."
        ),
    }

    validate_tool_proposal(normalized, available_tools)
    return normalized


def validate_tool_proposal(
    proposal: dict[str, Any],
    available_tools: list[dict[str, Any]],
) -> None:
    if not isinstance(proposal.get("should_call_tool"), bool):
        raise ToolProposalValidationError("should_call_tool must be a boolean.")

    if proposal["should_call_tool"] is False:
        return

    tool_name = proposal.get("tool_name")
    if not isinstance(tool_name, str) or not tool_name:
        raise ToolProposalValidationError(
            "tool_name must be a non-empty string when should_call_tool is true."
        )

    if not isinstance(proposal.get("arguments"), dict):
        raise ToolProposalValidationError("arguments must be an object.")

    available_tool_names = {
        tool.get("name")
        for tool in available_tools
        if isinstance(tool.get("name"), str)
    }
    if tool_name not in available_tool_names:
        raise ToolProposalValidationError(
            f"Tool '{tool_name}' is not available in backend inventory."
        )


def safe_no_tool_response(
    user_message: str = "No tool call is required.",
    rationale: str = "No valid tool proposal was produced.",
) -> dict[str, Any]:
    return {
        "should_call_tool": False,
        "tool_name": None,
        "arguments": {},
        "user_message": user_message,
        "rationale": rationale,
    }


def parse_proposal(raw_proposal: dict[str, Any] | str) -> dict[str, Any]:
    if isinstance(raw_proposal, dict):
        return raw_proposal

    if not isinstance(raw_proposal, str):
        raise ToolProposalValidationError("Provider proposal must be a JSON object.")

    json_text = extract_json_object(raw_proposal)
    try:
        parsed = json.loads(json_text)
    except json.JSONDecodeError as exc:
        raise ToolProposalValidationError("Provider output is not valid JSON.") from exc

    if not isinstance(parsed, dict):
        raise ToolProposalValidationError("Provider JSON output must be an object.")

    return parsed


def extract_json_object(text: str) -> str:
    cleaned = text.strip()
    if cleaned.startswith("```"):
        lines = cleaned.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        cleaned = "\n".join(lines).strip()

    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise ToolProposalValidationError("Provider output does not contain a JSON object.")

    return cleaned[start : end + 1]
