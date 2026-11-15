"""Generic bounded projection of embedded MCP text resources.

No provider endpoint, tool name or remote URI is trusted. This converts
only inline, complete, text/plain resources for the selected Modern profile;
no resource links or external URLs are fetched.
"""
import re
from urllib.parse import urlsplit

MAX_INLINE_RESOURCE_TEXT_BYTES = 262_144
MAX_INLINE_RESOURCE_URI_LENGTH = 2048
NETWORK_OR_LOCAL_SCHEMES = {
    "http", "https", "ftp", "ftps", "file", "ws", "wss",
    "javascript", "data",
}


class InlineResourceProjectionError(ValueError):
    """An embedded MCP resource failed strict, provider-neutral validation."""


def project_inline_text_resources(result: dict) -> dict:
    if not isinstance(result, dict) or result.get("resultType") != "complete":
        return result
    original = result.get("content")
    if not isinstance(original, list) or not any(
        isinstance(part, dict) and part.get("type") == "resource" for part in original
    ):
        return result
    if not 1 <= len(original) <= 8:
        raise InlineResourceProjectionError("inline_resource_count_invalid")
    structured = result.get("structuredContent")
    if structured is not None and (
        not isinstance(structured, dict)
        or set(structured) != {"content"}
        or structured.get("content") != original
    ):
        raise InlineResourceProjectionError("inline_resource_structured_content_mismatch")
    projected = []
    for part in original:
        if not isinstance(part, dict):
            raise InlineResourceProjectionError("inline_resource_part_invalid")
        if part.get("type") != "resource":
            projected.append(part)
            continue
        if set(part) != {"type", "resource"}:
            raise InlineResourceProjectionError("inline_resource_wrapper_invalid")
        resource = part.get("resource")
        if not isinstance(resource, dict) or set(resource) != {"uri", "mimeType", "text"}:
            raise InlineResourceProjectionError("inline_resource_envelope_invalid")
        uri, mime, contents = (resource["uri"], resource["mimeType"], resource["text"])
        if (
            not isinstance(uri, str)
            or not uri.isascii()
            or len(uri) > MAX_INLINE_RESOURCE_URI_LENGTH
            or "%" in uri
        ):
            raise InlineResourceProjectionError("inline_resource_uri_invalid")
        try:
            parsed = urlsplit(uri)
        except ValueError as exc:
            raise InlineResourceProjectionError("inline_resource_uri_invalid") from exc
        if (
            not re.fullmatch(r"[a-z][a-z0-9+.-]{1,31}", parsed.scheme)
            or parsed.scheme in NETWORK_OR_LOCAL_SCHEMES
            or not parsed.netloc
            or parsed.username is not None
            or parsed.password is not None
            or not parsed.path.startswith("/")
            or parsed.query
            or parsed.fragment
            or any(part in {"", ".", ".."} for part in parsed.path[1:].split("/"))
        ):
            raise InlineResourceProjectionError("inline_resource_uri_invalid")
        if mime not in {"text/plain", "text/plain; charset=utf-8"}:
            raise InlineResourceProjectionError("inline_resource_mime_unsupported")
        if not isinstance(contents, str) or len(contents.encode("utf-8")) > MAX_INLINE_RESOURCE_TEXT_BYTES:
            raise InlineResourceProjectionError("inline_resource_text_invalid")
        projected.append({"type": "text", "text": contents})
    next_result = {key: value for key, value in result.items() if key != "structuredContent"}
    next_result["content"] = projected
    return next_result
