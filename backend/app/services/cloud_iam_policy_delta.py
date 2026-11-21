"""Conservative reverse review of role identity policy grants vs approved MCP needs.

Only identity-policy Allow statements are inspected. This never establishes
effective IAM permissions or whether a shared role's grant is excessive for
other consumers. For conditioned/negated/broad and incomplete inputs we
return bounded uncertainty, not a fabricated excess finding.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any

_ACTION = re.compile(r"^[a-zA-Z0-9-]{1,63}:[A-Za-z0-9*?]{1,120}$")
_MAX_ITEMS = 200
_MAX_RESULTS = 120


@dataclass(frozen=True)
class Delta:
    status: str
    reason: str
    action: str | None
    resource: str | None
    statement_index: int
    evidence: str


def _items(value: Any) -> list[str] | None:
    if isinstance(value, str):
        return [value]
    if (isinstance(value, list) and len(value) <= _MAX_ITEMS and
            all(isinstance(x, str) for x in value)):
        return value
    return None


def reverse_identity_policy(statements: list[dict], expected: list[dict]) -> list[Delta]:
    """Bounded observations for role identity policy -> signed mapping.

    A known exact Allow action/resource outside ALL mapped tuples is reported
    as OUTSIDE_MCP_MAPPING, never as effective AWS permission or automatically
    removable role privilege. Unknown shapes and policy conditions abstain.
    """
    approved = {
        (x["action"].lower(), x["resource"])
        for x in expected
        if x.get("status") == "READY" and x.get("action") and x.get("resource")
    }
    result: list[Delta] = []
    seen: set[tuple[str, str | None, str | None]] = set()

    def add(status, reason, action, resource, index, evidence):
        key = (status, action.lower() if action else None, resource)
        if key in seen:
            return
        seen.add(key)
        # Examine one extra distinct result before claiming that a bounded
        # response is complete. Reserve a slot for the truncation marker.
        if len(result) <= _MAX_RESULTS:
            result.append(Delta(status, reason, action, resource, index, evidence))

    if len(statements) > 300:
        return [Delta("UNKNOWN", "IAM_REVERSE_STATEMENT_LIMIT", None, None, -1, "STATEMENT_LIMIT")]

    # Imported here to avoid a module-level circular dependency with worker.
    from app.services.cloud_iam_mcp_security import _matches
    for idx, statement in enumerate(statements):
        if len(result) > _MAX_RESULTS:
            break
        if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
            continue
        if ("Condition" in statement or "NotAction" in statement or "NotResource" in statement):
            add("UNKNOWN", "IAM_REVERSE_COMPLEX_ALLOW", None, None, idx, "CONDITIONAL_OR_NEGATED")
            continue
        actions = _items(statement.get("Action"))
        resources = _items(statement.get("Resource"))
        if actions is None or resources is None:
            add("UNKNOWN", "IAM_REVERSE_POLICY_SHAPE_UNKNOWN", None, None, idx, "INVALID_POLICY_SHAPE")
            continue
        for action in actions:
            if len(result) > _MAX_RESULTS:
                break
            if not _ACTION.fullmatch(action):
                add("UNKNOWN", "IAM_REVERSE_ACTION_UNSUPPORTED", None, None, idx, "ACTION_INVALID")
                continue
            action_matches = {approved_resource for expected_action, approved_resource in approved
                              if _matches(expected_action, action, action=True)}
            if "*" in action or "?" in action:
                # Wildcards can cover unseen actions, even if one signed need
                # happens to match. Forward comparison already marks broad
                # matches. Never call a wildcard an exact excess permission.
                add("UNKNOWN", "IAM_REVERSE_WILDCARD_ACTION_SCOPE", action,
                    None, idx, "WILDCARD_ACTION")
                continue
            for resource in resources:
                if len(result) > _MAX_RESULTS:
                    break
                if len(resource) > 512:
                    add("UNKNOWN", "IAM_REVERSE_RESOURCE_UNSUPPORTED", action,
                        None, idx, "RESOURCE_TOO_LARGE")
                    continue
                if "*" in resource or "?" in resource:
                    if resource in action_matches or "*" in action_matches:
                        # Identical approved glob, or unrestricted approved
                        # resource scope: no unsupported extra access inferred.
                        continue
                    if not action_matches:
                        # Action not used anywhere in the approved mapping,
                        # irrespective of the grant's resource breadth.
                        add("OUTSIDE_MCP_MAPPING", "IAM_ACTION_NOT_IN_APPROVED_MCP_MAPPING",
                            action, resource, idx, "IDENTITY_POLICY_ALLOW_ONLY")
                    else:
                        add("UNKNOWN", "IAM_REVERSE_WILDCARD_RESOURCE_SCOPE",
                            action, resource, idx, "RESOURCE_GLOB_NOT_SUBSET_PROVEN")
                    continue
                if not any(_matches(approved_resource, resource)
                           for approved_resource in action_matches):
                    reason = ("IAM_ACTION_NOT_IN_APPROVED_MCP_MAPPING" if not action_matches
                              else "IAM_RESOURCE_NOT_IN_APPROVED_MCP_MAPPING")
                    add("OUTSIDE_MCP_MAPPING", reason, action, resource,
                        idx, "IDENTITY_POLICY_ALLOW_ONLY")
        if len(result) > _MAX_RESULTS:
            break
    if len(result) > _MAX_RESULTS:
        # An extra distinct observation was really found. Do not suppress the
        # evidence that the return value is intentionally incomplete.
        result = result[:_MAX_RESULTS - 1] + [
            Delta("UNKNOWN", "IAM_REVERSE_RESULT_LIMIT", None, None, -1, "TRUNCATED")
        ]
    return result
