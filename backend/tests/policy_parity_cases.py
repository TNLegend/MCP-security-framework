from dataclasses import dataclass
from typing import Any

from app.schemas.policy_context import RuntimePolicyInput


@dataclass(frozen=True)
class PolicyParityCase:
    case_id: str
    context: dict[str, Any]
    expected_rule_id: str


def build_runtime_context(
    *,
    agent_id: str = "agent-parity",
    role: str = "legal_agent",
    authorization_status: str = "resolved",
    authorization_revision: str = "test-authorization-v1",
    grants: list[dict[str, Any]] | None = None,
    trust_status: str = "lab_trusted",
    tool_name: str = "list_files",
    risk_score: float = 0.0,
    sensitivity: str = "medium",
    path: str = "documents/file.txt",
    canonical_resource: str | None = None,
    arguments_valid: bool = True,
    validation_error_codes: list[str] | None = None,
    estimated_output_size_mb: float = 0.001,
) -> dict[str, Any]:
    if validation_error_codes is None:
        validation_error_codes = [] if arguments_valid else ["test_invalid_arguments"]
    if canonical_resource is None and arguments_valid:
        canonical_resource = path
    required_capability = _required_capability_for_tool(tool_name)
    resource_scope = _resource_scope_for_path(canonical_resource, arguments_valid)
    if grants is None:
        grants = [
            {"capability": "filesystem.read", "scopes": ["contracts"]},
            {"capability": "filesystem.list", "scopes": ["lab_root", "contracts"]},
        ]
    allowed_capabilities = [grant["capability"] for grant in grants]
    allowed_scopes = list(
        dict.fromkeys(scope for grant in grants for scope in grant["scopes"])
    )

    context = {
        "subject": {
            "agent_id": agent_id,
            "role": role,
            "authorization_status": authorization_status,
            "authorization_revision": authorization_revision,
            "grants": grants,
            "allowed_capabilities": allowed_capabilities,
            "allowed_scopes": allowed_scopes,
        },
        "server": {
            "id": 1,
            "endpoint": "http://127.0.0.1:9000/mcp",
            "trust_status": trust_status,
            "security_status": "pending_analysis",
        },
        "tool": {
            "id": 1,
            "name": tool_name,
            "risk_score": risk_score,
            "sensitivity": sensitivity,
            "capabilities": [],
            "admission_status": "unknown",
            "description_risk_score": 0.0,
            "capability_mismatch": False,
            "drift_status": "unknown",
        },
        "request": {
            "operation": "unknown",
            "resource_type": "unknown",
            "resource_scope": resource_scope,
            "required_capability": required_capability,
            "canonical_resource": canonical_resource,
            "arguments": {"path": path},
            "arguments_valid": arguments_valid,
            "validation_error_codes": validation_error_codes,
            "estimated_output_size_mb": estimated_output_size_mb,
        },
        "runtime": {
            "environment": "local",
            "session_id": "session-parity",
        },
    }
    RuntimePolicyInput.model_validate(context)
    return context


def _required_capability_for_tool(tool_name: str) -> str:
    if tool_name == "read_file":
        return "filesystem.read"
    if tool_name == "list_files":
        return "filesystem.list"
    return "unclassified"


def _resource_scope_for_path(path: str | None, arguments_valid: bool) -> str:
    if not arguments_valid:
        return "invalid"
    if path is None:
        return "unknown"
    comparison = path.lower()
    if any(pattern in comparison for pattern in (".env", ".aws/credentials", "/etc/passwd", "id_rsa", "secrets")):
        return "sensitive"
    if path == ".":
        return "lab_root"
    if path == "contracts" or path.startswith("contracts/"):
        return "contracts"
    return "lab_root"


POLICY_PARITY_CASES = [
    PolicyParityCase(
        "fallback_normal",
        build_runtime_context(
            tool_name="list_files",
            risk_score=0.0,
            sensitivity="medium",
            path="documents/",
            estimated_output_size_mb=0.001,
        ),
        "log_normal_runtime_call",
    ),
    PolicyParityCase(
        "server_unknown",
        build_runtime_context(trust_status="unknown"),
        "block_unknown_server",
    ),
    PolicyParityCase(
        "server_blocked",
        build_runtime_context(trust_status="blocked"),
        "block_unknown_server",
    ),
    PolicyParityCase(
        "sensitive_env",
        build_runtime_context(tool_name="read_file", path=".env"),
        "deny_sensitive_paths",
    ),
    PolicyParityCase(
        "sensitive_env_uppercase",
        build_runtime_context(tool_name="read_file", path=".ENV"),
        "deny_sensitive_paths",
    ),
    PolicyParityCase(
        "sensitive_env_mixed_case",
        build_runtime_context(tool_name="read_file", path=".Env"),
        "deny_sensitive_paths",
    ),
    PolicyParityCase(
        "sensitive_aws_credentials",
        build_runtime_context(tool_name="read_file", path=".aws/credentials"),
        "deny_sensitive_paths",
    ),
    PolicyParityCase(
        "sensitive_aws_credentials_uppercase",
        build_runtime_context(tool_name="read_file", path=".AWS/CREDENTIALS"),
        "deny_sensitive_paths",
    ),
    PolicyParityCase(
        "sensitive_etc_passwd",
        build_runtime_context(tool_name="read_file", path="/etc/passwd"),
        "deny_sensitive_paths",
    ),
    PolicyParityCase(
        "sensitive_id_rsa",
        build_runtime_context(tool_name="read_file", path="keys/id_rsa.backup"),
        "deny_sensitive_paths",
    ),
    PolicyParityCase(
        "sensitive_id_rsa_uppercase",
        build_runtime_context(tool_name="read_file", path="folder/ID_RSA"),
        "deny_sensitive_paths",
    ),
    PolicyParityCase(
        "sensitive_secrets",
        build_runtime_context(tool_name="read_file", path="data/secrets/config.json"),
        "deny_sensitive_paths",
    ),
    PolicyParityCase(
        "sensitive_secrets_uppercase",
        build_runtime_context(tool_name="read_file", path="SECRETS/api.txt"),
        "deny_sensitive_paths",
    ),
    PolicyParityCase(
        "contract_read_valid",
        build_runtime_context(tool_name="read_file", path="contracts/contract1.txt"),
        "allow_contracts_read",
    ),
    PolicyParityCase(
        "wrong_tool_in_contracts",
        build_runtime_context(tool_name="list_files", path="contracts/"),
        "log_normal_runtime_call",
    ),
    PolicyParityCase(
        "risk_below_threshold",
        build_runtime_context(risk_score=69.999),
        "log_normal_runtime_call",
    ),
    PolicyParityCase(
        "risk_at_threshold",
        build_runtime_context(risk_score=70.0),
        "warn_high_risk_tool",
    ),
    PolicyParityCase(
        "risk_above_threshold",
        build_runtime_context(risk_score=90.0),
        "warn_high_risk_tool",
    ),
    PolicyParityCase(
        "sensitivity_medium",
        build_runtime_context(sensitivity="medium"),
        "log_normal_runtime_call",
    ),
    PolicyParityCase(
        "sensitivity_high",
        build_runtime_context(sensitivity="high"),
        "require_approval_for_sensitive_tool",
    ),
    PolicyParityCase(
        "sensitivity_critical",
        build_runtime_context(sensitivity="critical"),
        "require_approval_for_sensitive_tool",
    ),
    PolicyParityCase(
        "size_equal_threshold",
        build_runtime_context(estimated_output_size_mb=10.0),
        "log_normal_runtime_call",
    ),
    PolicyParityCase(
        "size_above_threshold",
        build_runtime_context(estimated_output_size_mb=10.0001),
        "limit_large_outputs",
    ),
    PolicyParityCase(
        "size_large",
        build_runtime_context(estimated_output_size_mb=100.0),
        "limit_large_outputs",
    ),
    PolicyParityCase(
        "priority_unknown_server_env",
        build_runtime_context(trust_status="unknown", tool_name="read_file", path=".env"),
        "block_unknown_server",
    ),
    PolicyParityCase(
        "priority_blocked_server_env",
        build_runtime_context(trust_status="blocked", tool_name="read_file", path=".env"),
        "block_unknown_server",
    ),
    PolicyParityCase(
        "priority_unknown_server_contract",
        build_runtime_context(
            trust_status="unknown",
            tool_name="read_file",
            path="contracts/contract1.txt",
        ),
        "block_unknown_server",
    ),
    PolicyParityCase(
        "priority_unknown_server_all_lower",
        build_runtime_context(
            trust_status="unknown",
            tool_name="read_file",
            risk_score=90.0,
            sensitivity="high",
            path="contracts/contract1.txt",
            estimated_output_size_mb=100.0,
        ),
        "block_unknown_server",
    ),
    PolicyParityCase(
        "priority_sensitive_path_high_sensitivity",
        build_runtime_context(tool_name="read_file", sensitivity="high", path=".env"),
        "deny_sensitive_paths",
    ),
    PolicyParityCase(
        "priority_sensitive_path_large_output",
        build_runtime_context(
            tool_name="read_file",
            path=".env",
            estimated_output_size_mb=100.0,
        ),
        "deny_sensitive_paths",
    ),
    PolicyParityCase(
        "priority_sensitive_path_high_risk",
        build_runtime_context(tool_name="read_file", risk_score=90.0, path=".env"),
        "deny_sensitive_paths",
    ),
    PolicyParityCase(
        "priority_contract_env",
        build_runtime_context(tool_name="read_file", path="contracts/.env"),
        "deny_sensitive_paths",
    ),
    PolicyParityCase(
        "priority_high_sensitivity_limit_warn_contract",
        build_runtime_context(
            tool_name="read_file",
            risk_score=90.0,
            sensitivity="high",
            path="contracts/contract1.txt",
            estimated_output_size_mb=100.0,
        ),
        "require_approval_for_sensitive_tool",
    ),
    PolicyParityCase(
        "priority_large_output_warn_contract",
        build_runtime_context(
            tool_name="read_file",
            risk_score=90.0,
            path="contracts/contract1.txt",
            estimated_output_size_mb=100.0,
        ),
        "limit_large_outputs",
    ),
    PolicyParityCase(
        "priority_high_risk_contract",
        build_runtime_context(
            tool_name="read_file",
            risk_score=90.0,
            path="contracts/contract1.txt",
        ),
        "warn_high_risk_tool",
    ),
    PolicyParityCase(
        "priority_contract_only",
        build_runtime_context(
            tool_name="read_file",
            risk_score=0.0,
            path="contracts/contract1.txt",
        ),
        "allow_contracts_read",
    ),
    PolicyParityCase(
        "priority_high_sensitivity_high_risk",
        build_runtime_context(risk_score=90.0, sensitivity="high"),
        "require_approval_for_sensitive_tool",
    ),
    PolicyParityCase(
        "priority_large_output_high_risk",
        build_runtime_context(risk_score=90.0, estimated_output_size_mb=100.0),
        "limit_large_outputs",
    ),
    PolicyParityCase(
        "invalid_arguments_only",
        build_runtime_context(arguments_valid=False),
        "deny_invalid_arguments",
    ),
    PolicyParityCase(
        "unknown_server_and_invalid_arguments",
        build_runtime_context(trust_status="unknown", arguments_valid=False),
        "block_unknown_server",
    ),
    PolicyParityCase(
        "invalid_arguments_and_sensitive_path",
        build_runtime_context(
            tool_name="read_file",
            path=".env",
            arguments_valid=False,
        ),
        "deny_invalid_arguments",
    ),
    PolicyParityCase(
        "invalid_arguments_and_contract",
        build_runtime_context(
            tool_name="read_file",
            path="contracts/contract1.txt",
            arguments_valid=False,
        ),
        "deny_invalid_arguments",
    ),
    PolicyParityCase(
        "invalid_arguments_and_high_risk",
        build_runtime_context(risk_score=90.0, arguments_valid=False),
        "deny_invalid_arguments",
    ),
    PolicyParityCase(
        "invalid_arguments_and_sensitive_tool",
        build_runtime_context(sensitivity="high", arguments_valid=False),
        "deny_invalid_arguments",
    ),
    PolicyParityCase(
        "invalid_arguments_and_large_output",
        build_runtime_context(
            estimated_output_size_mb=100.0,
            arguments_valid=False,
        ),
        "deny_invalid_arguments",
    ),
    PolicyParityCase(
        "canonical_sensitive_over_raw_contract",
        build_runtime_context(
            tool_name="read_file",
            path="contracts/contract1.txt",
            canonical_resource=".env",
        ),
        "deny_sensitive_paths",
    ),
    PolicyParityCase(
        "canonical_uppercase_env_over_raw_contract",
        build_runtime_context(
            tool_name="read_file",
            path="contracts/contract1.txt",
            canonical_resource=".ENV",
        ),
        "deny_sensitive_paths",
    ),
    PolicyParityCase(
        "canonical_contract_over_raw_sensitive",
        build_runtime_context(
            tool_name="read_file",
            path=".env",
            canonical_resource="contracts/contract1.txt",
        ),
        "allow_contracts_read",
    ),
    PolicyParityCase(
        "unknown_subject",
        build_runtime_context(
            authorization_status="unknown",
            grants=[],
        ),
        "deny_unknown_subject",
    ),
    PolicyParityCase(
        "unclassified_capability",
        build_runtime_context(
            tool_name="generic_tool",
            path="documents/file.txt",
        ),
        "deny_unclassified_capability",
    ),
    PolicyParityCase(
        "capability_not_granted",
        build_runtime_context(
            tool_name="read_file",
            path="contracts/contract1.txt",
            grants=[{"capability": "filesystem.list", "scopes": ["lab_root"]}],
        ),
        "deny_capability_not_granted",
    ),
    PolicyParityCase(
        "scope_not_granted",
        build_runtime_context(
            tool_name="read_file",
            path="public/readme.txt",
            grants=[{"capability": "filesystem.read", "scopes": ["contracts"]}],
        ),
        "deny_scope_not_granted",
    ),
    PolicyParityCase(
        "exact_read_contract_grant",
        build_runtime_context(
            tool_name="read_file",
            path="contracts/contract1.txt",
            grants=[{"capability": "filesystem.read", "scopes": ["contracts"]}],
        ),
        "allow_contracts_read",
    ),
    PolicyParityCase(
        "exact_list_root_grant",
        build_runtime_context(
            tool_name="list_files",
            path=".",
            grants=[{"capability": "filesystem.list", "scopes": ["lab_root"]}],
        ),
        "log_normal_runtime_call",
    ),
    PolicyParityCase(
        "cross_product_scope_attack",
        build_runtime_context(
            tool_name="read_file",
            path="public/readme.txt",
            grants=[
                {"capability": "filesystem.read", "scopes": ["contracts"]},
                {"capability": "filesystem.list", "scopes": ["lab_root"]},
            ],
        ),
        "deny_scope_not_granted",
    ),
    PolicyParityCase(
        "unknown_server_and_unknown_subject",
        build_runtime_context(
            trust_status="unknown",
            authorization_status="unknown",
            grants=[],
        ),
        "block_unknown_server",
    ),
    PolicyParityCase(
        "invalid_arguments_and_unknown_subject",
        build_runtime_context(
            arguments_valid=False,
            authorization_status="unknown",
            grants=[],
        ),
        "deny_invalid_arguments",
    ),
    PolicyParityCase(
        "unknown_subject_and_sensitive",
        build_runtime_context(
            tool_name="read_file",
            path=".env",
            authorization_status="unknown",
            grants=[],
        ),
        "deny_unknown_subject",
    ),
    PolicyParityCase(
        "known_subject_without_grant_and_sensitive",
        build_runtime_context(
            tool_name="read_file",
            path=".env",
            grants=[],
        ),
        "deny_sensitive_paths",
    ),
    PolicyParityCase(
        "capability_denied_and_high_risk",
        build_runtime_context(
            tool_name="read_file",
            path="contracts/contract1.txt",
            risk_score=90.0,
            grants=[{"capability": "filesystem.list", "scopes": ["lab_root"]}],
        ),
        "deny_capability_not_granted",
    ),
    PolicyParityCase(
        "scope_denied_and_large_output",
        build_runtime_context(
            tool_name="read_file",
            path="public/readme.txt",
            estimated_output_size_mb=100.0,
            grants=[{"capability": "filesystem.read", "scopes": ["contracts"]}],
        ),
        "deny_scope_not_granted",
    ),
]
