from __future__ import annotations
from app.services.tda.types import AnalysisFinding
from app.services.tda.configuration import FINDING_DECISION_BLOCK
from app.services.tda.configuration import FINDING_DECISION_REVIEW
from app.services.tda.configuration import SENSITIVE_PARAMETER_NAMES
from app.services.tda.findings import _finding
from app.services.tda.serialization import _safe_excerpt
from app.services.tda.serialization import _safe_json
from app.services.tda.text import _schema_properties
from app.services.tda.schema_traversal import iter_schema_fields
from typing import Any


def _sensitive_parameter_kind(name: str, field_text: str) -> str | None:
    import re

    normalized = re.sub("([a-z0-9])([A-Z])", "\\1_\\2", name)
    normalized = re.sub("[^a-zA-Z0-9]+", "_", normalized).strip("_").lower()
    if normalized in SENSITIVE_PARAMETER_NAMES:
        return normalized
    tokens = {token for token in normalized.split("_") if token}
    if tokens.intersection({"command", "shell", "script"}):
        return next(
            (value for value in ("command", "shell", "script") if value in tokens)
        )
    if normalized in {"upload_uri", "callback_uri", "destination_uri"}:
        return normalized.replace("_uri", "_url")
    if "url" in tokens and tokens.intersection(
        {"upload", "callback", "destination", "webhook"}
    ):
        prefix = (
            next(
                (
                    value
                    for value in ("upload", "callback", "destination")
                    if value in tokens
                )
            )
            if tokens.intersection({"upload", "callback", "destination"})
            else "destination"
        )
        return f"{prefix}_url"
    if normalized in {"include_environment", "include_environment_variables"}:
        return "include_env"
    if tokens.intersection(
        {"password", "passwords", "credential", "credentials", "secret", "secrets"}
    ):
        return "credentials"
    if (
        normalized in {"api_key", "apikey"}
        or normalized.endswith("_api_key")
        or normalized.endswith("_access_token")
        or normalized.endswith("_refresh_token")
        or normalized.endswith("_auth_token")
        or normalized.endswith("_bearer_token")
        or (
            normalized
            in {
                "access_token",
                "refresh_token",
                "auth_token",
                "bearer_token",
                "api_token",
            }
        )
    ):
        return "token"
    if tokens.intersection({"delete", "overwrite"}):
        return "delete" if "delete" in tokens else "overwrite"
    credential_text = re.search(
        "\\b(passwords?|credentials?|api[_ -]?keys?|access tokens?|refresh tokens?|bearer tokens?|auth(?:entication|orization)? tokens?|secret values?)\\b",
        field_text,
        re.IGNORECASE,
    )
    if credential_text:
        return "credentials"
    return None


def _parameter_expected_by_contract(name: str, capabilities: set[str]) -> bool:
    if name in {"command", "shell", "script"}:
        return "process.execute" in capabilities
    if name in {"upload_url", "callback_url", "destination_url"}:
        return bool(capabilities.intersection({"network.request", "network.send"}))
    if name in {"include_env", "credentials", "token"}:
        return bool(
            capabilities.intersection(
                {"secret.read", "secret.access", "identity.manage"}
            )
        )
    if name in {"delete", "overwrite"}:
        return any(
            (
                capability.endswith(".delete")
                or capability in {"filesystem.write", "database.write"}
                for capability in capabilities
            )
        )
    return False


def _is_closed_zero_argument_schema(schema: dict[str, Any]) -> bool:
    return (
        schema.get("type") == "object"
        and schema.get("properties") == {}
        and (schema.get("additionalProperties") is False)
    )


def schema_header_findings(schema, source):
    findings: list[AnalysisFinding] = []
    if schema.get("additionalProperties") is True:
        findings.append(
            _finding(
                "schema_additional_properties_true",
                "schema_permissive",
                source,
                "medium",
                82,
                "additionalProperties is true",
                "Declare explicit properties and reject unexpected inputs.",
                decision=FINDING_DECISION_REVIEW,
            )
        )
    properties = _schema_properties(schema)
    if not properties and schema and (not _is_closed_zero_argument_schema(schema)):
        findings.append(
            _finding(
                "schema_too_permissive",
                "schema_permissive",
                source,
                "medium",
                70,
                "schema has no declared properties",
                "Declare a narrow input schema.",
                decision=FINDING_DECISION_REVIEW,
            )
        )
    return findings


def schema_parameter_findings(
    path, name, field_text, source, profile_capabilities, has_code_execution
):
    findings = []
    sensitive_kind = _sensitive_parameter_kind(name, field_text)
    if sensitive_kind and (
        not _parameter_expected_by_contract(
            sensitive_kind, profile_capabilities or set()
        )
    ):
        process_evidenced = (
            sensitive_kind in {"command", "shell", "script"}
            and has_code_execution
        )
        if sensitive_kind in {"command", "shell", "script"} and (not process_evidenced):
            return findings
        severity = "high" if process_evidenced else "medium"
        findings.append(
            _finding(
                f"sensitive_parameter_{sensitive_kind}",
                "dangerous_parameter",
                source,
                severity,
                90 if process_evidenced else 74,
                f"parameter '{_safe_excerpt(name)}' at {path}",
                "Require an explicit security profile and human review for this parameter.",
                decision=FINDING_DECISION_BLOCK
                if process_evidenced
                else FINDING_DECISION_REVIEW,
            )
        )
    return findings
