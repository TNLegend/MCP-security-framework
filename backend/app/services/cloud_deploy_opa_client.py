"""OPA advisory-only Deploy Security client; never a Runtime authorization oracle."""
from __future__ import annotations

import json
import socket
import urllib.error
import urllib.request
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

_DEPLOY_DECISION_PATH = "/v1/data/mcp/security/deploy/decision"
_MAX_OPA_RESPONSE_BYTES = 64 * 1024
_MAX_INPUT_BYTES = 128 * 1024


class DeployOPAError(ValueError):
    pass


class DeployAdvisoryDecision(BaseModel):
    classification: Literal[
        "REVIEW_REQUIRED", "EVIDENCE_INCOMPLETE", "OBSERVATION_ONLY"
    ]
    rule_ids: list[str] = Field(min_length=1, max_length=8)
    obligations: list[Literal["ADMIN_REVIEW", "REVIEW_EVIDENCE", "LOG"]] = Field(
        min_length=1, max_length=4
    )
    explanation: str = Field(min_length=1, max_length=500)
    policy_revision: Literal["opa-deploy-security-advisory-v1"]
    runtime_enforcement: Literal[False]
    effective_aws_authorization_proven: Literal[False]

    model_config = ConfigDict(extra="forbid")

    @model_validator(mode="after")
    def obligations_match_classification(self):
        required = {
            "REVIEW_REQUIRED": {"ADMIN_REVIEW", "LOG"},
            "EVIDENCE_INCOMPLETE": {"REVIEW_EVIDENCE", "LOG"},
            "OBSERVATION_ONLY": {"LOG"},
        }[self.classification]
        if len(self.obligations) != len(required) or set(self.obligations) != required:
            raise ValueError("deploy_governance_obligations_incoherent")
        return self


class DeployOPAClient:
    """Call a separate OPA path, fixed and distinct from Runtime's policy."""

    def __init__(self, *, base_url: str, timeout_seconds: float):
        if timeout_seconds <= 0 or timeout_seconds > 30:
            raise ValueError("invalid_deploy_opa_timeout")
        if not (base_url.startswith("http://") or base_url.startswith("https://")):
            raise ValueError("invalid_deploy_opa_url")
        self.url = base_url.rstrip("/") + _DEPLOY_DECISION_PATH
        self.timeout_seconds = timeout_seconds

    def evaluate(self, verified_context: dict) -> DeployAdvisoryDecision:
        if not isinstance(verified_context, dict):
            raise DeployOPAError("DEPLOY_OPA_INPUT_INVALID")
        request_bytes = json.dumps(
            {"input": verified_context},
            sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")
        if len(request_bytes) > _MAX_INPUT_BYTES:
            raise DeployOPAError("DEPLOY_OPA_INPUT_TOO_LARGE")
        request = urllib.request.Request(
            self.url, data=request_bytes,
            headers={"Accept": "application/json", "Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                raw = response.read(_MAX_OPA_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as exc:
            raise DeployOPAError("DEPLOY_OPA_HTTP_ERROR") from exc
        except (urllib.error.URLError, socket.timeout, TimeoutError) as exc:
            raise DeployOPAError("DEPLOY_OPA_UNAVAILABLE_OR_TIMEOUT") from exc
        if len(raw) > _MAX_OPA_RESPONSE_BYTES:
            raise DeployOPAError("DEPLOY_OPA_RESPONSE_TOO_LARGE")
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise DeployOPAError("DEPLOY_OPA_INVALID_JSON") from exc
        if not isinstance(payload, dict) or "result" not in payload:
            raise DeployOPAError("DEPLOY_OPA_UNDEFINED_RESULT")
        try:
            return DeployAdvisoryDecision.model_validate(payload["result"])
        except ValidationError as exc:
            raise DeployOPAError("DEPLOY_OPA_INVALID_DECISION") from exc
