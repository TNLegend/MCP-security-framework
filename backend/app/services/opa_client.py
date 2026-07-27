import json
import socket
import urllib.error
import urllib.request
from typing import Any

from pydantic import ValidationError

from app.schemas.policy_decision import PolicyDecision


MAX_OPA_RESPONSE_BYTES = 1024 * 1024


class OPAClientError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class OPAClient:
    def __init__(
        self,
        *,
        base_url: str,
        decision_path: str,
        timeout_seconds: float,
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be greater than zero.")

        self.base_url = base_url.rstrip("/")
        self.decision_path = (
            decision_path if decision_path.startswith("/") else f"/{decision_path}"
        )
        self.timeout_seconds = timeout_seconds

    @property
    def decision_url(self) -> str:
        return f"{self.base_url}{self.decision_path}"

    def evaluate(self, context: dict[str, Any]) -> PolicyDecision:
        request_body = json.dumps({"input": context}).encode("utf-8")
        request = urllib.request.Request(
            self.decision_url,
            data=request_body,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(
                request,
                timeout=self.timeout_seconds,
            ) as response:
                raw_body = response.read(MAX_OPA_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as exc:
            raise OPAClientError(
                "opa_http_error",
                f"OPA returned HTTP status {exc.code}.",
            ) from exc
        except urllib.error.URLError as exc:
            if _is_timeout_error(exc):
                raise OPAClientError("opa_timeout", "OPA request timed out.") from exc
            raise OPAClientError("opa_unavailable", "OPA is unavailable.") from exc
        except (socket.timeout, TimeoutError) as exc:
            raise OPAClientError("opa_timeout", "OPA request timed out.") from exc

        if len(raw_body) > MAX_OPA_RESPONSE_BYTES:
            raise OPAClientError(
                "opa_response_too_large",
                "OPA response exceeded the allowed size.",
            )

        try:
            payload = json.loads(raw_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise OPAClientError("opa_invalid_json", "OPA returned invalid JSON.") from exc

        if not isinstance(payload, dict):
            raise OPAClientError(
                "opa_invalid_response",
                "OPA response root must be an object.",
            )

        if "result" not in payload:
            raise OPAClientError(
                "opa_undefined_result",
                "OPA response did not contain a result.",
            )

        result = payload["result"]
        if not isinstance(result, dict):
            raise OPAClientError(
                "opa_invalid_result",
                "OPA result must be an object.",
            )

        try:
            return PolicyDecision.model_validate(result)
        except ValidationError as exc:
            raise OPAClientError(
                "opa_invalid_decision",
                "OPA result is not a valid PolicyDecision.",
            ) from exc


def _is_timeout_error(exc: urllib.error.URLError) -> bool:
    reason = getattr(exc, "reason", None)
    return isinstance(reason, (socket.timeout, TimeoutError))
