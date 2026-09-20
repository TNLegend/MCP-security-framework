from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import os
from pathlib import Path
import statistics
import sys
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = PROJECT_ROOT / "backend"
for path in (str(PROJECT_ROOT), str(BACKEND_DIR)):
    if path not in sys.path:
        sys.path.insert(0, path)

from common.project_environment import load_project_environment  # noqa: E402
from proxy.protocol_profiles import ProtocolProfileRegistry, TransportKind  # noqa: E402
from proxy.protocol_revisions import ProtocolEra  # noqa: E402
from scripts.local_identity_provider import issue_access_token  # noqa: E402


def benchmark_gateway(
    *,
    gateway_url: str,
    server_id: int,
    tool_name: str,
    arguments: dict[str, Any],
    bearer_token: str,
    protocol_version: str,
    requests_count: int,
    concurrency: int,
    timeout_seconds: float,
    expected_outcome: str,
    warmup: int = 3,
) -> dict[str, Any]:
    if requests_count < 1 or requests_count > 100_000:
        raise ValueError("requests_count_out_of_range")
    if concurrency < 1 or concurrency > 200:
        raise ValueError("concurrency_out_of_range")
    if timeout_seconds <= 0 or timeout_seconds > 120:
        raise ValueError("timeout_seconds_out_of_range")
    if expected_outcome not in {"EXECUTED", "BLOCKED", "ANY"}:
        raise ValueError("expected_outcome_invalid")

    endpoint = gateway_url.rstrip("/") + "/mcp/" + str(server_id)
    profile = ProtocolProfileRegistry().get_by_version(protocol_version)
    session_id: str | None = None
    if profile.protocol_era == ProtocolEra.LEGACY:
        if profile.transport_kind == TransportKind.LEGACY_HTTP_SSE:
            raise ValueError("legacy_http_sse_benchmark_unsupported")
        session_id = _create_legacy_session(
            endpoint=endpoint,
            protocol_version=protocol_version,
            timeout_seconds=timeout_seconds,
        )

    for index in range(max(0, min(warmup, 20))):
        _invoke(
            endpoint=endpoint,
            request_id=-(index + 1),
            tool_name=tool_name,
            arguments=arguments,
            bearer_token=bearer_token,
            profile=profile,
            session_id=session_id,
            timeout_seconds=timeout_seconds,
        )

    started = time.perf_counter()
    results: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=min(concurrency, requests_count)) as executor:
        futures = [
            executor.submit(
                _invoke,
                endpoint=endpoint,
                request_id=index + 1,
                tool_name=tool_name,
                arguments=arguments,
                bearer_token=bearer_token,
                profile=profile,
                session_id=session_id,
                timeout_seconds=timeout_seconds,
            )
            for index in range(requests_count)
        ]
        for future in as_completed(futures):
            results.append(future.result())
    elapsed = time.perf_counter() - started

    latencies = sorted(item["latency_ms"] for item in results)
    outcomes = {
        "executed": sum(1 for item in results if item["outcome"] == "EXECUTED"),
        "blocked": sum(1 for item in results if item["outcome"] == "BLOCKED"),
        "errors": sum(1 for item in results if item["outcome"] == "ERROR"),
    }
    unexpected = sum(
        1
        for item in results
        if expected_outcome != "ANY" and item["outcome"] != expected_outcome
    )
    report = {
        "report_version": "1",
        "gateway": gateway_url.rstrip("/"),
        "server_id": server_id,
        "tool_name": tool_name,
        "protocol_version": protocol_version,
        "warmup_requests": max(0, min(warmup, 20)),
        "requests": requests_count,
        "concurrency": concurrency,
        "elapsed_seconds": round(elapsed, 6),
        "throughput_requests_per_second": round(requests_count / elapsed, 3) if elapsed else 0.0,
        "latency_ms": {
            "avg": round(statistics.fmean(latencies), 3),
            "p50": _percentile(latencies, 0.50),
            "p95": _percentile(latencies, 0.95),
            "p99": _percentile(latencies, 0.99),
            "max": round(latencies[-1], 3),
        },
        "outcomes": outcomes,
        "expected_outcome": expected_outcome,
        "unexpected_outcomes": unexpected,
        "security_expectation_met": unexpected == 0,
        "http_statuses": _counts(item["http_status"] for item in results),
        "error_codes": _counts(
            item["error_code"] for item in results if item.get("error_code")
        ),
    }
    return report


def _create_legacy_session(
    *,
    endpoint: str,
    protocol_version: str,
    timeout_seconds: float,
) -> str:
    initialize = {
        "jsonrpc": "2.0",
        "id": 0,
        "method": "initialize",
        "params": {
            "protocolVersion": protocol_version,
            "capabilities": {},
            "clientInfo": {
                "name": "mcp-security-framework-benchmark",
                "version": "1",
            },
        },
    }
    request = Request(
        endpoint,
        data=json.dumps(initialize, separators=(",", ":")).encode("utf-8"),
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    with urlopen(request, timeout=timeout_seconds) as response:
        raw = response.read()
        if response.getcode() != 200:
            raise RuntimeError("legacy_initialize_failed")
        session_id = response.headers.get("Mcp-Session-Id")
    if not isinstance(session_id, str) or not session_id.strip():
        raise RuntimeError("legacy_session_header_missing")
    parsed = json.loads(raw.decode("utf-8")) if raw else {}
    result = parsed.get("result")
    if (
        not isinstance(result, dict)
        or result.get("protocolVersion") != protocol_version
    ):
        raise RuntimeError("legacy_initialize_protocol_mismatch")

    initialized = {
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {},
    }
    request = Request(
        endpoint,
        data=json.dumps(initialized, separators=(",", ":")).encode("utf-8"),
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "MCP-Protocol-Version": protocol_version,
            "Mcp-Session-Id": session_id,
        },
    )
    with urlopen(request, timeout=timeout_seconds) as response:
        response.read()
        if response.getcode() != 202:
            raise RuntimeError("legacy_initialized_notification_failed")
    return session_id


def _invoke(
    *,
    endpoint: str,
    request_id: int,
    tool_name: str,
    arguments: dict[str, Any],
    bearer_token: str,
    profile,
    session_id: str | None,
    timeout_seconds: float,
) -> dict[str, Any]:
    payload, protocol_headers = profile.serialize_tool_call(
        request_id=request_id,
        name=tool_name,
        arguments=arguments,
    )
    headers = {
        "Authorization": "Bearer " + bearer_token,
        "Content-Type": "application/json",
        "Accept": "application/json",
        **protocol_headers,
    }
    if session_id:
        headers["Mcp-Session-Id"] = session_id
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    request = Request(
        endpoint,
        data=body,
        method="POST",
        headers=headers,
    )
    started = time.perf_counter()
    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            raw = response.read()
            status = response.getcode()
        parsed = json.loads(raw.decode("utf-8")) if raw else {}
        outcome = "EXECUTED" if status == 200 and "result" in parsed else "ERROR"
        code = _response_error_code(parsed)
    except HTTPError as exc:
        status = exc.code
        try:
            parsed = json.loads(exc.read().decode("utf-8"))
        except Exception:
            parsed = {}
        outcome = "BLOCKED" if status == 403 else "ERROR"
        code = _response_error_code(parsed) or ("http_" + str(status))
    except (URLError, TimeoutError, OSError):
        status = 0
        outcome = "ERROR"
        code = "transport_error"
    except Exception:
        status = 0
        outcome = "ERROR"
        code = "unexpected_client_error"
    return {
        "latency_ms": round((time.perf_counter() - started) * 1000, 3),
        "http_status": status,
        "outcome": outcome,
        "error_code": code,
    }


def _response_error_code(payload: dict[str, Any]) -> str | None:
    error = payload.get("error")
    if not isinstance(error, dict):
        return None
    message = error.get("message")
    if isinstance(message, str) and message and message != "tool_call_blocked":
        return message[:128]
    data = error.get("data")
    if isinstance(data, dict):
        value = data.get("skip_reason") or data.get("rule_id")
        if isinstance(value, str) and value:
            return value[:128]
    return str(message)[:128] if message else None


def _percentile(values: list[float], quantile: float) -> float:
    if not values:
        return 0.0
    if len(values) == 1:
        return round(values[0], 3)
    position = (len(values) - 1) * quantile
    lower = int(position)
    upper = min(lower + 1, len(values) - 1)
    fraction = position - lower
    return round(values[lower] + (values[upper] - values[lower]) * fraction, 3)


def _counts(values) -> dict[str, int]:
    result: dict[str, int] = {}
    for value in values:
        key = str(value)
        result[key] = result.get(key, 0) + 1
    return dict(sorted(result.items()))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Concurrent benchmark for the governed MCP Gateway."
    )
    parser.add_argument("--gateway-url", default="http://127.0.0.1:9001")
    parser.add_argument("--server-id", type=int, required=True)
    parser.add_argument("--tool", required=True)
    parser.add_argument("--arguments-json", default="{}")
    parser.add_argument("--protocol-version", default="2025-11-25")
    parser.add_argument("--requests", type=int, default=100)
    parser.add_argument("--concurrency", type=int, default=10)
    parser.add_argument("--timeout-seconds", type=float, default=20.0)
    parser.add_argument(
        "--warmup",
        type=int,
        default=0,
        help="Unmeasured tool calls made before the benchmark (default: 0).",
    )
    parser.add_argument(
        "--expected-outcome",
        choices=("EXECUTED", "BLOCKED", "ANY"),
        default="ANY",
    )
    parser.add_argument(
        "--local-subject",
        default="service-account-llm-agent-demo",
        help="Local IdP subject. Token is generated in memory and never printed.",
    )
    parser.add_argument(
        "--token-env",
        default="",
        help="Optional environment variable holding a bearer token instead of local issuance.",
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    load_project_environment()
    arguments = json.loads(args.arguments_json)
    if not isinstance(arguments, dict):
        raise SystemExit("--arguments-json must decode to an object")

    token = os.getenv(args.token_env, "") if args.token_env else ""
    if not token:
        token = issue_access_token(
            subject=args.local_subject,
            lifetime_seconds=max(300, int(args.timeout_seconds * 4)),
        )

    report = benchmark_gateway(
        gateway_url=args.gateway_url,
        server_id=args.server_id,
        tool_name=args.tool,
        arguments=arguments,
        bearer_token=token,
        protocol_version=args.protocol_version,
        requests_count=args.requests,
        concurrency=args.concurrency,
        timeout_seconds=args.timeout_seconds,
        expected_outcome=args.expected_outcome,
        warmup=args.warmup,
    )
    rendered = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0 if report["security_expectation_met"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
