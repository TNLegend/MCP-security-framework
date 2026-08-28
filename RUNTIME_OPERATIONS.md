# Runtime Operations

Lot 7 makes the governed MCP runtime measurable, bounded, and recoverable without weakening fail-closed security.

## Operational evidence

Every persisted Runtime Call may include bounded timing evidence for:

- Gateway mediation;
- policy/backend evaluation;
- upstream MCP execution;
- specialized adapter and Tool Result Guard inspection.

The Operations API aggregates the configured recent window and reports exact call counts plus latency samples with average, p50, p95, p99, and max values. Latency sampling is bounded to the latest 10,000 calls while SQL counters remain exact for the complete window.

## Readiness

`/api/v1/health` remains process liveness.

`/api/v1/readiness` checks the Backend, PostgreSQL, OPA, Gateway, and identity provider. It returns HTTP 503 when a required dependency is not healthy.

The authenticated Control Center Operations page shows the same service readiness together with runtime, storage, and database-pool evidence.

## PostgreSQL and Runtime Calls

The database engine uses `pool_pre_ping` and configurable pool size, overflow, timeout, and recycle values.

Runtime Calls include indexes for the operational filters already used by the Control Center: creation time, decision, server, tool, and agent.

Runtime log retention is bounded by both age and maximum row count. Cleanup is batch-limited. Runtime Calls referenced by `policy_decisions` are protected from deletion.

An ADMIN can preview or apply cleanup through the Operations page. The preview is non-mutating and apply is audited. Automatic retention runs only at the configured Runtime Call interval and writes a system audit event when it deletes rows.

## Process logs and recovery

Framework-owned child stdout/stderr is continuously drained through active size-based rotation. Both active-file size and backup count are bounded.

If Backend, OPA, Gateway, or the local identity provider exits unexpectedly, the supervisor performs only the configured number of controlled restart attempts with bounded backoff. When recovery is disabled, fails, or is exhausted, the launcher exits non-zero and shuts down its remaining owned children instead of continuing in a partial state.

## Benchmarking

`scripts/benchmark_runtime.py` sends concurrent real JSON-RPC `tools/call` traffic through the Gateway. It reports throughput, average latency, p50/p95/p99/max, HTTP status distribution, outcomes, and bounded error codes.

The harness can issue a short-lived local IdP token in memory. Tokens are never included in the report.

Security expectations can be declared as `EXECUTED`, `BLOCKED`, or `ANY`. A mismatch makes the benchmark fail, allowing load tests to detect fail-open behavior rather than measuring latency alone.

Example:

    .\backend\.venv\Scripts\python.exe scripts\benchmark_runtime.py \
      --server-id 1 \
      --tool list_files \
      --arguments-json "{}" \
      --requests 100 \
      --concurrency 10 \
      --expected-outcome EXECUTED \
      --local-subject service-account-llm-agent-demo

For a negative load scenario, use an identity expected to be denied and set `--expected-outcome BLOCKED`.

## Security invariants

Performance and operations controls never bypass OPA, identity verification, argument validation, adapter validation, Tool Result Guard, Emergency Deny, or audit controls.

Dependency failure or overload is not an authorization fallback. Policy failure remains fail-closed and must not reach the upstream MCP.
