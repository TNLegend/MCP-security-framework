import { formatServerTime } from "../utils/serverTime.js";
import { useRef, useState } from "react";

import {
  cleanupRuntimeLogs, fetchUnresolvedRuntimeOperations,
  fetchRuntimeOperationReconciliation, safeErrorMessage,
} from "../api/client";
import "./management.css";


function Operations({ isAdmin = false, loading = false, onRefresh, summary }) {
  const [reason, setReason] = useState("Apply bounded runtime log retention maintenance.");
  const [preview, setPreview] = useState(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const cleanupLock = useRef(false);
  const [error, setError] = useState("");
  const [unresolvedCases, setUnresolvedCases] = useState(null);
  const [investigationError, setInvestigationError] = useState("");
  const [investigationBusy, setInvestigationBusy] = useState(false);
  const [caseReconciliation, setCaseReconciliation] = useState(null);

  async function inspectUnresolvedCases() {
    setCaseReconciliation(null);
    setInvestigationBusy(true);
    setInvestigationError("");
    try {
      setUnresolvedCases(await fetchUnresolvedRuntimeOperations());
    } catch (err) {
      setInvestigationError("Unresolved operations could not be loaded: " + safeErrorMessage(err));
    } finally {
      setInvestigationBusy(false);
    }
  }

  async function reconcileCase(operationId) {
    setCaseReconciliation(null);
    setInvestigationBusy(true);
    setInvestigationError("");
    try {
      const detail = await fetchRuntimeOperationReconciliation(operationId);
      setCaseReconciliation({ operationId, detail });
    } catch {
      setInvestigationError("This operation could not be reconciled. Its effects are still unknown; do not retry automatically.");
    } finally {
      setInvestigationBusy(false);
    }
  }

  async function runCleanup(dryRun) {
    if (!isAdmin || loading || cleanupLock.current || reason.trim().length < 10) return;
    if (!dryRun && (!preview || preview.planned <= 0 ||
                    !preview.preview_fingerprint)) {
      setError("A current, verified preview is required before applying retention.");
      return;
    }
    if (!dryRun && !window.confirm("Apply log retention cleanup? " + preview.planned + " eligible rows were identified in the preview.")) return;
    cleanupLock.current = true;
    setPreview(null);
    setBusy(true);
    setError("");
    setMessage("");
    try {
      const result = await cleanupRuntimeLogs({
        dry_run: dryRun,
        reason: reason.trim(),
        expected_preview_fingerprint: dryRun ? null : preview.preview_fingerprint,
      });
      if (dryRun) {
        setPreview(result);
        setMessage(
          result.planned > 0
            ? "Preview ready: " + result.planned + " row(s) would be removed."
            : "Preview ready: no rows require cleanup.",
        );
      } else {
        setPreview(null);
        setMessage("Retention applied to the exact previewed set: " +
          result.deleted + " row(s) removed. See the recorded maintenance receipt.");
        await onRefresh?.();
      }
    } catch (err) {
      setError(safeErrorMessage(err));
    } finally {
      cleanupLock.current = false;
      setBusy(false);
    }
  }

  const windowStats = summary?.window;
  const pool = summary?.database_pool;
  const storage = summary?.runtime_storage;

  return (
    <section className="page-section operations-page">
      <div className="section-heading">
        <div>
          <h2>System health</h2>
          <p>Check service status and recent errors.</p>
        </div>
        <span className={"operations-ready " + (summary ? (summary.ready ? "ready" : "not-ready") : "readiness-unknown")}>
          {summary ? (summary.ready ? "Ready" : "Not ready") : loading ? "Checking readiness" : "Readiness unavailable"}
        </span>
      </div>

      <nav aria-label="System health sections" className="management-jump-links">
        <a href="#service-readiness">Service readiness</a>
        <a href="#recent-activity">Recent activity</a>
        <a href="#storage-diagnostics">Storage diagnostics</a>
        <a href="#log-retention">Log retention</a>
      </nav>
      <section className="detail-panel" id="service-readiness">
        <div className="operations-section-heading">
          <h3>Service readiness</h3>
          <small>{summary?.generated_at ? "Generated " + formatDate(summary.generated_at) : "-"}</small>
        </div>
        {!summary && <p className="hint-text" role="status">{loading ? "Checking service status..." : "Service status is unavailable. Use Refresh in the header to try again."}</p>}
        <div className="status-grid operations-status-grid">
          {Object.entries(summary?.components || {}).map(([key, component]) => (
            <div className="status-panel compact-status" key={key}>
              <span>{humanize(key)}</span>
              <strong>{component?.status || "unknown"}</strong>
              {component?.detail && <small>{component.detail}</small>}
              {component?.endpoint && <small>{component.endpoint}</small>}
            </div>
          ))}
        </div>
      </section>

      <section className="detail-panel" aria-label="Installation and recovery diagnostics">
        <h3>Installation and recovery checks</h3>
        <p>These are operator diagnostics, not automatic repair actions.
          A green health endpoint alone does not establish that a signed
          configuration is active or that all scanners are installed.</p>
        <details>
          <summary>How to investigate an unavailable service</summary>
          <ul>
            <li><strong>Backend:</strong> verify the Windows launch script,
              environment checks and startup logs, then inspect the API
              readiness endpoint. Do not bypass failed integrity checks.</li>
            <li><strong>PostgreSQL:</strong> check the configured local
              connection and schema-migration receipt; do not point a test
              instance at a production database.</li>
            <li><strong>Policy engine:</strong> verify the pinned OPA binary,
              policy bundle SHA-256 and decision endpoint; restart only after
              confirming the published policy revision.</li>
            <li><strong>Gateway / Proxy:</strong> check the listener, signed
              tool catalog and the exact agent/server binding. A direct
              upstream endpoint bypasses Gateway controls.</li>
            <li><strong>Scanners:</strong> inspect each scanner's installed
              status in Code scans and Cloud security. Missing scanners
              mean incomplete coverage, not clean results.</li>
          </ul>
          <p>After correcting a prerequisite, rerun the startup
            self-check and verify an isolated MCP call before enabling
            normal workloads. No command in this panel mutates the system.</p>
        </details>
      </section>

      <section className="detail-panel" id="recent-activity">
        <div className="operations-section-heading">
          <h3>Recent activity</h3>
          <small>Last {windowStats?.window_minutes || "-"} minute(s)</small>
        </div>
        <div className="stats-grid">
          <Metric label="Calls" value={windowStats?.total_calls} />
          <Metric label="Calls / min" value={formatNumber(windowStats?.calls_per_minute)} />
          <Metric label="ALLOW" value={windowStats?.allowed} tone="stat-good" />
          <Metric label="BLOCK" value={windowStats?.blocked} tone="stat-danger" />
          <Metric label="Errors" value={windowStats?.errors} tone="stat-warn" />
          <Metric label="Error rate" value={formatPercent(windowStats?.error_rate)} />
          <Metric label="Executed" value={windowStats?.executed} />
          <Metric label="Result blocked" value={windowStats?.result_blocked} tone="stat-warn" />
        </div>
        {windowStats?.outcome_states && Object.keys(windowStats.outcome_states).length > 0 && (
          <div className="stats-grid" aria-label="Disjoint recorded outcome categories">
            <Metric label="Sent, outcome uncertain" value={windowStats.outcome_states.sent_uncertain ?? 0} tone="stat-warn" />
            <Metric label="Response withheld" value={windowStats.outcome_states.response_withheld ?? 0} />
            <Metric label="Execution recorded" value={windowStats.outcome_states.execution_recorded ?? 0} />
            <Metric label="Confirmed not sent" value={windowStats.outcome_states.confirmed_not_sent ?? 0} />
            <Metric label="Legacy / unclassified" value={windowStats.outcome_states.legacy_or_unclassified ?? 0} />
          </div>
        )}
        <p className="hint-text" role="note">
          The five outcome categories above are mutually exclusive and add up to Calls.
          ALLOW, BLOCK, executed, result-blocked and error remain independent diagnostic facets and can overlap.
          Legacy rows without durable dispatch evidence do not prove non-execution.
        </p>

        <div className="table-wrap operations-latency-table">
          <table>
            <thead>
              <tr>
                <th>Stage</th>
                <th>Samples</th>
                <th>Avg</th>
                <th>p50</th>
                <th>p95</th>
                <th>p99</th>
                <th>Max</th>
              </tr>
            </thead>
            <tbody>
              <LatencyRow label="Gateway mediation" stats={windowStats?.total_latency} />
              <LatencyRow label="Policy / backend" stats={windowStats?.policy_latency} />
              <LatencyRow label="Upstream MCP" stats={windowStats?.upstream_latency} />
              <LatencyRow label="Result Guard" stats={windowStats?.result_guard_latency} />
            </tbody>
          </table>
        </div>
      </section>

      <div className="dashboard-layout operations-layout" id="storage-diagnostics">
        <section className="detail-panel">
          <h3>PostgreSQL pool</h3>
          <dl className="compact-dl">
            <Row label="Pool size" value={pool?.pool_size} />
            <Row label="Checked out" value={pool?.checked_out} />
            <Row label="Checked in" value={pool?.checked_in} />
            <Row label="Overflow" value={pool?.overflow} />
            <Row label="Configured pool" value={pool?.configured_pool_size} />
            <Row label="Max overflow" value={pool?.configured_max_overflow} />
            <Row label="Pool timeout" value={formatSeconds(pool?.pool_timeout_seconds)} />
            <Row label="Recycle" value={formatSeconds(pool?.pool_recycle_seconds)} />
          </dl>
        </section>

        <section className="detail-panel">
          <h3>Runtime storage</h3>
          <dl className="compact-dl">
            <Row label="Rows" value={storage?.total_rows} />
            <Row label="Unresolved MCP operations" value={storage?.unresolved_intents} />
            <Row label="Intent grace" value={storage?.intent_grace_seconds != null ? storage.intent_grace_seconds + " seconds" : "-"} />
            <Row label="Retention" value={storage ? storage.retention_days + " days" : "-"} />
            <Row label="Max rows" value={storage?.max_rows} />
            <Row label="Cleanup batch" value={storage?.cleanup_batch_size} />
            <Row
              label="Auto cleanup interval"
              value={
                storage?.auto_cleanup_interval_rows
                  ? storage.auto_cleanup_interval_rows + " rows"
                  : "-"
              }
            />
            <Row label="Oldest" value={formatDate(storage?.oldest_at)} />
            <Row label="Newest" value={formatDate(storage?.newest_at)} />
          </dl>
          <p className="hint-text">
            Unresolved operations have a durable intent but no completion event.
            The upstream effect is unknown; never automatically retry them.
          </p>
          <button className="secondary-action" type="button"
            disabled={investigationBusy} onClick={inspectUnresolvedCases}>
            {investigationBusy ? "Loading investigation..." : "Investigate unresolved operations"}
          </button>
          {investigationError && <p role="alert">{investigationError}</p>}
          {unresolvedCases && <div className="operator-investigation-list">
            <p role="status">{unresolvedCases.returned} unresolved operation(s)
              shown{unresolvedCases.truncated ? "; more exist beyond this 50-row limit" : ""}.
              These are not confirmed failures or safe retry candidates.</p>
            {unresolvedCases.items.length === 0 && <p>No unresolved operations past the configured grace period.</p>}
            <ul>{unresolvedCases.items.map((item) => (
              <li key={item.operation_id}>
                <strong>{item.tool_name}</strong>
                {" · "}{formatDate(item.created_at)}
                {" · "}<code>{item.operation_id}</code>
                <button type="button" className="tiny-action"
                  disabled={investigationBusy}
                  onClick={() => reconcileCase(item.operation_id)}>
                  Read reconciliation
                </button>
              </li>
            ))}</ul>
            {caseReconciliation && <div className="detail-panel" role="status">
              <p><strong>Operation:</strong> <code>{caseReconciliation.operationId}</code></p>
              <p><strong>Recorded state:</strong> {caseReconciliation.detail.state}</p>
              <p>Intent recorded: {String(caseReconciliation.detail.intent_recorded)};
                Admission recorded: {String(caseReconciliation.detail.admission_recorded)};
                Outcome recorded: {String(caseReconciliation.detail.outcome_recorded)}.</p>
              <p>Remote effect possible: {String(caseReconciliation.detail.effect_possible)}.
                Manual review: {String(caseReconciliation.detail.manual_reconciliation_required)}.</p>
              <p>Do not automatically replay a call whose upstream effect is unknown.</p>
            </div>}
          </div>}
        </section>

        <section className="detail-panel">
          <h3>Process log bounds</h3>
          <dl className="compact-dl">
            <Row
              label="Active file max"
              value={summary?.process_logs ? formatBytes(summary.process_logs.max_bytes) : "-"}
            />
            <Row label="Backups" value={summary?.process_logs?.backup_count} />
          </dl>
          <p className="hint-text">
            Framework-owned child stdout/stderr is drained through active size-based rotation.
          </p>
        </section>
      </div>

      <section className="detail-panel operations-maintenance" id="log-retention">
        <h3>Runtime log retention maintenance</h3>
        <p>
          Cleanup is ADMIN-only and bounded by the configured batch size. Preview does not mutate
          data and is a point-in-time estimate, not a transaction reservation.
          Apply now requires the exact preview fingerprint, checked against
          current row eligibility and retention settings. If anything has
          changed, Apply refuses without deleting rows; rerun Preview.
          This also prevents accidental repeated application of a stale preview.
        </p>
        {!isAdmin ? (
          <div className="empty-state">VIEWER can inspect operations but cannot run maintenance.</div>
        ) : (
          <>
            <label>
              Maintenance reason
              <input
                disabled={busy}
                maxLength="500"
                onChange={(event) => {
                  setReason(event.target.value);
                  setPreview(null);
                  setMessage("");
                }}
                value={reason}
              />
            </label>
            <div className="button-row">
              <button
                disabled={busy || loading || reason.trim().length < 10}
                onClick={() => runCleanup(true)}
                type="button"
              >
                {busy ? "Working..." : "Preview cleanup"}
              </button>
              <button
                className="danger-action"
                disabled={busy || loading || !preview?.preview_fingerprint || preview.planned <= 0}
                onClick={() => runCleanup(false)}
                type="button"
              >
                Apply bounded cleanup
              </button>
            </div>
            {preview && (
              <div className="operations-preview">
                <strong>Retention preview</strong>
                {preview.planned > 0 && !preview.preview_fingerprint && (
                  <p role="status">This preview is missing its verification fingerprint. Run Preview again before applying cleanup.</p>
                )}
                <span>Planned: {preview.planned}</span>
                <span>Expired: {preview.eligible_expired}</span>
                <span>Over max rows: {preview.eligible_over_limit}</span>
                <span>Total before: {preview.total_before}</span>
              </div>
            )}
          </>
        )}
        {message && <div className="success-banner" role="status">{message}</div>}
        {error && <div className="error-banner" role="alert">{error}</div>}
      </section>
    </section>
  );
}


function Metric({ label, tone = "", value }) {
  return (
    <div className={"stat-card " + tone}>
      <span>{label}</span>
      <strong>{value ?? "-"}</strong>
    </div>
  );
}


function LatencyRow({ label, stats }) {
  return (
    <tr>
      <td>{label}</td>
      <td>{stats?.samples ?? "-"}</td>
      <td>{formatMs(stats?.avg_ms)}</td>
      <td>{formatMs(stats?.p50_ms)}</td>
      <td>{formatMs(stats?.p95_ms)}</td>
      <td>{formatMs(stats?.p99_ms)}</td>
      <td>{formatMs(stats?.max_ms)}</td>
    </tr>
  );
}


function Row({ label, value }) {
  return (
    <div>
      <dt>{label}</dt>
      <dd>{value ?? "-"}</dd>
    </div>
  );
}


function formatMs(value) {
  if (value === null || value === undefined || value === "") return "-";
  return Number.isFinite(Number(value)) ? Number(value).toFixed(2) + " ms" : "-";
}


function formatNumber(value) {
  if (value === null || value === undefined || value === "") return "-";
  return Number.isFinite(Number(value)) ? Number(value).toFixed(2) : "-";
}


function formatPercent(value) {
  if (value === null || value === undefined || value === "") return "-";
  return Number.isFinite(Number(value)) ? (Number(value) * 100).toFixed(2) + "%" : "-";
}


function formatDate(value) {
  return formatServerTime(value);
}


function formatBytes(value) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return "-";
  if (numeric >= 1000000) return (numeric / 1000000).toFixed(1) + " MB";
  if (numeric >= 1000) return (numeric / 1000).toFixed(1) + " KB";
  return numeric + " B";
}


function formatSeconds(value) {
  if (value === null || value === undefined || value === "") return "-";
  return Number.isFinite(Number(value)) ? Number(value) + " s" : "-";
}


function humanize(value) {
  return String(value || "-")
    .replaceAll("_", " ")
    .replace(/(^|\s)\S/g, (character) => character.toUpperCase());
}


export default Operations;
