import { useRef, useState } from "react";

import { cleanupRuntimeLogs, safeErrorMessage } from "../api/client";
import "./management.css";


function Operations({ isAdmin = false, loading = false, onRefresh, summary }) {
  const [reason, setReason] = useState("Apply bounded runtime log retention maintenance.");
  const [preview, setPreview] = useState(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const cleanupLock = useRef(false);
  const [error, setError] = useState("");

  async function runCleanup(dryRun) {
    if (!isAdmin || loading || cleanupLock.current || reason.trim().length < 10) return;
    if (!dryRun && (!preview || preview.planned <= 0)) return;
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
        setMessage("Retention applied: " + result.deleted + " row(s) removed.");
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
          data. Apply is enabled only after a preview with eligible rows.
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
                disabled={busy || loading || !preview || preview.planned <= 0}
                onClick={() => runCleanup(false)}
                type="button"
              >
                Apply bounded cleanup
              </button>
            </div>
            {preview && (
              <div className="operations-preview">
                <strong>Retention preview</strong>
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
  if (!value) return "-";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
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
