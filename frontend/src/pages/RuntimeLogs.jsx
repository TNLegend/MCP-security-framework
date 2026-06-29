import { useEffect, useMemo, useState } from "react";

const ERROR_STATUSES = new Set([
  "tool_error",
  "protocol_error",
  "http_error",
  "policy_error",
  "inventory_error",
]);

function RuntimeLogs({ logs = [], runtimeLogs, loading = false }) {
  const entries = Array.isArray(runtimeLogs) ? runtimeLogs : logs;
  const [selectedLogId, setSelectedLogId] = useState(null);

  const sortedLogs = useMemo(
    () =>
      [...entries].sort((left, right) => {
        const timeDelta = getTimestamp(right.created_at) - getTimestamp(left.created_at);
        if (timeDelta !== 0) {
          return timeDelta;
        }
        return Number(right.id || 0) - Number(left.id || 0);
      }),
    [entries],
  );

  const selectedLog = useMemo(
    () => sortedLogs.find((log) => log.id === selectedLogId) || null,
    [selectedLogId, sortedLogs],
  );

  const summary = useMemo(
    () => ({
      total: entries.length,
      allowed: entries.filter((log) => log.decision === "ALLOW").length,
      blocked: entries.filter((log) => log.decision === "BLOCK").length,
      executed: entries.filter((log) => log.executed === true).length,
      skipped: entries.filter(
        (log) => log.executed === false || log.execution_status === "skipped",
      ).length,
      errors: entries.filter((log) => ERROR_STATUSES.has(log.execution_status)).length,
    }),
    [entries],
  );

  useEffect(() => {
    if (sortedLogs.length === 0) {
      setSelectedLogId(null);
      return;
    }

    const selectedStillExists = sortedLogs.some((log) => log.id === selectedLogId);
    if (!selectedStillExists) {
      setSelectedLogId(sortedLogs[0].id);
    }
  }, [selectedLogId, sortedLogs]);

  if (loading) {
    return (
      <section className="page-section">
        <div className="section-heading">
          <h2>Runtime Logs</h2>
          <p>Loading runtime logs...</p>
        </div>
      </section>
    );
  }

  return (
    <section className="page-section">
      <div className="section-heading">
        <h2>Runtime Logs</h2>
        <p>{entries.length} log(s)</p>
      </div>

      <div className="summary-grid runtime-summary-grid">
        <SummaryCard label="Total Logs" value={summary.total} />
        <SummaryCard label="Allowed" value={summary.allowed} />
        <SummaryCard label="Blocked" value={summary.blocked} />
        <SummaryCard label="Executed" value={summary.executed} />
        <SummaryCard label="Skipped" value={summary.skipped} />
        <SummaryCard label="Errors" value={summary.errors} />
      </div>

      <div className="runtime-layout">
        <div className="runtime-section">
          <div className="section-heading compact-heading">
            <h3>Runtime Events</h3>
            <p>Policy decisions and execution proof</p>
          </div>
          <RuntimeLogsTable
            logs={sortedLogs}
            selectedLogId={selectedLogId}
            onSelectLog={setSelectedLogId}
          />
        </div>

        {selectedLog ? (
          <RuntimeLogDetailPanel log={selectedLog} />
        ) : sortedLogs.length > 0 ? (
          <EmptyState />
        ) : null}
      </div>
    </section>
  );
}

function SummaryCard({ label, value }) {
  return (
    <div className="summary-card">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function RuntimeLogsTable({ logs, selectedLogId, onSelectLog }) {
  if (logs.length === 0) {
    return <EmptyState />;
  }

  return (
    <div className="table-shell runtime-table">
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Tool</th>
            <th>Decision</th>
            <th>Rule</th>
            <th>Executed</th>
            <th>Execution Status</th>
            <th>Severity</th>
            <th>Agent</th>
            <th>Server</th>
          </tr>
        </thead>
        <tbody>
          {logs.map((log) => (
            <tr
              className={log.id === selectedLogId ? "selected-row" : ""}
              key={log.id}
              onClick={() => onSelectLog(log.id)}
              onKeyDown={(event) => {
                if (event.key === "Enter") {
                  onSelectLog(log.id);
                }
              }}
              role="button"
              tabIndex="0"
            >
              <td>{formatDate(log.created_at)}</td>
              <td>{displayValue(log.tool_name)}</td>
              <td>
                <Badge value={log.decision} className={getDecisionBadgeClass(log.decision)} />
              </td>
              <td>{displayValue(log.rule_id)}</td>
              <td>{formatBoolean(log.executed)}</td>
              <td>
                <Badge
                  value={log.execution_status}
                  className={getExecutionBadgeClass(log.execution_status)}
                />
              </td>
              <td>
                <Badge value={log.severity} className={getSeverityBadgeClass(log.severity)} />
              </td>
              <td>{displayValue(log.agent_id)}</td>
              <td>{displayValue(log.server_id)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function RuntimeLogDetailPanel({ log }) {
  return (
    <div className="detail-panel">
      <h3>Runtime log #{displayValue(log.id)}</h3>
      <div className="metadata-grid runtime-metadata-grid">
        <MetadataSection
          title="Runtime context"
          items={[
            ["id", log.id],
            ["agent_id", log.agent_id],
            ["session_id", log.session_id],
            ["server_id", log.server_id],
            ["tool_name", log.tool_name],
            ["arguments_summary", log.arguments_summary, "structured"],
            ["status", log.status],
            ["created_at", formatDate(log.created_at)],
          ]}
        />
        <MetadataSection
          title="Policy decision"
          items={[
            ["decision", log.decision, "decision"],
            ["rule_id", log.rule_id],
            ["decision_reason", log.decision_reason],
            ["severity", log.severity, "severity"],
          ]}
        />
        <MetadataSection
          title="Execution result"
          items={[
            ["executed", formatBoolean(log.executed)],
            ["execution_status", log.execution_status, "execution"],
            ["result_summary", log.result_summary],
            ["error_summary", log.error_summary],
          ]}
        />
      </div>
    </div>
  );
}

function MetadataSection({ title, items }) {
  return (
    <section className="metadata-section">
      <h4>{title}</h4>
      <dl>
        {items.map(([label, value, type]) => (
          <div className="metadata-row" key={label}>
            <dt>{label}</dt>
            <dd>
              {type === "decision" ? (
                <Badge value={value} className={getDecisionBadgeClass(value)} />
              ) : type === "execution" ? (
                <Badge value={value} className={getExecutionBadgeClass(value)} />
              ) : type === "severity" ? (
                <Badge value={value} className={getSeverityBadgeClass(value)} />
              ) : type === "structured" ? (
                <pre className="json-block">{formatStructuredValue(value)}</pre>
              ) : (
                displayValue(value)
              )}
            </dd>
          </div>
        ))}
      </dl>
    </section>
  );
}

function EmptyState() {
  return (
    <div className="empty-state">
      No runtime logs yet. Run the proxy demo to generate ALLOW/BLOCK events.
    </div>
  );
}

function Badge({ value, className }) {
  return <span className={`badge ${className}`}>{displayValue(value)}</span>;
}

function displayValue(value) {
  if (value === null || value === undefined || value === "") {
    return "\u2014";
  }
  return String(value);
}

function formatDate(value) {
  if (!value) {
    return "\u2014";
  }

  try {
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) {
      return String(value);
    }
    return date.toLocaleString();
  } catch {
    return String(value);
  }
}

function formatBoolean(value) {
  if (value === true) {
    return "Yes";
  }

  if (value === false) {
    return "No";
  }

  return "\u2014";
}

function formatStructuredValue(value) {
  if (value === null || value === undefined || value === "") {
    return "\u2014";
  }

  if (typeof value === "string") {
    try {
      return JSON.stringify(JSON.parse(value), null, 2);
    } catch {
      return value;
    }
  }

  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

function getDecisionBadgeClass(decision) {
  const normalized = String(decision || "").toUpperCase();

  if (normalized === "ALLOW") {
    return "badge-allow badge-success";
  }

  if (normalized === "BLOCK") {
    return "badge-block badge-danger";
  }

  if (normalized === "WARN" || normalized === "ASK_APPROVAL") {
    return "badge-warn badge-warning";
  }

  if (normalized === "LOG_ONLY") {
    return "badge-muted";
  }

  return "badge-muted";
}

function getExecutionBadgeClass(status) {
  const normalized = String(status || "").toLowerCase();

  if (normalized === "success") {
    return "badge-success";
  }

  if (normalized === "skipped") {
    return "badge-muted";
  }

  if (ERROR_STATUSES.has(normalized)) {
    return "badge-danger";
  }

  return "badge-muted";
}

function getSeverityBadgeClass(severity) {
  const normalized = String(severity || "").toLowerCase();

  if (normalized === "low") {
    return "badge-low";
  }

  if (normalized === "medium") {
    return "badge-warning";
  }

  if (normalized === "high" || normalized === "critical") {
    return "badge-danger";
  }

  return "badge-muted";
}

function getTimestamp(value) {
  const timestamp = Date.parse(value || "");
  return Number.isNaN(timestamp) ? 0 : timestamp;
}

export default RuntimeLogs;
