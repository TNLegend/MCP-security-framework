import { useEffect, useMemo, useState } from "react";

import { fetchRuntimeLogs } from "../api/client";

const PAGE_SIZE = 20;
const ERROR_STATUSES = new Set([
  "tool_error",
  "protocol_error",
  "http_error",
  "upstream_outcome_unknown",
  "policy_error",
  "inventory_error",
]);
const EMPTY_PAGE = {
  items: [],
  next_cursor: null,
  has_more: false,
  summary: { total: 0, allowed: 0, blocked: 0, executed: 0, skipped: 0, errors: 0 },
};
const EMPTY_FILTERS = {
  decision: "",
  server_id: "",
  tool_name: "",
  agent_id: "",
  protocol_profile_id: "",
  from: "",
  to: "",
  search: "",
};

function RuntimeLogs({ initialPage = EMPTY_PAGE, loading = false }) {
  const [page, setPage] = useState(normalizePage(initialPage));
  const [draftFilters, setDraftFilters] = useState(EMPTY_FILTERS);
  const [activeFilters, setActiveFilters] = useState({});
  const [cursorStack, setCursorStack] = useState([null]);
  const [pageLoading, setPageLoading] = useState(false);
  const [error, setError] = useState("");
  const [selectedLogId, setSelectedLogId] = useState(null);

  const entries = page.items;
  const appliedFilterCount = Object.values(activeFilters).filter((value) => value !== null && value !== undefined && value !== "").length;
  const selectedLog = useMemo(
    () => entries.find((log) => log.id === selectedLogId) || null,
    [entries, selectedLogId],
  );

  useEffect(() => {
    if (cursorStack.length === 1 && Object.keys(activeFilters).length === 0) {
      setPage(normalizePage(initialPage));
    }
  }, [initialPage]);

  useEffect(() => {
    void loadPage({}, [null]);
  }, []);

  useEffect(() => {
    if (entries.length === 0) {
      setSelectedLogId(null);
      return;
    }
    if (!entries.some((log) => log.id === selectedLogId)) {
      setSelectedLogId(entries[0].id);
    }
  }, [entries, selectedLogId]);

  async function loadPage(filters, cursors) {
    const cursor = cursors[cursors.length - 1];
    setPageLoading(true);
    setError("");
    try {
      const result = await fetchRuntimeLogs({ ...filters, limit: PAGE_SIZE, cursor });
      setPage(normalizePage(result));
      setCursorStack(cursors);
    } catch (err) {
      setError(err.message || "Runtime logs could not be loaded.");
    } finally {
      setPageLoading(false);
    }
  }

  async function applyFilters(event) {
    event.preventDefault();
    const filters = normalizedFilters(draftFilters);
    setActiveFilters(filters);
    await loadPage(filters, [null]);
  }

  async function clearFilters() {
    setDraftFilters(EMPTY_FILTERS);
    setActiveFilters({});
    await loadPage({}, [null]);
  }

  async function nextPage() {
    if (!page.next_cursor || pageLoading) return;
    await loadPage(activeFilters, [...cursorStack, page.next_cursor]);
  }

  async function previousPage() {
    if (cursorStack.length <= 1 || pageLoading) return;
    await loadPage(activeFilters, cursorStack.slice(0, -1));
  }

  if (loading && page.items.length === 0 && !pageLoading) {
    return (
      <section className="page-section">
        <div className="section-heading">
          <h2>Tool activity</h2>
          <p>Loading runtime calls...</p>
        </div>
      </section>
    );
  }

  return (
    <section className="page-section">
      <div className="section-heading">
        <h2>Tool activity</h2>
        <p>{page.summary.total} matching event(s)</p>
      </div>
      {error && <div className="error-banner">{error}</div>}
      <p className="hint-text" role="note">
        Allowed calls are not always completed calls. Do not automatically retry an unknown result.
      </p>

      {appliedFilterCount > 0 && (
        <p className="hint-text" role="status">
          {appliedFilterCount} filter(s) applied to the results below. Use Clear to reset all filters, including the advanced ones.
        </p>
      )}
      <form className="filter-bar runtime-filter-bar" onSubmit={applyFilters}>
        <FilterSelect
          label="Decision"
          name="decision"
          options={["ALLOW", "BLOCK"]}
          setFilters={setDraftFilters}
          value={draftFilters.decision}
        />
        <FilterInput label="Tool" name="tool_name" setFilters={setDraftFilters} value={draftFilters.tool_name} />
        <FilterInput className="runtime-search-field" label="Search" name="search" setFilters={setDraftFilters} value={draftFilters.search} />
        <details className="runtime-advanced-filters">
          <summary>Advanced filters: server, agent, protocol and time range</summary>
          <div className="runtime-advanced-fields">
            <FilterInput label="Server ID" name="server_id" setFilters={setDraftFilters} type="number" value={draftFilters.server_id} />
            <FilterInput label="Agent" name="agent_id" setFilters={setDraftFilters} value={draftFilters.agent_id} />
            <FilterInput label="Protocol profile" name="protocol_profile_id" setFilters={setDraftFilters} value={draftFilters.protocol_profile_id} />
            <FilterInput label="From" name="from" setFilters={setDraftFilters} type="datetime-local" value={draftFilters.from} />
            <FilterInput label="To" name="to" setFilters={setDraftFilters} type="datetime-local" value={draftFilters.to} />
          </div>
        </details>
        <div className="button-row runtime-filter-actions">
          <button disabled={pageLoading} type="submit">Apply</button>
          <button disabled={pageLoading} onClick={clearFilters} type="button">Clear</button>
        </div>
      </form>

      <div className="summary-grid runtime-summary-grid">
        <SummaryCard label="Matching" value={page.summary.total} />
        <SummaryCard label="Allowed" value={page.summary.allowed} />
        <SummaryCard label="Blocked" value={page.summary.blocked} />
        <SummaryCard label="Executed" value={page.summary.executed} />
        <SummaryCard label="Skipped" value={page.summary.skipped} />
        <SummaryCard label="Errors" value={page.summary.errors} />
      </div>

      <div className="runtime-layout">
        <div className="runtime-section">
          <div className="section-heading compact-heading">
            <h3>Runtime Events</h3>
            <p>Page {cursorStack.length} · {entries.length} row(s)</p>
          </div>
          {pageLoading ? (
            <div className="empty-state">Loading runtime calls...</div>
          ) : (
            <RuntimeLogsTable logs={entries} selectedLogId={selectedLogId} onSelectLog={setSelectedLogId} />
          )}
          <div className="pagination-bar">
            <button disabled={pageLoading || cursorStack.length <= 1} onClick={previousPage} type="button">Previous</button>
            <span>Page {cursorStack.length}</span>
            <button disabled={pageLoading || !page.has_more || !page.next_cursor} onClick={nextPage} type="button">Next</button>
          </div>
        </div>
        {selectedLog ? <RuntimeLogDetailPanel log={selectedLog} /> : null}
      </div>
    </section>
  );
}

function FilterInput({ className = "", label, name, setFilters, type = "text", value }) {
  return (
    <label className={className}>
      {label}
      <input
        maxLength={type === "text" ? 255 : undefined}
        min={type === "number" ? 1 : undefined}
        onChange={(event) => updateFilter(setFilters, name, event.target.value)}
        type={type}
        value={value}
      />
    </label>
  );
}

function FilterSelect({ label, name, options, setFilters, value }) {
  return (
    <label>
      {label}
      <select onChange={(event) => updateFilter(setFilters, name, event.target.value)} value={value}>
        <option value="">All</option>
        {options.map((option) => <option key={option} value={option}>{option}</option>)}
      </select>
    </label>
  );
}

function SummaryCard({ label, value }) {
  return <div className="summary-card"><span>{label}</span><strong>{value}</strong></div>;
}

function RuntimeLogsTable({ logs, selectedLogId, onSelectLog }) {
  if (logs.length === 0) return <div className="empty-state">No runtime calls match the current filters.</div>;
  return (
    <div className="table-shell runtime-table">
      <table>
        <thead><tr><th>Time</th><th>Tool</th><th>Decision</th><th>Rule</th><th>Config Rev</th><th>Executed</th><th>Execution Status</th><th>Severity</th><th>Agent</th><th>Server</th></tr></thead>
        <tbody>
          {logs.map((log) => (
            <tr
              className={log.id === selectedLogId ? "selected-row" : ""}
              key={log.id}
              onClick={() => onSelectLog(log.id)}
              onKeyDown={(event) => {
                if (event.key === "Enter" || event.key === " ") {
                  event.preventDefault();
                  onSelectLog(log.id);
                }
              }}
              role="button"
              tabIndex="0"
            >
              <td>{formatDate(log.created_at)}</td>
              <td>{displayValue(log.tool_name)}</td>
              <td><Badge value={log.decision} className={getDecisionBadgeClass(log.decision)} /></td>
              <td>{displayValue(log.rule_id)}</td>
              <td>{displayValue(log.control_plane_revision_number)}</td>
              <td>{formatBoolean(log.executed)}</td>
              <td><Badge value={log.execution_status} className={getExecutionBadgeClass(log.execution_status)} /></td>
              <td><Badge value={log.severity} className={getSeverityBadgeClass(log.severity)} /></td>
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
      <h3>Runtime call #{displayValue(log.id)}</h3>
      <div className="metadata-grid runtime-metadata-grid">
        <MetadataSection title="Runtime context" items={[["agent_id", log.agent_id], ["session_id", log.session_id], ["server_id", log.server_id], ["tool_name", log.tool_name], ["arguments_summary", log.arguments_summary, "structured"], ["created_at", formatDate(log.created_at)]]} />
        <MetadataSection title="Policy decision" items={[["decision", log.decision, "decision"], ["rule_id", log.rule_id], ["decision_reason", log.decision_reason], ["severity", log.severity, "severity"], ["control_plane_revision_number", log.control_plane_revision_number], ["control_plane_content_hash", shorten(log.control_plane_content_hash)]]} />
        <MetadataSection title="Transport and execution" items={[["client_protocol_profile_id", log.client_protocol_profile_id], ["upstream_protocol_profile_id", log.upstream_protocol_profile_id], ["executed", log.execution_status === "upstream_outcome_unknown" ? "Unknown — upstream effect possible" : formatBoolean(log.executed)], ["execution_status", log.execution_status, "execution"], ["result_summary", log.result_summary], ["error_summary", log.error_summary]]} />
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
              {type === "decision" ? <Badge value={value} className={getDecisionBadgeClass(value)} />
                : type === "execution" ? <Badge value={value} className={getExecutionBadgeClass(value)} />
                  : type === "severity" ? <Badge value={value} className={getSeverityBadgeClass(value)} />
                    : type === "structured" ? <pre className="json-block">{formatStructuredValue(value)}</pre>
                      : displayValue(value)}
            </dd>
          </div>
        ))}
      </dl>
    </section>
  );
}

function Badge({ value, className }) {
  return <span className={`badge ${className}`}>{displayValue(value)}</span>;
}

function updateFilter(setter, name, value) {
  setter((current) => ({ ...current, [name]: value }));
}

function normalizedFilters(filters) {
  const normalized = {};
  Object.entries(filters).forEach(([key, value]) => {
    const trimmed = typeof value === "string" ? value.trim() : value;
    if (!trimmed) return;
    normalized[key] = key === "from" || key === "to" ? new Date(trimmed).toISOString() : trimmed;
  });
  return normalized;
}

function normalizePage(value) {
  if (!value || !Array.isArray(value.items)) return EMPTY_PAGE;
  return {
    items: value.items,
    next_cursor: value.next_cursor || null,
    has_more: value.has_more === true,
    summary: { ...EMPTY_PAGE.summary, ...(value.summary || {}) },
  };
}

function displayValue(value) {
  return value === null || value === undefined || value === "" ? "-" : String(value);
}

function formatDate(value) {
  if (!value) return "-";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
}

function formatBoolean(value) {
  return value === true ? "Yes" : value === false ? "No" : "-";
}

function formatStructuredValue(value) {
  if (value === null || value === undefined || value === "") return "-";
  if (typeof value === "string") {
    try { return JSON.stringify(JSON.parse(value), null, 2); } catch { return value; }
  }
  return JSON.stringify(value, null, 2);
}

function getDecisionBadgeClass(decision) {
  const normalized = String(decision || "").toUpperCase();
  if (normalized === "ALLOW") return "badge-allow badge-success";
  if (normalized === "BLOCK") return "badge-block badge-danger";
  if (normalized === "WARN" || normalized === "ASK_APPROVAL") return "badge-warning";
  return "badge-muted";
}

function getExecutionBadgeClass(status) {
  const normalized = String(status || "").toLowerCase();
  if (normalized === "success") return "badge-success";
  if (ERROR_STATUSES.has(normalized)) return "badge-danger";
  return "badge-muted";
}

function getSeverityBadgeClass(severity) {
  const normalized = String(severity || "").toLowerCase();
  if (normalized === "low") return "badge-low";
  if (normalized === "medium") return "badge-warning";
  if (normalized === "high" || normalized === "critical") return "badge-danger";
  return "badge-muted";
}

function shorten(value) {
  return value ? `${String(value).slice(0, 12)}...${String(value).slice(-8)}` : value;
}

export default RuntimeLogs;
