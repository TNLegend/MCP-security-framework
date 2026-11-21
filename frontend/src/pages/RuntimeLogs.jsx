import { formatServerTime } from "../utils/serverTime.js";
import { executionDisplay } from "../utils/runtimePresentation.js";
import SecurityExplanation from "../components/securityexplanation.jsx";
import { useEffect, useMemo, useRef, useState } from "react";

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

  const requestGeneration = useRef(0);
  const detailHeading = useRef(null);
  const eventControl = useRef(null);
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
    return () => { requestGeneration.current += 1; };
  }, []);

  useEffect(() => {
    if (selectedLogId !== null && !entries.some((log) => log.id === selectedLogId)) {
      setSelectedLogId(null);
    }
  }, [entries, selectedLogId]);

  async function loadPage(filters, cursors) {
    const cursor = cursors[cursors.length - 1];
    const generation = ++requestGeneration.current;
    setPageLoading(true);
    setError("");
    try {
      const result = await fetchRuntimeLogs({ ...filters, limit: PAGE_SIZE, cursor });
      if (generation !== requestGeneration.current) return;
      setPage(normalizePage(result));
      setActiveFilters(filters);
      setCursorStack(cursors);
    } catch (err) {
      if (generation === requestGeneration.current) {
        setError(err.message || "Runtime logs could not be loaded.");
      }
    } finally {
      if (generation === requestGeneration.current) setPageLoading(false);
    }
  }

  async function applyFilters(event) {
    event.preventDefault();
    const filters = normalizedFilters(draftFilters);
    if (filters.from && filters.to && filters.from > filters.to) {
      setError("The end date must be on or after the start date.");
      return;
    }
    await loadPage(filters, [null]);
  }

  async function clearFilters() {
    setDraftFilters(EMPTY_FILTERS);
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

  function openEvent(event, id) {
    eventControl.current = event.currentTarget;
    setSelectedLogId(id);
    window.requestAnimationFrame(() => detailHeading.current?.focus());
  }

  function closeEvent() {
    setSelectedLogId(null);
    eventControl.current?.focus();
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
    <section className="page-section activity-page">
      <div className="section-heading">
        <h2>Tool activity</h2>
        <p>{page.summary.total} outcome event(s) matching filters; pending intent events are listed separately.</p>
      </div>
      {error && <div className="error-banner" role="alert">{error} Previous results are retained when available.</div>}
      <p className="hint-text" role="note">
        The summary counts exclude pending audit intents. The table includes them for traceability.
        A policy ALLOW does not establish successful dispatch. Never replay an uncertain result without reconciliation.
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
        <SummaryCard label="Outcome events" value={page.summary.total} />
        <SummaryCard label="Allowed" value={page.summary.allowed} />
        <SummaryCard label="Blocked" value={page.summary.blocked} />
        <SummaryCard label="Executed" value={page.summary.executed} />
        <SummaryCard label="Skipped" value={page.summary.skipped} />
        <SummaryCard label="Errors" value={page.summary.errors} />
      </div>

      <div className="runtime-layout investigation-layout">
        <div className="runtime-section">
          <div className="section-heading compact-heading">
            <h3>Runtime Events</h3>
            <p>Page {cursorStack.length} · {entries.length} row(s)</p>
          </div>
          <div aria-busy={pageLoading}>
            {pageLoading && <p role="status" className="hint-text">Loading runtime calls...</p>}
            {(!pageLoading || entries.length > 0) && (
              <RuntimeLogsTable logs={entries} selectedLogId={selectedLogId} onSelectLog={openEvent} />
            )}
          </div>
          <div className="pagination-bar">
            <button disabled={pageLoading || cursorStack.length <= 1} onClick={previousPage} type="button">Previous</button>
            <span>Page {cursorStack.length}</span>
            <button disabled={pageLoading || !page.has_more || !page.next_cursor} onClick={nextPage} type="button">Next</button>
          </div>
        </div>
        {selectedLog && <RuntimeLogDetailPanel log={selectedLog} detailHeading={detailHeading} onClose={closeEvent} />}
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
    <div aria-label="Runtime events table" className="table-shell runtime-table" tabIndex={0}>
      <table>
        <thead><tr><th>Time</th><th>Phase</th><th>Tool</th><th>Decision</th><th>Rule</th><th>Config Rev</th><th>Executed</th><th>Execution Status</th><th>Severity</th><th>Agent</th><th>Server</th></tr></thead>
        <tbody>
          {logs.map((log) => (
            <tr className={(log.id === selectedLogId ? "selected-row " : "") + "selectable-record"} key={log.id}
              onClick={(event) => { if (!event.target.closest("button")) event.currentTarget.querySelector("button")?.click(); }}>
              <td>{formatDate(log.created_at)}</td>
              <td>{log.event_phase || "Legacy event"}</td>
              <td><button aria-pressed={log.id === selectedLogId} className="record-link" onClick={(event) => onSelectLog(event, log.id)} type="button">
                {displayValue(log.tool_name)}<span className="record-link-context"> · #{displayValue(log.id)}</span>
              </button></td>
              <td><Badge value={log.decision} className={getDecisionBadgeClass(log.decision)} /></td>
              <td>{displayValue(log.rule_id)}</td>
              <td>{displayValue(log.control_plane_revision_number)}</td>
              <td>{executionDisplay(log)}</td>
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

function RuntimeLogDetailPanel({ log, detailHeading, onClose }) {
  return (
    <section className="detail-panel investigation-detail" aria-labelledby="runtime-event-heading">
      <div className="section-heading compact-heading">
        <h3 id="runtime-event-heading" ref={detailHeading} tabIndex={-1}>Runtime call #{displayValue(log.id)}</h3>
        <button onClick={onClose} type="button">Close details</button>
      </div>
      <SecurityExplanation record={log} />
      <div className="metadata-grid runtime-metadata-grid">
        <MetadataSection title="Runtime context" items={[["Operation ID", log.operation_id], ["Audit phase", log.event_phase], ["Agent", log.agent_id], ["Session ID", log.session_id], ["Server ID", log.server_id], ["Tool", log.tool_name], ["Argument summary", log.arguments_summary, "structured"], ["created_at", formatDate(log.created_at)]]} />
        <MetadataSection title="Policy decision" items={[["Decision", log.decision, "decision"], ["Rule ID", log.rule_id], ["Decision reason", log.decision_reason], ["Severity", log.severity, "severity"], ["Configuration revision", log.control_plane_revision_number], ["control_plane_content_hash", log.control_plane_content_hash]]} />
        <MetadataSection title="Transport and execution" items={[["Client protocol profile", log.client_protocol_profile_id], ["Upstream protocol profile", log.upstream_protocol_profile_id], ["Executed", executionDisplay(log)], ["Execution status", log.execution_status, "execution"], ["Result summary", log.result_summary], ["Error summary", log.error_summary]]} />
      </div>
    </section>
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
  return formatServerTime(value);
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


export default RuntimeLogs;
