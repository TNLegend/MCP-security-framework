import { formatServerTime } from "../utils/serverTime.js";
import { executionDisplay } from "../utils/runtimePresentation.js";
import SecurityExplanation from "../components/securityexplanation.jsx";
import { useEffect, useMemo, useRef, useState } from "react";

import { fetchRuntimeLogs, fetchRuntimeOperationEvents, fetchRuntimeOperationReconciliation } from "../api/client";

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
  const hasLoadedPage = useRef(false);
  const eventControl = useRef(null);
  const entries = page.items;
  const appliedFilterCount = Object.values(activeFilters).filter((value) => value !== null && value !== undefined && value !== "").length;
  const selectedLog = useMemo(
    () => entries.find((log) => log.id === selectedLogId) || null,
    [entries, selectedLogId],
  );

  useEffect(() => {
    if (!hasLoadedPage.current && cursorStack.length === 1 && Object.keys(activeFilters).length === 0) {
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
      hasLoadedPage.current = true;
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
        <div>
          <h2>Tool activity</h2>
          <p>{page.summary.total} outcome event(s) matching filters. The table also includes recorded authorization intents.</p>
        </div>
        <button type="button" className="secondary-action"
          disabled={pageLoading} onClick={() => loadPage(activeFilters, [null])}>Refresh events</button>
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
          options={["ALLOW", "BLOCK", "WARN", "LOG_ONLY", "ASK_APPROVAL", "LIMIT"]}
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
        <SummaryCard label="Recorded outcomes (not intents)" value={page.summary.total} />
        {page.summary.outcome_states && Object.keys(page.summary.outcome_states).length > 0 ? (
          <>
            <SummaryCard label="Sent, outcome uncertain" value={page.summary.outcome_states.sent_uncertain ?? 0} />
            <SummaryCard label="Response withheld after execution" value={page.summary.outcome_states.response_withheld ?? 0} />
            <SummaryCard label="Execution recorded" value={page.summary.outcome_states.execution_recorded ?? 0} />
            <SummaryCard label="Confirmed not sent" value={page.summary.outcome_states.confirmed_not_sent ?? 0} />
            <SummaryCard label="Legacy or unclassified" value={page.summary.outcome_states.legacy_or_unclassified ?? 0} />
          </>
        ) : (
          <p className="hint-text">Disjoint outcome counts are not available from this backend version. No dispatch state is inferred.</p>
        )}
      </div>
      <p className="hint-text" role="note">
        These five outcome categories do not overlap and add up to recorded outcomes. Authorization intents are separate rows;
        legacy records without dispatch evidence are never counted as confirmed non-execution.
      </p>
      <details>
        <summary>Decision and diagnostic counts (overlapping categories)</summary>
        <div className="summary-grid runtime-summary-grid">
          <SummaryCard label="OPA or Proxy ALLOW" value={page.summary.allowed} />
          <SummaryCard label="OPA or Proxy BLOCK" value={page.summary.blocked} />
          <SummaryCard label="Execution flag recorded" value={page.summary.executed} />
          <SummaryCard label="Skipped or blocked without confirmed execution" value={page.summary.skipped} />
          <SummaryCard label="Error status recorded" value={page.summary.errors} />
        </div>
        <p className="hint-text">These are independent facets, not a partition: for example, an executed tool error can also have an ALLOW decision.</p>
      </details>

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
        <thead><tr><th>Time</th><th>Phase</th><th>Tool</th><th>Decision</th><th>Rule</th><th>Config Rev</th><th>Dispatch evidence</th><th>Execution status</th><th>Severity</th><th>Agent</th><th>Server</th></tr></thead>
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

const EFFECT_SUMMARY_LIMITS = {
  REFERENCE_VALUES_NOT_RECORDED: "Resource values and arguments are not recorded; only identifiers and counts.",
  SCOPE_AUTHORIZATION_DECIDED_BY_OPA: "Listed scopes are configured candidates for the resource type. Whether a scope matched is decided by the policy, see the decision above.",
  EFFECTS_TRUNCATED: "This tool declares more effects than this summary keeps (16).",
  NON_EXPLICIT_REFERENCE_PRESENT: "At least one effect uses a non-explicit (opaque or derived) resource reference.",
  UNRESOLVED_BINDING_PRESENT: "At least one resource binding was not resolved for this call.",
};

// RT-12: restitute every effect the Proxy prepared, never just the first one.
// The data is the Proxy's bounded summary; nothing is inferred in the browser.
export function ToolEffectsSummary({ summary }) {
  const effects = summary && typeof summary === "object" && Array.isArray(summary.effects) ? summary.effects : null;
  if (!effects) return null;
  return (
    <section className="tool-effects-summary" aria-labelledby="tool-effects-heading">
      <h4 id="tool-effects-heading">
        Tool effects requested ({effects.length}{summary.effect_count > effects.length ? ` of ${summary.effect_count}` : ""})
      </h4>
      <div className="table-shell">
        <table>
          <thead>
            <tr><th scope="col">Effect</th><th scope="col">Required capability</th><th scope="col">Resource types</th><th scope="col">Reference precision</th><th scope="col">References</th><th scope="col">Candidate scopes</th></tr>
          </thead>
          <tbody>
            {effects.map((effect) => (
              <tr key={effect.effect_id}>
                <td>{displayValue(effect.effect_id)}</td>
                <td><code>{displayValue(effect.capability)}</code></td>
                <td>{effect.resource_types?.length ? effect.resource_types.join(", ") : "None"}</td>
                <td>{displayValue(effect.reference_precision)}{effect.binding_statuses?.length ? ` (${effect.binding_statuses.join(", ")})` : ""}</td>
                <td>{Number.isInteger(effect.reference_count) ? effect.reference_count : "Unknown"}</td>
                <td>{effect.candidate_scope_ids?.length ? effect.candidate_scope_ids.join(", ") : "None configured"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {Array.isArray(summary.limits) && summary.limits.length > 0 && (
        <ul className="evidence-limits" aria-label="Limits of this summary">
          {summary.limits.map((code) => <li key={code}>{EFFECT_SUMMARY_LIMITS[code] || code}</li>)}
        </ul>
      )}
    </section>
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
      <ToolEffectsSummary summary={log.arguments_summary} />
      <RuntimeReconciliation key={log.operation_id || `legacy-${log.id}`} operationId={log.operation_id} />
      <details className="operator-technical-details">
        <summary>Request, policy and transport records</summary>
      <div className="metadata-grid runtime-metadata-grid">
        <MetadataSection title="Runtime context" items={[["Operation ID", log.operation_id], ["Audit phase", log.event_phase], ["Agent", log.agent_id], ["Session ID", log.session_id], ["Server ID", log.server_id], ["Tool", log.tool_name], ["Argument summary", log.arguments_summary, "structured"], ["Recorded at", formatDate(log.created_at)]]} />
        <MetadataSection title="Policy decision" items={[["Decision", log.decision, "decision"], ["Rule ID", log.rule_id], ["Decision reason", log.decision_reason], ["Severity", log.severity, "severity"], ["Configuration revision", log.control_plane_revision_number], ["Configuration digest", log.control_plane_content_hash]]} />
        <MetadataSection title="Transport and execution" items={[["Client protocol profile", log.client_protocol_profile_id], ["Upstream protocol profile", log.upstream_protocol_profile_id], ["Dispatch evidence", executionDisplay(log)], ["Execution status", log.execution_status, "execution"], ["Result summary", log.result_summary], ["Error summary", log.error_summary]]} />
      </div>
      </details>
    </section>
  );
}

function RuntimeReconciliation({ operationId }) {
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [events, setEvents] = useState(null);

  useEffect(() => {
    setEvents(null);
    setResult(null);
    setError("");
  }, [operationId]);

  if (!operationId) {
    return <p role="note" className="hint-text">Legacy event: no operation ID was recorded.
      Automated reconciliation cannot establish the missing remote outcome.</p>;
  }

  async function examine() {
    setBusy(true);
    setError("");
    setResult(null);
    setEvents(null);
    try {
      const [reconciliation, phases] = await Promise.allSettled([
        fetchRuntimeOperationReconciliation(operationId),
        fetchRuntimeOperationEvents(operationId),
      ]);
      if (reconciliation.status === "fulfilled") {
        setResult(reconciliation.value);
      }
      if (phases.status === "fulfilled" && Array.isArray(phases.value)) {
        setEvents(phases.value);
      }
      if (reconciliation.status === "rejected" || phases.status === "rejected") {
        setError("Some operation evidence could not be loaded. Missing data does not establish non-execution.");
      }
    } catch {
      setError("Reconciliation data is unavailable. Do not assume the remote action did not occur.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="detail-panel" aria-label="MCP operation reconciliation">
      <h4>Execution reconciliation</h4>
      <p>Check whether an authorized intent, dispatch admission and execution outcome were durably recorded.
        This is a read-only check; it never retries the tool call.</p>
      <button type="button" onClick={examine} disabled={busy}>
        {busy ? "Checking..." : "Check operation " + operationId.slice(0, 8)}
      </button>
      {error && <p role="alert">{error}</p>}
      {events && <div aria-label="Recorded phases for this operation">
        <h5>Recorded intent and outcome</h5>
        {events.length === 0
          ? <p>No phases are currently recorded under this operation ID.
            Do not conclude that the upstream tool did not run.</p>
          : <ol>{events.map((event) => <li key={event.id}>
              <strong>{event.event_phase === "intent" ? "Authorization intent" :
                event.event_phase === "outcome" ? "Execution outcome" : "Legacy or unclassified event"}</strong>
              {" · "}{formatDate(event.created_at)}
              {" · "}Decision {event.decision || "not recorded"}
              {" · "}{event.execution_status || "status not recorded"}
              {" · "}Dispatch {event.dispatch_state || "unverified"}
              {event.rule_id && <>{" · "}Rule <code>{event.rule_id}</code></>}
            </li>)}</ol>}
        {!events.some((event) => event.event_phase === "outcome") && <p role="note">
          No recorded outcome was found. This does not prove that the tool was not executed.
        </p>}
      </div>}
      {result && <div role="status">
        <p><strong>Reconciliation:</strong> {result.state}</p>
        <p>Intent recorded: {result.intent_recorded ? "Yes" : "No"}.
          Dispatch admitted: {result.admission_recorded ? "Yes" : "No"}.
          Outcome recorded: {result.outcome_recorded ? "Yes" : "No"}.</p>
        <p><strong>Effect possible:</strong> {result.effect_possible ? "Yes" : "Not established"}.
          <strong> Manual investigation:</strong> {result.manual_reconciliation_required ? "Required" : "Not required by the recorded state"}.</p>
        {result.retry_unsafe && <p><strong>Do not retry automatically.</strong>
          Review the MCP server's own audit trail before attempting a new action.</p>}
      </div>}
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

export function getExecutionBadgeClass(status) {
  const normalized = String(status || "").toLowerCase();
  if (normalized === "success") return "badge-success";
  // A withheld response is an enforced security block, not an ordinary
  // grey/inconclusive execution. Do not mistake an uncertain upstream
  // outcome for confirmed non-execution or a safe automatic retry.
  if (normalized === "result_blocked" || normalized === "blocked"
      || normalized === "policy_blocked") return "badge-block badge-danger";
  if (normalized === "authorized_pending_execution"
      || normalized === "upstream_outcome_unknown"
      || normalized === "audit_completion_failed") return "badge-warn badge-warning";
  if (ERROR_STATUSES.has(normalized)) return "badge-danger";
  if (!normalized || normalized === "unknown") return "badge-unknown";
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
