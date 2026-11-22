import { formatServerTime } from "../utils/serverTime.js";
import { toolInQueue } from "../utils/toolQueues.js";

function StatCard({ label, value, tone = "" }) {
  return (
    <div className={`stat-card ${tone}`}>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function Dashboard({
  activeRevision,
  auditEvents = [],
  emergencyDenies = [],
  health,
  isAdmin,
  runtimeStatus,
  servers,
  tools,
  runtimeLogs,
  runtimeSummary,
  dashboardRefreshedAt,
  loading,
  readStates = {},
  readTimestamps = {},
  onNavigate,
}) {
  const approvedTools = tools.filter(
    (tool) =>
      ["APPROVED", "ADMIN_ALLOWED"].includes(tool.analysis_status) &&
      tool.approved_fingerprint_match,
  );
  // UX-04: the same queue predicates as the Security review filter, so each
  // Home count equals the list it opens.
  const reviewTools = tools.filter((tool) => toolInQueue(tool, "REVIEW"));
  const blockedTools = tools.filter((tool) => toolInQueue(tool, "BLOCKED"));
  // EM-01: the backend state is authoritative (a revoked deny is not active).
  const activeDenies = emergencyDenies.filter((deny) => deny.state === "ACTIVE");
  // A pre-execution audit intent and its completion are two events, but
  // one logical tool call. Keep intents in logs; exclude them from KPIs.
  // Runtime summary is aggregated server-side over all retained outcome
  // events, not over the first 20 table rows loaded for convenience.
  const recordedAllows = runtimeSummary?.allowed;
  const recordedBlocks = runtimeSummary?.blocked;
  // Disjoint outcome buckets from the same server query; never derived here.
  const outcomeStates = runtimeSummary?.outcome_states || null;
  const uncertainOutcomes = outcomeStates ? outcomeStates.sent_uncertain ?? 0 : null;
  const executionRecorded = outcomeStates ? outcomeStates.execution_recorded ?? 0 : null;

  function count(source, value) {
    return readStates[source] === "ready" ? value : "—";
  }

  function unavailableMessage(source) {
    return readStates[source] === "unavailable" ? "The latest data is unavailable." : null;
  }

  function readAt(source) {
    if (readStates[source] !== "ready" || !readTimestamps[source]) return "not yet read";
    return "read " + formatDate(readTimestamps[source]);
  }

  function lastResponse(source) {
    // This is the local *receipt time* of an independently completed API read,
    // never the source collection time, proof of current AWS state, or a stale
    // response being silently relabeled as a successful new check.
    if (readStates[source] !== "ready" || !readTimestamps[source]) return null;
    return "Response received: " + formatDate(readTimestamps[source]);
  }

  return (
    <section className="page-section">
      <div className="section-heading">
        <h2>Security overview</h2>
        <p aria-live="polite">{loading ? "Refreshing security information…" : "Review tool risks and recorded decisions."}
          {dashboardRefreshedAt ? " Last attempted refresh: " + formatDate(dashboardRefreshedAt) + "." : " No refresh timestamp recorded."}
        </p>
      </div>

      {isAdmin && (
        <div className="dashboard-actions" aria-label="Quick actions">
          <button className="console-primary" type="button" onClick={() => onNavigate("inventory")}>Add MCP server</button>
          <button className="secondary-action" type="button" onClick={() => onNavigate("analysis")}>Review tools</button>
          <button className="secondary-action" type="button" onClick={() => onNavigate("emergency")}>Emergency block</button>
          <button className="secondary-action" type="button" onClick={() => onNavigate("users")}>Manage users</button>
        </div>
      )}

      <section className="dashboard-priority" aria-label="What needs attention">
        <div className="section-heading compact-heading">
          <h3>Needs attention</h3>
          <p>Actions based on the latest recorded results</p>
        </div>
        <div className="dashboard-priority-grid">
          <article className="dashboard-priority-card" data-tone="attention" data-queue="REVIEW">
            <span>Tools to review</span>
            <strong>{count("tools", reviewTools.length)}</strong>
            <p>{unavailableMessage("tools") || "Pending, stale, quarantined or failed analyses awaiting review."}</p>
            <small className="priority-population">Current inventory · {readAt("tools")}</small>
            <button type="button" className="secondary-action" onClick={() => onNavigate("analysis", null, { queue: "REVIEW" })}>
              Open review queue
            </button>
          </article>
          <article className="dashboard-priority-card" data-tone="restricted" data-queue="BLOCKED">
            <span>Tools marked blocked</span>
            <strong>{count("tools", blockedTools.length)}</strong>
            <p>{unavailableMessage("tools") || "Each has a recorded block decision with its reason."}</p>
            <small className="priority-population">Current inventory · {readAt("tools")}</small>
            <button type="button" className="secondary-action" onClick={() => onNavigate("analysis", null, { queue: "BLOCKED" })}>
              Open blocked tools
            </button>
          </article>
          <article className="dashboard-priority-card" data-tone="attention" data-queue="sent_uncertain">
            <span>Outcome uncertain after send</span>
            <strong>{count("runtimeLogs", uncertainOutcomes ?? "—")}</strong>
            <p>{unavailableMessage("runtimeLogs") || (outcomeStates
              ? "Sent to the MCP server, result not confirmed. Reconcile before any retry."
              : "This backend does not report outcome states; nothing is inferred.")}</p>
            <small className="priority-population">All retained outcome events · {readAt("runtimeLogs")}</small>
            <button type="button" className="secondary-action" disabled={!outcomeStates}
              onClick={() => onNavigate("runtime", null, { outcome: "sent_uncertain" })}>
              Review uncertain outcomes
            </button>
          </article>
          <article className="dashboard-priority-card" data-tone="neutral">
            <span>Active emergency restrictions</span>
            <strong>{count("emergencyDenies", activeDenies.length)}</strong>
            <p>{unavailableMessage("emergencyDenies") || "Restrictions currently in effect."}</p>
            <small className="priority-population">Server-computed state · {readAt("emergencyDenies")}</small>
            <button type="button" className="secondary-action" onClick={() => onNavigate("emergency")}>
              See restrictions
            </button>
          </article>
        </div>
      </section>

      <div className="section-heading dashboard-status-heading">
        <h3 className="dashboard-section-heading">Service status</h3>
        <button className="secondary-action" type="button" onClick={() => onNavigate("operations")}>Open system health</button>
      </div>
      <div className="status-grid">
        <RuntimeStatusCard label="API" value={readStates.health === "ready" ? health?.status : readStates.health || "checking"} freshness={lastResponse("health")}
          measurementAt={readStates.health === "ready" ? health?.checked_at : null} />
        <RuntimeStatusCard
          label="Database"
          value={readStates.runtimeStatus === "ready" ? runtimeStatus?.database?.status : readStates.runtimeStatus || "checking"}
          detail={readStates.runtimeStatus === "ready" ? runtimeStatus?.database?.detail : null}
          freshness={lastResponse("runtimeStatus")}
          measurementAt={readStates.runtimeStatus === "ready" ? runtimeStatus?.database?.checked_at : null}
        />
        <RuntimeStatusCard
          label="Policy checks"
          value={readStates.runtimeStatus === "ready" ? runtimeStatus?.opa?.status : readStates.runtimeStatus || "checking"}
          detail={readStates.runtimeStatus === "ready" ? runtimeStatus?.opa?.endpoint : null}
          freshness={lastResponse("runtimeStatus")}
          measurementAt={readStates.runtimeStatus === "ready" ? runtimeStatus?.opa?.checked_at : null}
        />
        <RuntimeStatusCard
          label="Gateway"
          value={readStates.runtimeStatus === "ready" ? runtimeStatus?.gateway?.status : readStates.runtimeStatus || "checking"}
          detail={readStates.runtimeStatus === "ready" ? runtimeStatus?.gateway?.endpoint : null}
          freshness={lastResponse("runtimeStatus")}
          measurementAt={readStates.runtimeStatus === "ready" ? runtimeStatus?.gateway?.checked_at : null}
        />
      </div>

      <details className="operator-technical-details"><summary>MCP inventory and decision counts</summary><h3 className="dashboard-section-heading">Recorded activity</h3>
      <div className="stats-grid">
        <StatCard label="MCP servers" value={count("servers", servers.length)} />
        <StatCard label="MCP tools" value={count("tools", tools.length)} />
        <StatCard label="Reviews approved" value={count("tools", approvedTools.length)} tone="stat-good" />
        <StatCard label="Tools requiring review" value={count("tools", reviewTools.length)} tone="stat-warn" />
        <StatCard label="Blocked tools" value={count("tools", blockedTools.length)} tone="stat-danger" />
        <StatCard label="Recorded policy allows (OPA or Proxy decision)" value={count("runtimeLogs", recordedAllows ?? "—")} />
        <StatCard label="Recorded policy blocks (OPA or Proxy decision)" value={count("runtimeLogs", recordedBlocks ?? "—")} tone="stat-danger" />
        <StatCard label="Outcome uncertain after send" value={count("runtimeLogs", uncertainOutcomes ?? "—")} tone="stat-warn" />
        <StatCard label="Execution recorded" value={count("runtimeLogs", executionRecorded ?? "—")} />
        <StatCard label="Active emergency blocks" value={count("emergencyDenies", activeDenies.length)} tone="stat-warn" />
      </div>
      <p className="hint-text">Runtime counts are computed by the backend over all retained outcome events, not the latest 20 rows; intents and deleted history are excluded. A policy allow is a decision, not a successful call: an allowed call can still be withheld, fail or have an uncertain outcome, so allows and uncertain outcomes are counted separately.</p>
      <p className="hint-text" role="note">Inventory: {lastResponse("tools") || "current response unavailable"}. Runtime outcome summary: {lastResponse("runtimeLogs") || "current response unavailable"}. Emergency restrictions: {lastResponse("emergencyDenies") || "current response unavailable"}. These are API receipt times, not measurement times from the upstream services.</p>
      </details>

      <div className="dashboard-layout">
        <section className="detail-panel">
          <h3>Active security rules</h3>
          {readStates.activeRevision === "unavailable" && (
            <p className="hint-text" role="status">
              The latest signed configuration could not be checked. Any revision below is
              previously loaded metadata, not proof of what is currently active.
              Refresh after the service recovers before changing security settings.
            </p>
          )}
          {lastResponse("activeRevision") && <p className="hint-text" role="note">{lastResponse("activeRevision")}; signature metadata must still be verified independently.</p>}
          {activeRevision ? (
            <dl className="compact-dl">
              <div>
                <dt>Revision</dt>
                <dd>{activeRevision.revision_number}</dd>
              </div>
              <div>
                <dt>Signed revision metadata</dt>
                <dd>
                  <details className="dashboard-technical-details">
                    <summary>View technical identifiers</summary>
                    <span>Schema: {activeRevision.schema_version}</span>
                    <span>Content fingerprint: {shorten(activeRevision.content_hash)}</span>
                  </details>
                </dd>
              </div>
              <div>
                <dt>Status</dt>
                <dd>
                  <Badge value={activeRevision.status} />
                </dd>
              </div>
            </dl>
          ) : (
            <div className="empty-state">{unavailableMessage("activeRevision") ||
              (readStates.activeRevision === "ready" ? "No published security rules yet." : "Checking for published security rules…")}</div>
          )}
          <button className="secondary-action" type="button" onClick={() => onNavigate("config")}>Open security rules</button>
        </section>

        <section className="detail-panel">
          <h3>Recent activity (up to six of the latest 200 loaded audit events)</h3>
          {auditEvents.length === 0 ? (
            <div className="empty-state">{unavailableMessage("audit") ||
              (readStates.audit === "ready" ? "No audit events recorded yet." : "Loading audit history…")}</div>
          ) : (
            <ul className="event-list">
              {auditEvents.slice(0, 6).map((event) => (
                <li key={event.id}>
                  <strong title={event.action}>{String(event.action || "Unknown").replaceAll("_", " ").toLowerCase().replace(/^./, (c) => c.toUpperCase())}</strong>
                  <span>{event.actor_username_snapshot || "system"}</span>
                  <small>{formatDate(event.timestamp)}</small>
                </li>
              ))}
            </ul>
          )}
          <button className="secondary-action" type="button" onClick={() => onNavigate("audit")}>Open audit history</button>
        </section>
      </div>

    </section>
  );
}

function RuntimeStatusCard({ label, value, detail, freshness, measurementAt }) {
  return (
    <div className="status-panel compact-status">
      <span>{label}</span>
      <strong>{String(value || "unknown").toLowerCase().replace(/^./, (c) => c.toUpperCase())}</strong>
      <small role="note">{measurementAt ? "Checked by server: " + formatDate(measurementAt) : "Server check time unavailable"}</small>
      <small role="note">{freshness || "Current API response unavailable"}</small>
      {detail && <details className="operator-technical-details">
        <summary>Connection details</summary>
        <small>{detail}</small>
      </details>}
    </div>
  );
}

function Badge({ value }) {
  return <span className={`badge ${badgeClass(value)}`}>{value || "unknown"}</span>;
}

function badgeClass(value) {
  const normalized = String(value || "").toLowerCase();
  if (["ok", "healthy", "published", "approved", "admin_allowed"].includes(normalized)) {
    return "badge-success";
  }
  if (["unavailable", "blocked", "error"].includes(normalized)) {
    return "badge-danger";
  }
  return "badge-muted";
}

function shorten(value) {
  if (!value) {
    return "-";
  }
  return `${String(value).slice(0, 12)}...${String(value).slice(-8)}`;
}

function formatDate(value) {
  return formatServerTime(value);
}

export default Dashboard;
