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
  loading,
  readStates = {},
  onNavigate,
}) {
  const approvedTools = tools.filter(
    (tool) =>
      ["APPROVED", "ADMIN_ALLOWED"].includes(tool.analysis_status) &&
      tool.approved_fingerprint_match,
  );
  const reviewTools = tools.filter((tool) =>
    ["PENDING_ANALYSIS", "QUARANTINED", "REVIEW_REQUIRED", "ANALYSIS_FAILED"].includes(
      tool.analysis_status,
    ),
  );
  const blockedTools = tools.filter((tool) => tool.analysis_status === "BLOCKED");
  const activeDenies = emergencyDenies.filter((deny) => new Date(deny.expires_at) > new Date());
  // A pre-execution audit intent and its completion are two events, but
  // one logical tool call. Keep intents in logs; exclude them from KPIs.
  const recentAllows = runtimeLogs.filter(
    (log) => log.decision === "ALLOW" && log.execution_status !== "authorized_pending_execution",
  ).length;
  const recentBlocks = runtimeLogs.filter((log) => log.decision === "BLOCK").length;

  function count(source, value) {
    return readStates[source] === "ready" ? value : "—";
  }

  function unavailableMessage(source) {
    return readStates[source] === "unavailable" ? "The latest data is unavailable." : null;
  }

  return (
    <section className="page-section">
      <div className="section-heading">
        <h2>Security overview</h2>
        <p aria-live="polite">{loading ? "Refreshing security information…" : "Review tool risks, service health and recent decisions."}</p>
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
          <article className="dashboard-priority-card" data-tone="attention">
            <span>Tools to review</span>
            <strong>{count("tools", reviewTools.length)}</strong>
            <p>{unavailableMessage("tools") || "Pending, quarantined or failed tool reviews."}</p>
            <button type="button" className="secondary-action" onClick={() => onNavigate("analysis")}>
              Review tools
            </button>
          </article>
          <article className="dashboard-priority-card" data-tone="restricted">
            <span>Tools marked blocked</span>
            <strong>{count("tools", blockedTools.length)}</strong>
            <p>{unavailableMessage("tools") || "Open a tool to see why it was blocked."}</p>
            <button type="button" className="secondary-action" onClick={() => onNavigate("analysis")}>
              See analysis
            </button>
          </article>
          <article className="dashboard-priority-card" data-tone="neutral">
            <span>Active emergency restrictions</span>
            <strong>{count("emergencyDenies", activeDenies.length)}</strong>
            <p>{unavailableMessage("emergencyDenies") || "Restrictions currently in effect."}</p>
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
        <RuntimeStatusCard label="API" value={readStates.health === "ready" ? health?.status : readStates.health || "checking"} />
        <RuntimeStatusCard
          label="Database"
          value={readStates.runtimeStatus === "ready" ? runtimeStatus?.database?.status : readStates.runtimeStatus || "checking"}
          detail={runtimeStatus?.database?.detail}
        />
        <RuntimeStatusCard
          label="Policy checks"
          value={readStates.runtimeStatus === "ready" ? runtimeStatus?.opa?.status : readStates.runtimeStatus || "checking"}
          detail={runtimeStatus?.opa?.endpoint}
        />
        <RuntimeStatusCard
          label="Gateway"
          value={readStates.runtimeStatus === "ready" ? runtimeStatus?.gateway?.status : readStates.runtimeStatus || "checking"}
          detail={runtimeStatus?.gateway?.endpoint}
        />
      </div>

      <details className="operator-technical-details"><summary>MCP inventory and decision counts</summary><h3 className="dashboard-section-heading">Recorded activity</h3>
      <div className="stats-grid">
        <StatCard label="MCP servers" value={count("servers", servers.length)} />
        <StatCard label="MCP tools" value={count("tools", tools.length)} />
        <StatCard label="Reviews approved" value={count("tools", approvedTools.length)} tone="stat-good" />
        <StatCard label="Tools requiring review" value={count("tools", reviewTools.length)} tone="stat-warn" />
        <StatCard label="Blocked tools" value={count("tools", blockedTools.length)} tone="stat-danger" />
        <StatCard label="Recent allowed decisions" value={count("runtimeLogs", recentAllows)} tone="stat-good" />
        <StatCard label="Recent blocked decisions" value={count("runtimeLogs", recentBlocks)} tone="stat-danger" />
        <StatCard label="Active emergency blocks" value={count("emergencyDenies", activeDenies.length)} tone="stat-warn" />
      </div>

      </details>

      <div className="dashboard-layout">
        <section className="detail-panel">
          <h3>Active security rules</h3>
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
          <h3>Recent activity</h3>
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

function RuntimeStatusCard({ label, value, detail }) {
  return (
    <div className="status-panel compact-status">
      <span>{label}</span>
      <strong>{String(value || "unknown").toLowerCase().replace(/^./, (c) => c.toUpperCase())}</strong>
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
  if (!value) {
    return "-";
  }
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
}

export default Dashboard;
