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

  return (
    <section className="page-section">
      <div className="section-heading">
        <h2>Dashboard</h2>
        <p>{loading ? "Loading backend data..." : "Control Plane evidence loaded."}</p>
      </div>

      <section className="dashboard-priority" aria-label="What needs attention">
        <div className="section-heading compact-heading">
          <h3>What needs attention?</h3>
          <p>Counts from recorded Control Plane data, not a runtime permission check</p>
        </div>
        <div className="dashboard-priority-grid">
          <article className="dashboard-priority-card">
            <span>Tools awaiting analysis or review</span>
            <strong>{reviewTools.length}</strong>
            <p>Inspect the current findings before an administrator decides.</p>
            <button type="button" className="secondary-action" onClick={() => onNavigate("analysis")}>
              Review tools
            </button>
          </article>
          <article className="dashboard-priority-card">
            <span>Tools marked blocked</span>
            <strong>{blockedTools.length}</strong>
            <p>A previous analysis block does not establish the state of every runtime policy.</p>
            <button type="button" className="secondary-action" onClick={() => onNavigate("analysis")}>
              See analysis
            </button>
          </article>
          <article className="dashboard-priority-card">
            <span>Active emergency restrictions</span>
            <strong>{activeDenies.length}</strong>
            <p>Emergency Deny is an independent enforcement mechanism.</p>
            <button type="button" className="secondary-action" onClick={() => onNavigate("emergency")}>
              See restrictions
            </button>
          </article>
        </div>
      </section>

      <h3 className="dashboard-section-heading">Service status</h3>
      <p className="hint-text">Unavailable status information does not mean a service is healthy.</p>
      <div className="status-grid">
        <RuntimeStatusCard label="Backend" value={health?.status || "unavailable"} />
        <RuntimeStatusCard
          label="PostgreSQL"
          value={runtimeStatus?.database?.status || "unknown"}
          detail={runtimeStatus?.database?.detail}
        />
        <RuntimeStatusCard
          label="OPA"
          value={runtimeStatus?.opa?.status || "unknown"}
          detail={runtimeStatus?.opa?.endpoint}
        />
        <RuntimeStatusCard
          label="MCP Gateway"
          value={runtimeStatus?.gateway?.status || "unknown"}
          detail={runtimeStatus?.gateway?.endpoint}
        />
      </div>

      <h3 className="dashboard-section-heading">Recorded activity</h3>
      <div className="stats-grid">
        <StatCard label="MCP servers" value={servers.length || 0} />
        <StatCard label="MCP tools" value={tools.length || 0} />
        <StatCard label="Analysis approved (not runtime access)" value={approvedTools.length} tone="stat-good" />
        <StatCard label="Tools requiring review" value={reviewTools.length} tone="stat-warn" />
        <StatCard label="Blocked tools" value={blockedTools.length} tone="stat-danger" />
        <StatCard label="Recent ALLOW decisions (not proof of execution)" value={recentAllows} tone="stat-good" />
        <StatCard label="Recent BLOCK calls" value={recentBlocks} tone="stat-danger" />
        <StatCard label="Active Emergency Denies" value={activeDenies.length} tone="stat-warn" />
      </div>

      <div className="dashboard-layout">
        <section className="detail-panel">
          <h3>Published Configuration</h3>
          {activeRevision ? (
            <dl className="compact-dl">
              <div>
                <dt>revision_number</dt>
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
                <dt>status</dt>
                <dd>
                  <Badge value={activeRevision.status} />
                </dd>
              </div>
            </dl>
          ) : (
            <div className="empty-state">No published configuration revision found.</div>
          )}
        </section>

        <section className="detail-panel">
          <h3>Recent Audit Events</h3>
          {auditEvents.length === 0 ? (
            <div className="empty-state">No audit events recorded yet.</div>
          ) : (
            <ul className="event-list">
              {auditEvents.slice(0, 6).map((event) => (
                <li key={event.id}>
                  <strong>{event.action}</strong>
                  <span>{event.actor_username_snapshot || "system"}</span>
                  <small>{formatDate(event.timestamp)}</small>
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>

      {isAdmin && (
        <div className="quick-actions">
          <button type="button" onClick={() => onNavigate("inventory")}>
            Register MCP
          </button>
          <button type="button" onClick={() => onNavigate("analysis")}>
            Review Tools
          </button>
          <button type="button" onClick={() => onNavigate("emergency")}>
            Create Emergency Deny
          </button>
          <button type="button" onClick={() => onNavigate("users")}>
            Manage Users
          </button>
        </div>
      )}
    </section>
  );
}

function RuntimeStatusCard({ label, value, detail }) {
  return (
    <div className="status-panel compact-status">
      <span>{label}</span>
      <strong>{value}</strong>
      {detail && <small>{detail}</small>}
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
