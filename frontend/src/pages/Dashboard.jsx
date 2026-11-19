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
        <h2>Security overview</h2>
        <p>{loading ? "Loading security data..." : "Your security overview"}</p>
      </div>

      <section className="dashboard-priority" aria-label="What needs attention">
        <div className="section-heading compact-heading">
          <h3>Needs attention</h3>
          <p>Actions based on the latest recorded results</p>
        </div>
        <div className="dashboard-priority-grid">
          <article className="dashboard-priority-card">
            <span>Tools to review</span>
            <strong>{reviewTools.length}</strong>
            <p>See the latest security findings.</p>
            <button type="button" className="secondary-action" onClick={() => onNavigate("analysis")}>
              Review tools
            </button>
          </article>
          <article className="dashboard-priority-card">
            <span>Tools marked blocked</span>
            <strong>{blockedTools.length}</strong>
            <p>Open the tool to see why it was blocked.</p>
            <button type="button" className="secondary-action" onClick={() => onNavigate("analysis")}>
              See analysis
            </button>
          </article>
          <article className="dashboard-priority-card">
            <span>Active emergency restrictions</span>
            <strong>{activeDenies.length}</strong>
            <p>Restrictions currently in effect.</p>
            <button type="button" className="secondary-action" onClick={() => onNavigate("emergency")}>
              See restrictions
            </button>
          </article>
        </div>
      </section>

      <h3 className="dashboard-section-heading">Service status</h3>
      <p className="hint-text">Some services may be unavailable.</p>
      <div className="status-grid">
        <RuntimeStatusCard label="API" value={health?.status || "unavailable"} />
        <RuntimeStatusCard
          label="Database"
          value={runtimeStatus?.database?.status || "unknown"}
          detail={runtimeStatus?.database?.detail}
        />
        <RuntimeStatusCard
          label="Policy checks"
          value={runtimeStatus?.opa?.status || "unknown"}
          detail={runtimeStatus?.opa?.endpoint}
        />
        <RuntimeStatusCard
          label="Gateway"
          value={runtimeStatus?.gateway?.status || "unknown"}
          detail={runtimeStatus?.gateway?.endpoint}
        />
      </div>

      <details className="operator-technical-details"><summary>More security numbers</summary><h3 className="dashboard-section-heading">Recorded activity</h3>
      <div className="stats-grid">
        <StatCard label="MCP servers" value={servers.length || 0} />
        <StatCard label="MCP tools" value={tools.length || 0} />
        <StatCard label="Reviews approved" value={approvedTools.length} tone="stat-good" />
        <StatCard label="Tools requiring review" value={reviewTools.length} tone="stat-warn" />
        <StatCard label="Blocked tools" value={blockedTools.length} tone="stat-danger" />
        <StatCard label="Recent allowed decisions" value={recentAllows} tone="stat-good" />
        <StatCard label="Recent blocked decisions" value={recentBlocks} tone="stat-danger" />
        <StatCard label="Active emergency blocks" value={activeDenies.length} tone="stat-warn" />
      </div>

      </details>

      <div className="dashboard-layout">
        <section className="detail-panel">
          <h3>Active security rules</h3>
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
          <h3>Recent activity</h3>
          {auditEvents.length === 0 ? (
            <div className="empty-state">No audit events recorded yet.</div>
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
        </section>
      </div>

      {isAdmin && (
        <div className="quick-actions">
          <button type="button" onClick={() => onNavigate("inventory")}>
            Add MCP server
          </button>
          <button type="button" onClick={() => onNavigate("analysis")}>
            Review tools
          </button>
          <button type="button" onClick={() => onNavigate("emergency")}>
            Emergency block
          </button>
          <button type="button" onClick={() => onNavigate("users")}>
            Manage users
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
