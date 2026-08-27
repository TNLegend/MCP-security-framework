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
  const recentAllows = runtimeLogs.filter((log) => log.decision === "ALLOW").length;
  const recentBlocks = runtimeLogs.filter((log) => log.decision === "BLOCK").length;

  return (
    <section className="page-section">
      <div className="section-heading">
        <h2>Dashboard</h2>
        <p>{loading ? "Loading backend data..." : "Control Plane evidence loaded."}</p>
      </div>

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

      <div className="stats-grid">
        <StatCard label="MCP servers" value={servers.length || 0} />
        <StatCard label="MCP tools" value={tools.length || 0} />
        <StatCard label="Approved tools" value={approvedTools.length} tone="stat-good" />
        <StatCard label="Tools requiring review" value={reviewTools.length} tone="stat-warn" />
        <StatCard label="Blocked tools" value={blockedTools.length} tone="stat-danger" />
        <StatCard label="Recent ALLOW calls" value={recentAllows} tone="stat-good" />
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
                <dt>schema_version</dt>
                <dd>{activeRevision.schema_version}</dd>
              </div>
              <div>
                <dt>content_hash</dt>
                <dd>{shorten(activeRevision.content_hash)}</dd>
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
