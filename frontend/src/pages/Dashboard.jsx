function StatCard({ label, value }) {
  return (
    <div className="stat-card">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function Dashboard({ health, servers, tools, policies, runtimeLogs, loading }) {
  return (
    <section className="page-section">
      <div className="section-heading">
        <h2>Dashboard</h2>
        <p>{loading ? "Loading backend data..." : "Backend data loaded."}</p>
      </div>

      <div className="status-panel">
        <span>Backend status</span>
        <strong>{health?.status || "unavailable"}</strong>
        <small>{health?.service || "MCP Security Framework Backend"}</small>
      </div>

      <div className="stats-grid">
        <StatCard label="MCP servers" value={servers.length || 0} />
        <StatCard label="MCP tools" value={tools.length || 0} />
        <StatCard label="Policy rules" value={policies.length || 0} />
        <StatCard label="Runtime logs" value={runtimeLogs.length || 0} />
      </div>
    </section>
  );
}

export default Dashboard;
