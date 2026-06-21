function RuntimeLogs({ logs, loading }) {
  return (
    <section className="page-section">
      <div className="section-heading">
        <h2>Runtime Logs</h2>
        <p>{loading ? "Loading runtime logs..." : `${logs.length} log(s)`}</p>
      </div>

      <div className="table-shell">
        <table>
          <thead>
            <tr>
              <th>Agent ID</th>
              <th>Server ID</th>
              <th>Tool</th>
              <th>Status</th>
              <th>Created</th>
            </tr>
          </thead>
          <tbody>
            {logs.length === 0 ? (
              <tr>
                <td colSpan="5">Aucune donnée</td>
              </tr>
            ) : (
              logs.map((log) => (
                <tr key={log.id}>
                  <td>{log.agent_id}</td>
                  <td>{log.server_id ?? "none"}</td>
                  <td>{log.tool_name}</td>
                  <td>{log.status}</td>
                  <td>{log.created_at}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}

export default RuntimeLogs;
