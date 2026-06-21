function Inventory({ servers, loading }) {
  return (
    <section className="page-section">
      <div className="section-heading">
        <h2>MCP Inventory</h2>
        <p>{loading ? "Loading inventory..." : `${servers.length} server(s)`}</p>
      </div>

      <div className="table-shell">
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Type</th>
              <th>Endpoint</th>
              <th>Status</th>
              <th>Created</th>
            </tr>
          </thead>
          <tbody>
            {servers.length === 0 ? (
              <tr>
                <td colSpan="5">Aucune donnée</td>
              </tr>
            ) : (
              servers.map((server) => (
                <tr key={server.id}>
                  <td>{server.name}</td>
                  <td>{server.server_type}</td>
                  <td>{server.endpoint}</td>
                  <td>{server.status}</td>
                  <td>{server.created_at}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}

export default Inventory;
