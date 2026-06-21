function Policies({ policies, loading }) {
  return (
    <section className="page-section">
      <div className="section-heading">
        <h2>Policies</h2>
        <p>{loading ? "Loading policies..." : `${policies.length} rule(s)`}</p>
      </div>

      <div className="table-shell">
        <table>
          <thead>
            <tr>
              <th>Rule ID</th>
              <th>Decision</th>
              <th>Severity</th>
              <th>Enabled</th>
            </tr>
          </thead>
          <tbody>
            {policies.length === 0 ? (
              <tr>
                <td colSpan="4">Aucune donnée</td>
              </tr>
            ) : (
              policies.map((policy) => (
                <tr key={policy.id}>
                  <td>{policy.rule_id}</td>
                  <td>{policy.decision}</td>
                  <td>{policy.severity}</td>
                  <td>{policy.enabled ? "true" : "false"}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}

export default Policies;
