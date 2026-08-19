import { useMemo, useState } from "react";

function Audit({ events = [], loading = false }) {
  const [query, setQuery] = useState("");
  const filtered = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    if (!normalized) {
      return events;
    }
    return events.filter((event) =>
      [
        event.action,
        event.target_type,
        event.target_id,
        event.actor_username_snapshot,
        event.result,
      ]
        .filter(Boolean)
        .some((value) => String(value).toLowerCase().includes(normalized)),
    );
  }, [events, query]);

  if (loading) {
    return (
      <section className="page-section">
        <div className="section-heading">
          <h2>Audit</h2>
          <p>Loading audit events...</p>
        </div>
      </section>
    );
  }

  return (
    <section className="page-section">
      <div className="section-heading">
        <h2>Audit</h2>
        <p>{filtered.length} event(s)</p>
      </div>
      <div className="action-panel inline-form">
        <label>
          Filter
          <input
            onChange={(event) => setQuery(event.target.value)}
            placeholder="action, actor, target..."
            value={query}
          />
        </label>
      </div>
      <div className="table-shell">
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Actor</th>
              <th>Action</th>
              <th>Target</th>
              <th>Revision</th>
              <th>Result</th>
              <th>Reason</th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr>
                <td colSpan="7">No audit events.</td>
              </tr>
            ) : (
              filtered.map((event) => (
                <tr key={event.id}>
                  <td>{formatDate(event.timestamp)}</td>
                  <td>{event.actor_username_snapshot || "system"}</td>
                  <td>{event.action}</td>
                  <td>{[event.target_type, event.target_id].filter(Boolean).join(" / ")}</td>
                  <td>{shorten(event.revision_id)}</td>
                  <td>
                    <span className={`badge ${event.result === "SUCCESS" ? "badge-success" : "badge-danger"}`}>
                      {event.result}
                    </span>
                  </td>
                  <td>{event.reason || "-"}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function formatDate(value) {
  if (!value) {
    return "-";
  }
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
}

function shorten(value) {
  if (!value) {
    return "-";
  }
  return String(value).length > 22
    ? `${String(value).slice(0, 10)}...${String(value).slice(-6)}`
    : String(value);
}

export default Audit;
