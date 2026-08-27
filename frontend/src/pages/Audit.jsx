import { useMemo, useState } from "react";

function Audit({ events = [], loading = false }) {
  const [query, setQuery] = useState("");
  const [selectedEvent, setSelectedEvent] = useState(null);
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
      <div className="table-shell audit-table">
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
              <th>Details</th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr>
                <td colSpan="8">No audit events.</td>
              </tr>
            ) : (
              filtered.map((event) => {
                const target = [event.target_type, event.target_id].filter(Boolean).join(" / ");
                return (
                <tr key={event.id}>
                  <td>{formatDate(event.timestamp)}</td>
                  <td>{event.actor_username_snapshot || "system"}</td>
                  <td>{event.action}</td>
                  <td><span className="audit-target" title={target}>{shorten(target, 42)}</span></td>
                  <td>{shorten(event.revision_id)}</td>
                  <td>
                    <span className={`badge ${event.result === "SUCCESS" ? "badge-success" : "badge-danger"}`}>
                      {event.result}
                    </span>
                  </td>
                  <td>{event.reason || "-"}</td>
                  <td>
                    <button onClick={() => setSelectedEvent(event)} type="button">
                      View
                    </button>
                  </td>
                </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
      {selectedEvent && (
        <section className="audit-event-detail" aria-label="Audit event detail">
          <div className="section-heading compact-heading">
            <h3>{selectedEvent.action}</h3>
            <button onClick={() => setSelectedEvent(null)} type="button">Close</button>
          </div>
          <dl className="inline-metadata audit-event-metadata">
            <div><dt>Event ID</dt><dd>{selectedEvent.id}</dd></div>
            <div><dt>Target</dt><dd>{[selectedEvent.target_type, selectedEvent.target_id].filter(Boolean).join(" / ") || "-"}</dd></div>
            <div><dt>Revision</dt><dd>{selectedEvent.revision_id || "-"}</dd></div>
            <div><dt>Result</dt><dd>{selectedEvent.result}</dd></div>
            <div><dt>Source IP</dt><dd>{selectedEvent.source_ip || "-"}</dd></div>
            <div><dt>Reason</dt><dd>{selectedEvent.reason || "-"}</dd></div>
          </dl>
          <div className="audit-json-grid">
            <AuditJson title="Before" value={selectedEvent.before_json} />
            <AuditJson title="After" value={selectedEvent.after_json} />
            <AuditJson title="Metadata" value={selectedEvent.metadata} />
          </div>
        </section>
      )}
    </section>
  );
}

function AuditJson({ title, value }) {
  return (
    <div>
      <h4>{title}</h4>
      <pre className="json-block">{value ? JSON.stringify(value, null, 2) : "-"}</pre>
    </div>
  );
}

function formatDate(value) {
  if (!value) {
    return "-";
  }
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
}

function shorten(value, maxLength = 22) {
  if (!value) {
    return "-";
  }
  return String(value).length > maxLength
    ? `${String(value).slice(0, 10)}...${String(value).slice(-6)}`
    : String(value);
}

export default Audit;
