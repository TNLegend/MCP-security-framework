import { useState } from "react";
import { createEmergencyDeny, revokeEmergencyDeny } from "../api/client";

const TARGET_TYPES = [
  "global",
  "agent_id",
  "framework_session_id",
  "server_ref",
  "server_tool",
];

function EmergencyDeny({ denies = [], isAdmin = false, loading = false, onRefresh }) {
  const [form, setForm] = useState({
    target_type: "global",
    target_value: "",
    target_secondary_value: "",
    reason: "Emergency deny from Control Center",
    expires_at: futureLocalDateTime(),
  });
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  async function submit(event) {
    event.preventDefault();
    setError("");
    setMessage("");
    const payload = {
      target_type: form.target_type,
      target_value: form.target_type === "global" ? null : form.target_value || null,
      target_secondary_value:
        form.target_type === "server_tool" ? form.target_secondary_value || null : null,
      reason: form.reason,
      expires_at: new Date(form.expires_at).toISOString(),
    };
    try {
      await createEmergencyDeny(payload);
      setMessage("Emergency Deny created.");
      await onRefresh?.();
    } catch (err) {
      setError(err.message || "Emergency Deny creation failed");
    }
  }

  async function revoke(denyId) {
    if (!window.confirm("Revoke this Emergency Deny?")) {
      return;
    }
    setError("");
    setMessage("");
    try {
      await revokeEmergencyDeny(denyId);
      setMessage("Emergency Deny revoked.");
      await onRefresh?.();
    } catch (err) {
      setError(err.message || "Emergency Deny revocation failed");
    }
  }

  if (loading) {
    return (
      <section className="page-section">
        <div className="section-heading">
          <h2>Emergency Deny</h2>
          <p>Loading deny list...</p>
        </div>
      </section>
    );
  }

  return (
    <section className="page-section">
      <div className="section-heading">
        <h2>Emergency Deny</h2>
        <p>{denies.length} record(s)</p>
      </div>
      {message && <div className="success-banner">{message}</div>}
      {error && <div className="error-banner">{error}</div>}

      {isAdmin && (
        <form className="action-panel form-grid" onSubmit={submit}>
          <label>
            Target type
            <select
              onChange={(event) => setForm({ ...form, target_type: event.target.value })}
              value={form.target_type}
            >
              {TARGET_TYPES.map((target) => (
                <option key={target} value={target}>
                  {target}
                </option>
              ))}
            </select>
          </label>
          {form.target_type !== "global" && (
            <label>
              Target value
              <input
                onChange={(event) => setForm({ ...form, target_value: event.target.value })}
                value={form.target_value}
              />
            </label>
          )}
          {form.target_type === "server_tool" && (
            <label>
              Tool name
              <input
                onChange={(event) =>
                  setForm({ ...form, target_secondary_value: event.target.value })
                }
                value={form.target_secondary_value}
              />
            </label>
          )}
          <label>
            Expires at
            <input
              onChange={(event) => setForm({ ...form, expires_at: event.target.value })}
              type="datetime-local"
              value={form.expires_at}
            />
          </label>
          <label className="wide-field">
            Reason
            <input
              onChange={(event) => setForm({ ...form, reason: event.target.value })}
              value={form.reason}
            />
          </label>
          <button className="secondary-action" type="submit">
            Create Emergency Deny
          </button>
        </form>
      )}

      <div className="table-shell">
        <table>
          <thead>
            <tr>
              <th>Target</th>
              <th>Value</th>
              <th>Reason</th>
              <th>Created</th>
              <th>Expires</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {denies.length === 0 ? (
              <tr>
                <td colSpan="6">No Emergency Deny records.</td>
              </tr>
            ) : (
              denies.map((deny) => (
                <tr key={deny.id}>
                  <td>{deny.target_type}</td>
                  <td>{targetValue(deny)}</td>
                  <td>{deny.reason}</td>
                  <td>{formatDate(deny.created_at)}</td>
                  <td>{formatDate(deny.expires_at)}</td>
                  <td>
                    {isAdmin ? (
                      <button className="tiny-action" onClick={() => revoke(deny.id)} type="button">
                        Revoke
                      </button>
                    ) : (
                      "read-only"
                    )}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function targetValue(deny) {
  if (deny.target_type === "global") {
    return "all governed calls";
  }
  if (deny.target_secondary_value) {
    return `${deny.target_value} / ${deny.target_secondary_value}`;
  }
  return deny.target_value || "-";
}

function futureLocalDateTime() {
  const date = new Date(Date.now() + 60 * 60 * 1000);
  return date.toISOString().slice(0, 16);
}

function formatDate(value) {
  if (!value) {
    return "-";
  }
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
}

export default EmergencyDeny;
