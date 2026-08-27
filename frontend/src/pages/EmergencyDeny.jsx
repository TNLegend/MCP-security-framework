import { useState } from "react";
import { createEmergencyDeny, revokeEmergencyDeny } from "../api/client";
import {
  LIMITS,
  clearFieldError,
  emergencyDenyPayload,
  futureLocalDateTime,
  validateEmergencyDeny,
} from "../utils/validation";

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
  const [fieldErrors, setFieldErrors] = useState({});
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(event) {
    event.preventDefault();
    if (busy) {
      return;
    }
    setError("");
    setMessage("");
    const errors = validateEmergencyDeny(form);
    setFieldErrors(errors);
    if (Object.keys(errors).length > 0) {
      return;
    }
    const { payload } = emergencyDenyPayload(form);
    setBusy(true);
    try {
      await createEmergencyDeny(payload);
      setMessage("Emergency Deny created.");
      setFieldErrors({});
      await onRefresh?.();
    } catch (err) {
      setError(err.message || "Emergency Deny creation failed");
    } finally {
      setBusy(false);
    }
  }

  async function revoke(denyId) {
    if (busy || !window.confirm("Revoke this Emergency Deny?")) {
      return;
    }
    setError("");
    setMessage("");
    setBusy(true);
    try {
      await revokeEmergencyDeny(denyId);
      setMessage("Emergency Deny revoked.");
      await onRefresh?.();
    } catch (err) {
      setError(err.message || "Emergency Deny revocation failed");
    } finally {
      setBusy(false);
    }
  }

  function updateField(field, value) {
    setForm({ ...form, [field]: value });
    setFieldErrors((current) => clearFieldError(current, field));
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
              onChange={(event) => {
                setForm({
                  ...form,
                  target_type: event.target.value,
                  target_value: "",
                  target_secondary_value: "",
                });
                setFieldErrors((current) =>
                  clearFieldError(
                    clearFieldError(
                      clearFieldError(current, "target_type"),
                      "target_value",
                    ),
                    "target_secondary_value",
                  ),
                );
              }}
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
                aria-describedby="deny-target-value-error"
                aria-invalid={Boolean(fieldErrors.target_value)}
                maxLength={LIMITS.emergencyTargetValueMax}
                onChange={(event) => updateField("target_value", event.target.value)}
                required
                value={form.target_value}
              />
              <FieldError id="deny-target-value-error" message={fieldErrors.target_value} />
            </label>
          )}
          {form.target_type === "server_tool" && (
            <label>
              Tool name
              <input
                aria-describedby="deny-secondary-target-error"
                aria-invalid={Boolean(fieldErrors.target_secondary_value)}
                maxLength={LIMITS.emergencySecondaryTargetMax}
                onChange={(event) =>
                  updateField("target_secondary_value", event.target.value)
                }
                required
                value={form.target_secondary_value}
              />
              <FieldError
                id="deny-secondary-target-error"
                message={fieldErrors.target_secondary_value}
              />
            </label>
          )}
          <label>
            Expires at
            <input
              aria-describedby="deny-expiry-error"
              aria-invalid={Boolean(fieldErrors.expires_at)}
              min={futureLocalDateTime(5 * 60 * 1000)}
              onChange={(event) => updateField("expires_at", event.target.value)}
              required
              type="datetime-local"
              value={form.expires_at}
            />
            <FieldError id="deny-expiry-error" message={fieldErrors.expires_at} />
          </label>
          <label className="wide-field">
            Reason
            <input
              aria-describedby="deny-reason-error"
              aria-invalid={Boolean(fieldErrors.reason)}
              maxLength={LIMITS.emergencyReasonMax}
              minLength={LIMITS.emergencyReasonMin}
              onChange={(event) => updateField("reason", event.target.value)}
              required
              value={form.reason}
            />
            <FieldError id="deny-reason-error" message={fieldErrors.reason} />
          </label>
          <button className="secondary-action" disabled={busy} type="submit">
            {busy ? "Creating..." : "Create Emergency Deny"}
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
                      <button
                        className="tiny-action"
                        disabled={busy}
                        onClick={() => revoke(deny.id)}
                        type="button"
                      >
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

function FieldError({ id, message }) {
  return message ? (
    <span className="field-error" id={id}>
      {message}
    </span>
  ) : null;
}

function formatDate(value) {
  if (!value) {
    return "-";
  }
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
}

export default EmergencyDeny;
