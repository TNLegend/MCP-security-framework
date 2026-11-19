import { useEffect, useRef, useState } from "react";
import { createEmergencyDeny, revokeEmergencyDeny } from "../api/client";
import { Pagination, usePagination } from "../components/Pagination";
import { useDialogFocus } from "../utils/useDialogFocus";
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

const TARGET_LABELS = {
  global: "All governed MCP calls",
  agent_id: "One agent",
  framework_session_id: "One framework session",
  server_ref: "One MCP server",
  server_tool: "One tool on one MCP server",
};

function describedTarget(target) {
  const name = TARGET_LABELS[target.target_type] || target.target_type;
  if (target.target_type === "global") return name;
  return name + ": " + (target.target_value || "not specified")
    + (target.target_secondary_value ? " / " + target.target_secondary_value : "");
}

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
  const [pendingCreate, setPendingCreate] = useState(null);
  const mutationLockRef = useRef(false);
  const modalRef = useRef(null);
  useDialogFocus(Boolean(pendingCreate), modalRef);
  useEffect(() => {
    if (!pendingCreate) return undefined;
    function handleEscape(event) {
      if (event.key === "Escape" && !mutationLockRef.current) {
        event.preventDefault();
        setPendingCreate(null);
      }
    }
    window.addEventListener("keydown", handleEscape);
    return () => window.removeEventListener("keydown", handleEscape);
  }, [pendingCreate]);
  const denyPagination = usePagination(denies, String(denies.length));

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
    setPendingCreate({ payload, identity: JSON.stringify(payload) });
  }

  async function confirmCreate() {
    if (!isAdmin || busy || mutationLockRef.current || !pendingCreate) return;
    const errors = validateEmergencyDeny(form);
    const current = Object.keys(errors).length === 0 ? emergencyDenyPayload(form).payload : null;
    if (!current || JSON.stringify(current) !== pendingCreate.identity) {
      setPendingCreate(null);
      setError("Restriction details changed. Review the new target and expiry before confirming.");
      return;
    }
    mutationLockRef.current = true;
    setBusy(true);
    setError("");
    try {
      await createEmergencyDeny(current);
      setMessage("Emergency Deny created.");
      setPendingCreate(null);
      setFieldErrors({});
      await onRefresh?.();
    } catch (err) {
      setError(err.message || "Emergency Deny creation failed");
    } finally {
      setBusy(false);
      mutationLockRef.current = false;
    }
  }

  async function revoke(deny) {
    if (!isAdmin || busy || mutationLockRef.current || !window.confirm(
      "Revoke the restriction for " + describedTarget(deny)
      + "? This may allow future calls if all other policies permit them."
    )) {
      return;
    }
    setError("");
    setMessage("");
    mutationLockRef.current = true;
    setBusy(true);
    try {
      await revokeEmergencyDeny(deny.id);
      setMessage("Emergency Deny revoked.");
      await onRefresh?.();
    } catch (err) {
      setError(err.message || "Emergency Deny revocation failed");
    } finally {
      setBusy(false);
      mutationLockRef.current = false;
    }
  }

  function updateField(field, value) {
    setPendingCreate(null);
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

      <p className="hint-text" role="note">
        An emergency restriction can deny calls independently of analysis scores.
        It does not change the signed configuration or permanently remove tool permissions.
      </p>
      {isAdmin && (
        <form className="action-panel form-grid" onSubmit={submit}>
          <label>
            Restriction scope
            <select
              onChange={(event) => {
                setPendingCreate(null);
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
                  {TARGET_LABELS[target] || target}
                </option>
              ))}
            </select>
          </label>
          {form.target_type === "global" && (
            <p className="deny-global-warning wide-field" role="alert">
              Global scope: this restriction affects all governed MCP calls until expiry or revocation.
              Review this choice carefully.
            </p>
          )}
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
            {busy ? "Working..." : "Review restriction before creating"}
          </button>
        </form>
      )}

      {pendingCreate && isAdmin && (
        <div className="modal-backdrop" role="presentation">
          <section aria-modal="true" aria-labelledby="deny-confirm-title"
            aria-describedby="deny-confirm-description" className="modal-panel"
            ref={modalRef} role="dialog" tabIndex={-1}>
            <h3 id="deny-confirm-title">Confirm emergency restriction</h3>
            <p id="deny-confirm-description">
              This will create an independent deny that affects future governed calls matching the scope below.
            </p>
            <dl className="compact-dl">
              <div><dt>Exact target</dt><dd>{describedTarget(pendingCreate.payload)}</dd></div>
              <div><dt>Expiry</dt><dd>{formatDate(pendingCreate.payload.expires_at)}</dd></div>
              <div><dt>Reason</dt><dd>{pendingCreate.payload.reason}</dd></div>
            </dl>
            {pendingCreate.payload.target_type === "global" && (
              <p className="deny-global-warning" role="alert">
                Global emergency restriction: all governed MCP calls will be denied while it is active.
              </p>
            )}
            <div className="button-row">
              <button className="danger-action" disabled={busy} onClick={confirmCreate} type="button">
                {busy ? "Creating restriction..." : "Confirm and activate restriction"}
              </button>
              <button className="secondary-action" disabled={busy}
                onClick={() => setPendingCreate(null)} type="button">Cancel</button>
            </div>
          </section>
        </div>
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
              denyPagination.pageItems.map((deny) => (
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
                        onClick={() => revoke(deny)}
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
      <Pagination
        label="Emergency Deny records"
        onPageChange={denyPagination.setPage}
        page={denyPagination.page}
        pageCount={denyPagination.pageCount}
        total={denyPagination.total}
      />
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
