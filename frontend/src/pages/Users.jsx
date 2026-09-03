import { useState } from "react";

import { Pagination, usePagination } from "../components/Pagination";
import {
  createUser,
  disableUser,
  enableUser,
  resetUserPassword,
  revokeUserSessions,
  updateUser,
} from "../api/client";
import {
  LIMITS,
  clearFieldError,
  isFinalEnabledAdmin,
  validatePasswordReset,
  validateReason,
  validateUserCreate,
} from "../utils/validation";

function Users({ users = [], loading = false, onRefresh }) {
  const [form, setForm] = useState({
    username: "",
    password: "",
    confirmation: "",
    role: "VIEWER",
    display_name: "",
  });
  const [fieldErrors, setFieldErrors] = useState({});
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [creating, setCreating] = useState(false);
  const [busyAction, setBusyAction] = useState("");
  const [resetTarget, setResetTarget] = useState(null);
  const [resetForm, setResetForm] = useState({
    password: "",
    confirmation: "",
    reason: "",
  });
  const [resetErrors, setResetErrors] = useState({});
  const [actionDialog, setActionDialog] = useState(null);
  const userPagination = usePagination(users, String(users.length));

  async function create(event) {
    event.preventDefault();
    setMessage("");
    setError("");
    const errors = validateUserCreate(form);
    setFieldErrors(errors);
    if (Object.keys(errors).length > 0) {
      return;
    }
    if (
      form.role === "ADMIN" &&
      !window.confirm(`Create ADMIN account for ${form.username.trim()}?`)
    ) {
      return;
    }
    setCreating(true);
    try {
      await createUser({
        username: form.username.trim(),
        password: form.password,
        role: form.role,
        display_name: form.display_name.trim() || null,
      });
      setForm({
        username: "",
        password: "",
        confirmation: "",
        role: "VIEWER",
        display_name: "",
      });
      setFieldErrors({});
      setMessage("User created.");
      await onRefresh?.();
    } catch (err) {
      setError(err.message || "User creation failed");
    } finally {
      setCreating(false);
    }
  }

  async function run(action, user) {
    if (busyAction) {
      return;
    }
    setMessage("");
    setError("");
    if (action === "role") {
      const role = user.role === "ADMIN" ? "VIEWER" : "ADMIN";
      if (role === "VIEWER" && isFinalEnabledAdmin(user, users)) {
        setError("At least one enabled ADMIN is required.");
        return;
      }
      if (
        role === "ADMIN" &&
        !window.confirm(`Grant ADMIN privileges to ${user.username}?`)
      ) {
        return;
      }
      await runMutation(`role:${user.id}`, async () => {
        await updateUser(user.id, { role });
        setMessage(`Role changed to ${role}.`);
      });
    } else if (action === "enable") {
      await runMutation(`enable:${user.id}`, async () => {
        await enableUser(user.id);
        setMessage("User enabled.");
      });
    } else if (action === "disable") {
      if (isFinalEnabledAdmin(user, users)) {
        setError("At least one enabled ADMIN is required.");
        return;
      }
      setActionDialog({
        action: "disable",
        user,
        title: `Disable ${user.username}`,
        label: "Disable reason",
        reason: "",
        errors: {},
      });
    } else if (action === "reset") {
      setResetTarget(user);
      setResetForm({ password: "", confirmation: "", reason: "" });
      setResetErrors({});
    } else if (action === "revoke") {
      setActionDialog({
        action: "revoke",
        user,
        title: `Revoke sessions for ${user.username}`,
        label: "Session revocation reason",
        reason: "",
        errors: {},
      });
    }
  }

  async function runMutation(key, mutate) {
    setBusyAction(key);
    try {
      await mutate();
      await onRefresh?.();
    } catch (err) {
      setError(err.message || "User operation failed");
    } finally {
      setBusyAction("");
    }
  }

  function closeResetDialog() {
    setResetTarget(null);
    setResetForm({ password: "", confirmation: "", reason: "" });
    setResetErrors({});
  }

  function updateCreateField(field, value) {
    setForm({ ...form, [field]: value });
    setFieldErrors((current) => clearFieldError(current, field));
  }

  function updateResetField(field, value) {
    setResetForm({ ...resetForm, [field]: value });
    setResetErrors((current) => clearFieldError(current, field));
  }

  async function submitPasswordReset(event) {
    event.preventDefault();
    setMessage("");
    setError("");
    const errors = validatePasswordReset(resetForm);
    setResetErrors(errors);
    if (Object.keys(errors).length > 0) {
      setResetForm({ ...resetForm, password: "", confirmation: "" });
      return;
    }
    setBusyAction(`reset:${resetTarget.id}`);
    try {
      await resetUserPassword(
        resetTarget.id,
        resetForm.password,
        resetForm.reason.trim(),
      );
      setMessage("Password reset and sessions revoked.");
      closeResetDialog();
      await onRefresh?.();
    } catch (err) {
      setError(err.message || "Password reset failed");
      setResetForm((current) => ({ ...current, password: "", confirmation: "" }));
    } finally {
      setBusyAction("");
    }
  }

  async function submitReasonAction(event) {
    event.preventDefault();
    if (!actionDialog) {
      return;
    }
    const reasonError = validateReason(actionDialog.reason);
    if (reasonError) {
      setActionDialog({
        ...actionDialog,
        errors: { reason: reasonError },
      });
      return;
    }
    const { action, user, reason } = actionDialog;
    setActionDialog(null);
    await runMutation(`${action}:${user.id}`, async () => {
      if (action === "disable") {
        await disableUser(user.id, reason.trim());
        setMessage("User disabled.");
      } else {
        await revokeUserSessions(user.id, reason.trim());
        setMessage("Sessions revoked.");
      }
    });
  }

  if (loading) {
    return (
      <section className="page-section">
        <div className="section-heading">
          <h2>Users</h2>
          <p>Loading users...</p>
        </div>
      </section>
    );
  }

  return (
    <section className="page-section">
      <div className="section-heading">
        <h2>Users</h2>
        <p>{users.length} user(s)</p>
      </div>
      {message && <div className="success-banner">{message}</div>}
      {error && <div className="error-banner">{error}</div>}

      <div className="users-layout">
        <form className="action-panel user-create-panel" onSubmit={create}>
          <h3>Create user</h3>
          <label>
            Username
            <input
              aria-describedby="create-username-error"
              aria-invalid={Boolean(fieldErrors.username)}
              autoComplete="username"
              maxLength={LIMITS.usernameMax}
              onChange={(event) => updateCreateField("username", event.target.value)}
              required
              value={form.username}
            />
            <FieldError id="create-username-error" message={fieldErrors.username} />
          </label>
          <label>
            Display name
            <input
              aria-describedby="create-display-error"
              aria-invalid={Boolean(fieldErrors.display_name)}
              maxLength={LIMITS.displayNameMax}
              onChange={(event) => updateCreateField("display_name", event.target.value)}
              value={form.display_name}
            />
            <FieldError id="create-display-error" message={fieldErrors.display_name} />
          </label>
          <label>
            Role
            <select
              aria-describedby="create-role-error"
              aria-invalid={Boolean(fieldErrors.role)}
              onChange={(event) => updateCreateField("role", event.target.value)}
              value={form.role}
            >
              <option value="VIEWER">VIEWER</option>
              <option value="ADMIN">ADMIN</option>
            </select>
            <FieldError id="create-role-error" message={fieldErrors.role} />
          </label>
          <label>
            Password
            <input
              aria-describedby="create-password-error"
              aria-invalid={Boolean(fieldErrors.password)}
              autoComplete="new-password"
              maxLength={LIMITS.passwordMax}
              minLength={LIMITS.passwordMin}
              onChange={(event) => updateCreateField("password", event.target.value)}
              required
              type="password"
              value={form.password}
            />
            <small>Minimum {LIMITS.passwordMin} characters.</small>
            <FieldError id="create-password-error" message={fieldErrors.password} />
          </label>
          <label>
            Confirm password
            <input
              aria-describedby="create-confirmation-error"
              aria-invalid={Boolean(fieldErrors.confirmation)}
              autoComplete="new-password"
              maxLength={LIMITS.passwordMax}
              minLength={LIMITS.passwordMin}
              onChange={(event) => updateCreateField("confirmation", event.target.value)}
              required
              type="password"
              value={form.confirmation}
            />
            <FieldError id="create-confirmation-error" message={fieldErrors.confirmation} />
          </label>
          <button className="secondary-action" disabled={creating} type="submit">
            {creating ? "Creating..." : "Create User"}
          </button>
        </form>

        <div className="table-shell users-table">
        <table>
          <thead>
            <tr>
              <th>Username</th>
              <th>Role</th>
              <th>Enabled</th>
              <th>Last login</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {users.length === 0 ? (
              <tr>
                <td colSpan="5">No users.</td>
              </tr>
            ) : (
              userPagination.pageItems.map((user) => {
                const finalAdmin = isFinalEnabledAdmin(user, users);
                const lastAdminReason = finalAdmin
                  ? "At least one enabled ADMIN is required."
                  : undefined;
                return (
                  <tr key={user.id}>
                    <td>
                      <strong>{user.username}</strong>
                      <small>{user.display_name || ""}</small>
                    </td>
                    <td>
                      <span className="badge badge-muted">{user.role}</span>
                    </td>
                    <td>{user.enabled ? "yes" : "no"}</td>
                    <td>{formatDate(user.last_login_at)}</td>
                    <td>
                      <div className="button-row compact-buttons">
                        <button
                          disabled={Boolean(busyAction) || (user.role === "ADMIN" && finalAdmin)}
                          onClick={() => run("role", user)}
                          title={user.role === "ADMIN" ? lastAdminReason : undefined}
                          type="button"
                        >
                          Make {user.role === "ADMIN" ? "VIEWER" : "ADMIN"}
                        </button>
                        {user.enabled ? (
                          <button
                            disabled={Boolean(busyAction) || finalAdmin}
                            onClick={() => run("disable", user)}
                            title={lastAdminReason}
                            type="button"
                          >
                            Disable
                          </button>
                        ) : (
                          <button
                            disabled={Boolean(busyAction)}
                            onClick={() => run("enable", user)}
                            type="button"
                          >
                            Enable
                          </button>
                        )}
                        <button
                          disabled={Boolean(busyAction)}
                          onClick={() => run("reset", user)}
                          type="button"
                        >
                          Reset Password
                        </button>
                        <button
                          disabled={Boolean(busyAction)}
                          onClick={() => run("revoke", user)}
                          type="button"
                        >
                          Revoke Sessions
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
        </div>
        <Pagination
          label="Users"
          onPageChange={userPagination.setPage}
          page={userPagination.page}
          pageCount={userPagination.pageCount}
          total={userPagination.total}
        />
      </div>
      {resetTarget && (
        <div className="modal-backdrop" role="presentation">
          <section aria-modal="true" className="modal-panel" role="dialog">
            <h3>Reset Password</h3>
            <p>{resetTarget.username}</p>
            <form className="form-grid" onSubmit={submitPasswordReset}>
              <label>
                New temporary password
                <input
                  aria-describedby="reset-password-error"
                  aria-invalid={Boolean(resetErrors.password)}
                  autoComplete="new-password"
                  maxLength={LIMITS.passwordMax}
                  minLength={LIMITS.passwordMin}
                  onChange={(event) => updateResetField("password", event.target.value)}
                  required
                  type="password"
                  value={resetForm.password}
                />
                <FieldError id="reset-password-error" message={resetErrors.password} />
              </label>
              <label>
                Confirm password
                <input
                  aria-describedby="reset-confirmation-error"
                  aria-invalid={Boolean(resetErrors.confirmation)}
                  autoComplete="new-password"
                  maxLength={LIMITS.passwordMax}
                  minLength={LIMITS.passwordMin}
                  onChange={(event) => updateResetField("confirmation", event.target.value)}
                  required
                  type="password"
                  value={resetForm.confirmation}
                />
                <FieldError
                  id="reset-confirmation-error"
                  message={resetErrors.confirmation}
                />
              </label>
              <label>
                Reason
                <input
                  aria-describedby="reset-reason-error"
                  aria-invalid={Boolean(resetErrors.reason)}
                  maxLength={LIMITS.reasonMax}
                  minLength={LIMITS.reasonMin}
                  onChange={(event) => updateResetField("reason", event.target.value)}
                  required
                  value={resetForm.reason}
                />
                <FieldError id="reset-reason-error" message={resetErrors.reason} />
              </label>
              <div className="button-row">
                <button
                  className="secondary-action"
                  disabled={Boolean(busyAction)}
                  type="submit"
                >
                  {busyAction.startsWith("reset:") ? "Resetting..." : "Reset Password"}
                </button>
                <button disabled={Boolean(busyAction)} onClick={closeResetDialog} type="button">
                  Cancel
                </button>
              </div>
            </form>
          </section>
        </div>
      )}
      {actionDialog && (
        <div className="modal-backdrop" role="presentation">
          <section aria-modal="true" className="modal-panel" role="dialog">
            <h3>{actionDialog.title}</h3>
            <form className="form-grid" onSubmit={submitReasonAction}>
              <label className="wide-field">
                {actionDialog.label}
                <input
                  aria-describedby="action-reason-error"
                  aria-invalid={Boolean(actionDialog.errors.reason)}
                  maxLength={LIMITS.reasonMax}
                  minLength={LIMITS.reasonMin}
                  onChange={(event) =>
                    setActionDialog({
                      ...actionDialog,
                      reason: event.target.value,
                      errors: clearFieldError(actionDialog.errors, "reason"),
                    })
                  }
                  required
                  value={actionDialog.reason}
                />
                <FieldError id="action-reason-error" message={actionDialog.errors.reason} />
              </label>
              <div className="button-row">
                <button className="secondary-action" type="submit">
                  Confirm
                </button>
                <button onClick={() => setActionDialog(null)} type="button">
                  Cancel
                </button>
              </div>
            </form>
          </section>
        </div>
      )}
    </section>
  );
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

export default Users;
