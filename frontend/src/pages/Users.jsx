import { useState } from "react";
import {
  createUser,
  disableUser,
  enableUser,
  resetUserPassword,
  revokeUserSessions,
  updateUser,
} from "../api/client";

function Users({ users = [], loading = false, onRefresh }) {
  const [form, setForm] = useState({
    username: "",
    password: "",
    role: "VIEWER",
    display_name: "",
  });
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [resetTarget, setResetTarget] = useState(null);
  const [resetForm, setResetForm] = useState({
    password: "",
    confirmation: "",
    reason: "",
  });

  async function create(event) {
    event.preventDefault();
    setMessage("");
    setError("");
    try {
      await createUser({
        username: form.username,
        password: form.password,
        role: form.role,
        display_name: form.display_name || null,
      });
      setForm({ username: "", password: "", role: "VIEWER", display_name: "" });
      setMessage("User created.");
      await onRefresh?.();
    } catch (err) {
      setError(err.message || "User creation failed");
    }
  }

  async function run(action, user) {
    setMessage("");
    setError("");
    try {
      if (action === "role") {
        const role = user.role === "ADMIN" ? "VIEWER" : "ADMIN";
        if (
          role === "ADMIN" &&
          !window.confirm(`Grant ADMIN privileges to ${user.username}?`)
        ) {
          return;
        }
        await updateUser(user.id, { role });
        setMessage(`Role changed to ${role}.`);
      } else if (action === "enable") {
        await enableUser(user.id);
        setMessage("User enabled.");
      } else if (action === "disable") {
        const reason = window.prompt("Disable reason");
        if (!reason) {
          return;
        }
        await disableUser(user.id, reason);
        setMessage("User disabled.");
      } else if (action === "reset") {
        setResetTarget(user);
        setResetForm({ password: "", confirmation: "", reason: "" });
        return;
      } else if (action === "revoke") {
        const reason = window.prompt("Session revocation reason");
        if (!reason) {
          return;
        }
        await revokeUserSessions(user.id, reason);
        setMessage("Sessions revoked.");
      }
      await onRefresh?.();
    } catch (err) {
      setError(err.message || "User operation failed");
    }
  }

  function closeResetDialog() {
    setResetTarget(null);
    setResetForm({ password: "", confirmation: "", reason: "" });
  }

  async function submitPasswordReset(event) {
    event.preventDefault();
    setMessage("");
    setError("");
    if (resetForm.password !== resetForm.confirmation) {
      setError("Password confirmation does not match.");
      setResetForm({ ...resetForm, password: "", confirmation: "" });
      return;
    }
    try {
      await resetUserPassword(resetTarget.id, resetForm.password, resetForm.reason);
      setMessage("Password reset and sessions revoked.");
      closeResetDialog();
      await onRefresh?.();
    } catch (err) {
      setError(err.message || "Password reset failed");
      setResetForm({ ...resetForm, password: "", confirmation: "" });
    }
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

      <form className="action-panel form-grid" onSubmit={create}>
        <label>
          Username
          <input
            onChange={(event) => setForm({ ...form, username: event.target.value })}
            required
            value={form.username}
          />
        </label>
        <label>
          Display name
          <input
            onChange={(event) => setForm({ ...form, display_name: event.target.value })}
            value={form.display_name}
          />
        </label>
        <label>
          Role
          <select
            onChange={(event) => setForm({ ...form, role: event.target.value })}
            value={form.role}
          >
            <option value="VIEWER">VIEWER</option>
            <option value="ADMIN">ADMIN</option>
          </select>
        </label>
        <label>
          Password
          <input
            autoComplete="new-password"
            onChange={(event) => setForm({ ...form, password: event.target.value })}
            required
            type="password"
            value={form.password}
          />
        </label>
        <button className="secondary-action" type="submit">
          Create User
        </button>
      </form>

      <div className="table-shell">
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
              users.map((user) => (
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
                      <button onClick={() => run("role", user)} type="button">
                        Make {user.role === "ADMIN" ? "VIEWER" : "ADMIN"}
                      </button>
                      {user.enabled ? (
                        <button onClick={() => run("disable", user)} type="button">
                          Disable
                        </button>
                      ) : (
                        <button onClick={() => run("enable", user)} type="button">
                          Enable
                        </button>
                      )}
                      <button onClick={() => run("reset", user)} type="button">
                        Reset Password
                      </button>
                      <button onClick={() => run("revoke", user)} type="button">
                        Revoke Sessions
                      </button>
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
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
                  autoComplete="new-password"
                  onChange={(event) =>
                    setResetForm({ ...resetForm, password: event.target.value })
                  }
                  required
                  type="password"
                  value={resetForm.password}
                />
              </label>
              <label>
                Confirm password
                <input
                  autoComplete="new-password"
                  onChange={(event) =>
                    setResetForm({ ...resetForm, confirmation: event.target.value })
                  }
                  required
                  type="password"
                  value={resetForm.confirmation}
                />
              </label>
              <label>
                Reason
                <input
                  onChange={(event) =>
                    setResetForm({ ...resetForm, reason: event.target.value })
                  }
                  required
                  value={resetForm.reason}
                />
              </label>
              <div className="button-row">
                <button className="secondary-action" type="submit">
                  Reset Password
                </button>
                <button onClick={closeResetDialog} type="button">
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

function formatDate(value) {
  if (!value) {
    return "-";
  }
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
}

export default Users;
