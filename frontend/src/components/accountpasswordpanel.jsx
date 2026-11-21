import { useState } from "react";

import { changeOwnPassword, safeErrorMessage } from "../api/client";

export default function AccountPasswordPanel({ onChanged, onClose }) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(event) {
    event.preventDefault();
    if (busy) return;
    if (next.length < 8 || next.length > 4096) {
      setError("The new password must contain at least eight characters.");
      return;
    }
    if (next !== confirm) {
      setError("The new password and confirmation do not match.");
      return;
    }
    if (current === next) {
      setError("Choose a different password.");
      return;
    }
    setError("");
    setBusy(true);
    try {
      const result = await changeOwnPassword(current, next);
      if (result?.ok !== true) throw new Error("Password update not confirmed.");
      setCurrent(""); setNext(""); setConfirm("");
      onChanged?.();
    } catch (err) {
      setError(safeErrorMessage(err) || "Password update failed; check the current password.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="detail-panel account-password-panel" aria-label="Change your password">
      <h3>Change your password</h3>
      <p>This is your personal account setting, available to ADMIN and VIEWER.
        The backend verifies your current password. After a successful change,
        all existing sessions are revoked and you must sign in again.</p>
      <form className="form-grid" onSubmit={submit}>
        <label>Current password
          <input required autoComplete="current-password" type="password"
            value={current} maxLength={4096} disabled={busy}
            onChange={(event) => setCurrent(event.target.value)} />
        </label>
        <label>New password
          <input required autoComplete="new-password" type="password"
            value={next} minLength={8} maxLength={4096} disabled={busy}
            onChange={(event) => setNext(event.target.value)} />
        </label>
        <label>Confirm new password
          <input required autoComplete="new-password" type="password"
            value={confirm} minLength={8} maxLength={4096} disabled={busy}
            onChange={(event) => setConfirm(event.target.value)} />
        </label>
        {error && <p className="error-banner" role="alert">{error}</p>}
        <div className="button-row">
          <button disabled={busy} type="submit">
            {busy ? "Updating..." : "Update password and revoke sessions"}
          </button>
          <button type="button" disabled={busy} onClick={onClose}>Cancel</button>
        </div>
      </form>
    </section>
  );
}
