import { useLayoutEffect, useRef, useState } from "react";

import { changeOwnPassword, safeErrorMessage } from "../api/client";
import { useDialogFocus } from "../utils/useDialogFocus";

export default function AccountPasswordPanel({ onChanged, onClose }) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const modalRef = useRef(null);
  useDialogFocus(true, modalRef, { focusContainer: true });

  useLayoutEffect(() => {
    const modal = modalRef.current;
    if (!modal.contains(document.activeElement)) modal.focus();
  }, [busy]);

  async function submit(event) {
    event.preventDefault();
    if (busy) return;
    if (next.length < 8 || next.length > 4096) {
      setError("The new password must contain between 8 and 4,096 characters.");
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
      setError(err?.code === "Invalid password"
        ? "The current password is incorrect."
        : safeErrorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="modal-backdrop">
      <section className="modal-panel account-password-panel" role="dialog" aria-modal="true"
        aria-labelledby="account-password-title" aria-describedby="account-password-impact"
        tabIndex={-1} ref={modalRef} onKeyDown={(event) => {
          if (event.key === "Escape" && !busy) onClose();
        }}>
        <h2 id="account-password-title">Change your password</h2>
        <p id="account-password-impact">A successful password change signs you out of every session.
          Sign in again with your new password.</p>
        <form className="form-grid" onSubmit={submit} aria-busy={busy}>
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
          <div className="button-row">
            <button disabled={busy} type="submit">
              {busy ? "Updating…" : "Update password and revoke sessions"}
            </button>
            <button type="button" disabled={busy} onClick={onClose}>Cancel</button>
          </div>
        </form>
        {error && <p className="error-banner" role="alert">{error}</p>}
      </section>
    </div>
  );
}
