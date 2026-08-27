import { useState } from "react";
import { addDeclarativeSecurityPack, safeErrorMessage } from "../api/client";
import { declarativeManifestFromForm } from "./securityPackUtils";

const EMPTY_PACK = {
  packId: "",
  title: "",
  capabilityId: "",
  resourceTypeId: "",
  templateId: "",
  keywords: "",
  hints: "",
  destructive: false,
  externalEffect: false,
};

function SecurityPackManager({ onComplete, revision }) {
  const [form, setForm] = useState(EMPTY_PACK);
  const [summary, setSummary] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  if (!revision || revision.status !== "DRAFT" || revision.schema_version !== 2) {
    return null;
  }

  function update(field, value) {
    setForm((current) => ({ ...current, [field]: value }));
    setError("");
    setMessage("");
  }

  async function submit(event) {
    event.preventDefault();
    setBusy(true);
    setError("");
    setMessage("");
    try {
      await addDeclarativeSecurityPack({
        draft_revision_id: revision.id,
        change_summary: summary.trim(),
        manifest: declarativeManifestFromForm(form),
      });
      setMessage("Security Pack added to the draft.");
      setForm(EMPTY_PACK);
      setSummary("");
      await onComplete?.();
    } catch (err) {
      setError(safeErrorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  const capabilityValid = /^[a-z0-9][a-z0-9._:-]*\.[a-z0-9_-]+$/.test(form.capabilityId);
  return (
    <section className="security-pack-manager">
      <div className="section-heading compact-heading">
        <h3>Declarative Security Pack</h3>
        <p>Draft {revision.revision_number}</p>
      </div>
      {error && <div className="error-banner">{error}</div>}
      {message && <div className="success-banner">{message}</div>}
      <form className="security-pack-form" onSubmit={submit}>
        <label>Pack ID<input maxLength="128" onChange={(event) => update("packId", event.target.value)} pattern="[a-z0-9][a-z0-9._-]*" required value={form.packId} /></label>
        <label>Title<input maxLength="128" onChange={(event) => update("title", event.target.value)} required value={form.title} /></label>
        <label>Capability<input aria-invalid={form.capabilityId && !capabilityValid} maxLength="128" onChange={(event) => update("capabilityId", event.target.value)} pattern="[a-z0-9][a-z0-9._:-]*[.][a-z0-9_-]+" required value={form.capabilityId} /></label>
        <label>Resource type<input maxLength="128" onChange={(event) => update("resourceTypeId", event.target.value)} pattern="[a-z0-9][a-z0-9._:-]*" required value={form.resourceTypeId} /></label>
        <label>Template ID<input maxLength="128" onChange={(event) => update("templateId", event.target.value)} pattern="[a-z0-9][a-z0-9._:-]*" required value={form.templateId} /></label>
        <label>Keywords<input maxLength="500" onChange={(event) => update("keywords", event.target.value)} required value={form.keywords} /></label>
        <label>Argument hints<input maxLength="500" onChange={(event) => update("hints", event.target.value)} required value={form.hints} /></label>
        <label>Change summary<input maxLength="2000" minLength="3" onChange={(event) => setSummary(event.target.value)} required value={summary} /></label>
        <label className="checkbox-field"><input checked={form.destructive} onChange={(event) => update("destructive", event.target.checked)} type="checkbox" />Destructive</label>
        <label className="checkbox-field"><input checked={form.externalEffect} onChange={(event) => update("externalEffect", event.target.checked)} type="checkbox" />External effect</label>
        <button className="secondary-action" disabled={busy || !capabilityValid} type="submit">{busy ? "Adding..." : "Add to Draft"}</button>
      </form>
    </section>
  );
}

export default SecurityPackManager;
