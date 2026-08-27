import { useMemo, useState } from "react";
import {
  createToolSecurityPackDraft,
  fetchAIToolSecurityPackDraft,
  safeErrorMessage,
} from "../api/client";
import {
  blankPackForTool,
  declarativeManifestFromForm,
  packFormFromManifest,
} from "./securityPackUtils";

function ToolSecurityPackBuilder({ draftRevisionId, onCancel, onCreated, tool }) {
  const initialForm = useMemo(() => blankPackForTool(tool), [tool]);
  const [form, setForm] = useState(initialForm);
  const [mode, setMode] = useState("blank");
  const [summary, setSummary] = useState(`Create Security Pack for ${tool.name}`);
  const [uncertainties, setUncertainties] = useState([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const capabilityValid = /^[a-z0-9][a-z0-9._:-]*\.[a-z0-9_-]+$/.test(
    form.capabilityId,
  );

  function update(field, value) {
    setForm((current) => ({ ...current, [field]: value }));
    setError("");
  }

  async function selectMode(nextMode) {
    setMode(nextMode);
    setError("");
    setUncertainties([]);
    if (nextMode === "blank") {
      setForm(initialForm);
      return;
    }
    setBusy(true);
    try {
      const proposal = await fetchAIToolSecurityPackDraft(tool.id, draftRevisionId);
      setForm(packFormFromManifest(proposal.manifest));
      setUncertainties(proposal.uncertainties || []);
    } catch (err) {
      setError(safeErrorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  async function submit(event) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const manifest = declarativeManifestFromForm(form);
      const revision = await createToolSecurityPackDraft(tool.id, {
        manifest,
        draft_revision_id: draftRevisionId,
        change_summary: summary.trim(),
      });
      await onCreated?.({ manifest, revision });
    } catch (err) {
      setError(safeErrorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="tool-pack-builder">
      <div className="section-heading compact-heading">
        <h3>Create Security Pack</h3>
        <p>Declarative adapter only</p>
      </div>
      <div aria-label="Pack creation mode" className="segmented-control" role="group">
        <button
          aria-pressed={mode === "blank"}
          className={mode === "blank" ? "active-segment" : ""}
          disabled={busy}
          onClick={() => selectMode("blank")}
          type="button"
        >
          Blank
        </button>
        <button
          aria-pressed={mode === "ai"}
          className={mode === "ai" ? "active-segment" : ""}
          disabled={busy}
          onClick={() => selectMode("ai")}
          type="button"
        >
          AI-assisted
        </button>
      </div>
      {error && <div className="error-banner">{error}</div>}
      {uncertainties.length > 0 && (
        <div className="warning-banner">
          Review the AI proposal: {uncertainties.join("; ")}
        </div>
      )}
      <form className="tool-pack-form" onSubmit={submit}>
        <label>Pack ID<input disabled={busy} maxLength="128" onChange={(event) => update("packId", event.target.value)} pattern="[a-z0-9][a-z0-9._-]*" required value={form.packId} /></label>
        <label>Title<input disabled={busy} maxLength="128" onChange={(event) => update("title", event.target.value)} required value={form.title} /></label>
        <label>Capability<input aria-invalid={form.capabilityId && !capabilityValid} disabled={busy} maxLength="128" onChange={(event) => update("capabilityId", event.target.value)} pattern="[a-z0-9][a-z0-9._:-]*[.][a-z0-9_-]+" required value={form.capabilityId} /></label>
        <label>Resource type<input disabled={busy} maxLength="128" onChange={(event) => update("resourceTypeId", event.target.value)} pattern="[a-z0-9][a-z0-9._:-]*" required value={form.resourceTypeId} /></label>
        <label>Template ID<input disabled={busy} maxLength="128" onChange={(event) => update("templateId", event.target.value)} pattern="[a-z0-9][a-z0-9._:-]*" required value={form.templateId} /></label>
        <label>Keywords<input disabled={busy} maxLength="500" onChange={(event) => update("keywords", event.target.value)} required value={form.keywords} /></label>
        <label>Argument hints<input disabled={busy} maxLength="500" onChange={(event) => update("hints", event.target.value)} required value={form.hints} /></label>
        <label>Change summary<input disabled={busy} maxLength="2000" minLength="3" onChange={(event) => setSummary(event.target.value)} required value={summary} /></label>
        <label className="checkbox-field"><input checked={form.destructive} disabled={busy} onChange={(event) => update("destructive", event.target.checked)} type="checkbox" />Destructive</label>
        <label className="checkbox-field"><input checked={form.externalEffect} disabled={busy} onChange={(event) => update("externalEffect", event.target.checked)} type="checkbox" />External effect</label>
        <div className="button-row tool-pack-actions">
          <button disabled={busy} onClick={onCancel} type="button">Cancel</button>
          <button className="secondary-action" disabled={busy || !capabilityValid} type="submit">
            {busy ? "Adding..." : "Add to Draft"}
          </button>
        </div>
      </form>
    </section>
  );
}

export default ToolSecurityPackBuilder;
