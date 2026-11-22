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
import { assistantErrorMessage } from "../utils/controlledAI";

function ToolSecurityPackBuilder({ draftRevisionId, onCancel, onCreated, tool }) {
  const initialForm = useMemo(() => blankPackForTool(tool), [tool]);
  const [form, setForm] = useState(initialForm);
  const [mode, setMode] = useState("blank");
  const [advancedManifestText, setAdvancedManifestText] = useState(
    JSON.stringify(declarativeManifestFromForm(initialForm), null, 2),
  );
  const [summary, setSummary] = useState(`Create Security Pack for ${tool.name}`);
  const [uncertainties, setUncertainties] = useState([]);
  const [aiProposal, setAiProposal] = useState(null);
  const [aiApplied, setAiApplied] = useState(false);
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
    setAiProposal(null);
    setAiApplied(false);
    if (nextMode === "blank") {
      setForm(initialForm);
      return;
    }
    if (nextMode === "advanced") {
      setAdvancedManifestText(JSON.stringify(
        declarativeManifestFromForm(initialForm),
        null,
        2,
      ));
      return;
    }
    setBusy(true);
    try {
      const proposal = await fetchAIToolSecurityPackDraft(tool.id, draftRevisionId);
      setAiProposal({ form: packFormFromManifest(proposal.manifest), draftRevisionId });
      setUncertainties(proposal.uncertainties || []);
    } catch (err) {
      setError(assistantErrorMessage(err));
      // Keep the blank editor available when AI suggestions fail.
      setMode("blank");
    } finally {
      setBusy(false);
    }
  }

  function applyAiProposal() {
    if (!aiProposal || aiProposal.draftRevisionId !== draftRevisionId) return;
    setForm(aiProposal.form);
    setAiApplied(true);
    setAiProposal(null);
  }

  async function submit(event) {
    event.preventDefault();
    if (mode === "ai" && !aiApplied) return;
    setBusy(true);
    setError("");
    try {
      let manifest;
      if (mode === "advanced") {
        try {
          manifest = JSON.parse(advancedManifestText);
        } catch {
          throw new Error("Advanced manifest must be valid JSON.");
        }
      } else {
        manifest = declarativeManifestFromForm(form);
      }
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
          Preview with AI
        </button>
        <button
          aria-pressed={mode === "advanced"}
          className={mode === "advanced" ? "active-segment" : ""}
          disabled={busy}
          onClick={() => selectMode("advanced")}
          type="button"
        >
          Advanced JSON
        </button>
      </div>
      <p className="hint-text">AI-assisted drafting sends the tool description and input fields to the configured AI provider or its fallback. Review the proposal before adding it to a draft.</p>
      {mode === "ai" && busy && <p role="status">Requesting AI assistance…</p>}
      {error && <div className="error-banner" role="alert">{error}</div>}
      {uncertainties.length > 0 && (
        <div className="warning-banner" role="status">
          <strong>Uncertainties to review</strong>
          <ul>{uncertainties.map((uncertainty, index) => <li key={index}>{uncertainty}</li>)}</ul>
        </div>
      )}
      {aiProposal && <section className="detail-panel" aria-label="Security pack proposal preview">
        <strong>{aiProposal.form.title}</strong>
        <p><code>{aiProposal.form.packId}</code> · <code>{aiProposal.form.capabilityId}</code></p>
        <p>Template <code>{aiProposal.form.templateId}</code> · Resource type <code>{aiProposal.form.resourceTypeId}</code></p>
        {aiProposal.draftRevisionId === draftRevisionId ?
          <button type="button" disabled={busy} onClick={applyAiProposal}>Apply proposal to editor</button> :
          <p role="status">The draft changed. Preview the proposal again.</p>}
      </section>}
      <form className="tool-pack-form" onSubmit={submit}>
        {mode === "advanced" ? (
          <>
            <div className="warning-banner wide-field">
              Declarative JSON only. The backend validates identifiers, capabilities, resource types, effects and constraints before it can enter a draft.
            </div>
            <label className="wide-field">
              Advanced Security Pack manifest
              <textarea
                disabled={busy}
                onChange={(event) => setAdvancedManifestText(event.target.value)}
                rows="24"
                spellCheck="false"
                value={advancedManifestText}
              />
            </label>
          </>
        ) : (
          <>
            <label>Pack ID<input disabled={busy} maxLength="128" onChange={(event) => update("packId", event.target.value)} pattern="[a-z0-9][a-z0-9._-]*" required value={form.packId} /></label>
            <label>Title<input disabled={busy} maxLength="128" onChange={(event) => update("title", event.target.value)} required value={form.title} /></label>
            <label>Capability<input aria-invalid={form.capabilityId && !capabilityValid} disabled={busy} maxLength="128" onChange={(event) => update("capabilityId", event.target.value)} pattern="[a-z0-9][a-z0-9._:-]*[.][a-z0-9_-]+" required value={form.capabilityId} /></label>
            <label>Resource type<input disabled={busy} maxLength="128" onChange={(event) => update("resourceTypeId", event.target.value)} pattern="[a-z0-9][a-z0-9._:-]*" required value={form.resourceTypeId} /></label>
            <label>Template ID<input disabled={busy} maxLength="128" onChange={(event) => update("templateId", event.target.value)} pattern="[a-z0-9][a-z0-9._:-]*" required value={form.templateId} /></label>
            <label>Keywords<input disabled={busy} maxLength="500" onChange={(event) => update("keywords", event.target.value)} required value={form.keywords} /></label>
            <label>Argument hints<input disabled={busy} maxLength="500" onChange={(event) => update("hints", event.target.value)} value={form.hints} /></label>
            <label className="checkbox-field"><input checked={form.destructive} disabled={busy} onChange={(event) => update("destructive", event.target.checked)} type="checkbox" />Destructive</label>
            <label className="checkbox-field"><input checked={form.externalEffect} disabled={busy} onChange={(event) => update("externalEffect", event.target.checked)} type="checkbox" />External effect</label>
          </>
        )}
        <label className="wide-field">Change summary<input disabled={busy} maxLength="2000" minLength="3" onChange={(event) => setSummary(event.target.value)} required value={summary} /></label>
        <div className="button-row tool-pack-actions">
          <button disabled={busy} onClick={onCancel} type="button">Cancel</button>
          <button className="secondary-action" disabled={busy || (mode === "ai" && !aiApplied) || (mode !== "advanced" && !capabilityValid)} type="submit">
            {busy ? "Saving..." : "Save pack to draft"}
          </button>
        </div>
      </form>
    </section>
  );
}

export default ToolSecurityPackBuilder;
