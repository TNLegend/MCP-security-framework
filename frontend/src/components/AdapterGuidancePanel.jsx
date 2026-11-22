import { useEffect, useMemo, useState } from "react";
import {
  downloadTrustedAdapterStarter,
  safeErrorMessage,
} from "../api/client";


function AdapterGuidancePanel({ guidance, isAdmin, tool }) {
  const defaultAdapterId = useMemo(() => adapterIdForTool(tool?.name), [tool?.name]);
  const [adapterId, setAdapterId] = useState(defaultAdapterId);
  const [starterId, setStarterId] = useState("blank");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    setAdapterId(defaultAdapterId);
    setStarterId(
      guidance?.starters?.some((value) => value.starter_id === guidance.recommended_starter)
        ? guidance.recommended_starter
        : "blank",
    );
    setError("");
  }, [defaultAdapterId, guidance]);

  if (!guidance) return null;

  async function downloadStarter() {
    setBusy(true);
    setError("");
    try {
      const archive = await downloadTrustedAdapterStarter(starterId, adapterId.trim());
      const url = URL.createObjectURL(archive);
      const link = document.createElement("a");
      link.href = url;
      link.download = `${adapterId.trim()}-starter.zip`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
    } catch (err) {
      setError(safeErrorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="adapter-guidance" aria-label="Adapter compatibility">
      <div className="adapter-guidance-heading">
        <div>
          <strong>Adapter compatibility</strong>
          <span className="status-pill">{typeof guidance.status === "string"
            ? guidance.status.replaceAll("_", " ")
            : "Status unavailable"}</span>
        </div>
        <span>
          {guidance.generic_declarative_available
            ? "Declarative mapping available"
            : "Specialized review required"}
        </span>
      </div>

      <ul className="adapter-guidance-reasons">
        {(guidance.reasons || []).map((reason) => <li key={reason}>{reason}</li>)}
      </ul>

      {(guidance.closest_adapters || []).length > 0 ? (
        <div className="adapter-candidates">
          <strong>Closest trusted adapters</strong>
          {(guidance.closest_adapters || []).map((adapter) => (
            <div key={adapter.adapter_id}>
              <span>{adapter.display_name}</span>
              <small>{adapter.family} / {adapter.adapter_id} / {adapter.implementation_version}</small>
              <small>Signals: {adapter.matching_signals.join(", ")}</small>
            </div>
          ))}
        </div>
      ) : (
        <div className="empty-state compact-empty-state">
          No installed specialized adapter has corroborating signals. Start from the blank fail-closed SDK template.
        </div>
      )}

      {isAdmin && (
        <div className="adapter-starter-row">
          <label>
            Starter
            <select disabled={busy} onChange={(event) => setStarterId(event.target.value)} value={starterId}>
              {(guidance.starters || []).map((starter) => (
                <option key={starter.starter_id} value={starter.starter_id}>{starter.title}</option>
              ))}
            </select>
          </label>
          <label>
            Adapter ID
            <input
              disabled={busy}
              maxLength="128"
              onChange={(event) => setAdapterId(event.target.value)}
              pattern="[a-z0-9][a-z0-9._-]*"
              value={adapterId}
            />
          </label>
          <button
            className="secondary-action"
            disabled={busy || !/^[a-z0-9][a-z0-9._-]{0,127}$/.test(adapterId.trim())}
            onClick={downloadStarter}
            type="button"
          >
            {busy ? "Preparing..." : "Download Starter"}
          </button>
        </div>
      )}
      {error && <div className="error-banner">{error}</div>}
      <p className="field-help">
        Adapter code remains quarantined until it is reviewed, signed by a trusted maintainer, installed by an operator, and loaded by a controlled backend and Gateway restart.
      </p>
    </section>
  );
}


function adapterIdForTool(toolName) {
  const normalized = String(toolName || "custom")
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^[^a-z0-9]+/, "")
    .replace(/-+$/g, "") || "custom";
  return `${normalized.slice(0, 110)}-adapter`;
}


export default AdapterGuidancePanel;
