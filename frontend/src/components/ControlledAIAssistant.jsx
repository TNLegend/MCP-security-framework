import { useEffect, useMemo, useState } from "react";

import {
  requestControlledAIAssistance,
  safeErrorMessage,
} from "../api/client";


const MODES = [
  ["EXPLAIN", "Explain decision"],
  ["RISK_SUMMARY", "Risk summary"],
  ["SUGGEST_NEXT_STEP", "Suggest next step"],
  ["COMPARE_OPTIONS", "Compare options"],
  ["DRAFT_ONBOARDING", "Draft onboarding"],
];


function ControlledAIAssistant({ bundle, isAdmin = false, tool }) {
  const [mode, setMode] = useState("EXPLAIN");
  const [question, setQuestion] = useState("");
  const [result, setResult] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const currentAnalysis = bundle?.analyses?.[0] || null;
  const contextFresh = Boolean(
    tool?.current_fingerprint
      && currentAnalysis?.fingerprint
      && tool.current_fingerprint === currentAnalysis.fingerprint,
  );
  const canAsk = Boolean(isAdmin && tool?.id && contextFresh && !busy);

  useEffect(() => {
    setResult(null);
    setError("");
    setQuestion("");
    setMode("EXPLAIN");
  }, [tool?.id, tool?.current_fingerprint]);

  const evidenceSummary = useMemo(() => {
    if (!currentAnalysis) return "No completed analysis evidence is loaded.";
    return [
      currentAnalysis.analysis_status,
      currentAnalysis.risk_level,
      currentAnalysis.drift_status,
    ].filter(Boolean).join(" / ");
  }, [currentAnalysis]);

  async function submit(event) {
    event.preventDefault();
    if (!canAsk) return;
    setBusy(true);
    setError("");
    setResult(null);
    try {
      const payload = {
        mode,
        question: question.trim() || null,
      };
      setResult(await requestControlledAIAssistance(tool.id, payload));
    } catch (err) {
      setError(safeErrorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="controlled-ai-panel" aria-label="Controlled AI assistance">
      <div className="controlled-ai-guardrail">
        <div>
          <strong>Advisory only</strong>
          <span>AI output never substitutes for administrator review.</span>
        </div>
        <p>
          AI cannot approve tools, publish configuration, grant capabilities, install or sign
          adapters, modify OPA, execute MCP tools, or disable Emergency Deny.
        </p>
      </div>

      <div className="controlled-ai-context">
        <div>
          <span>Evidence context</span>
          <strong>{evidenceSummary}</strong>
        </div>
        <div>
          <span>Fingerprint</span>
          <strong title={tool?.current_fingerprint || ""}>
            {shorten(tool?.current_fingerprint)}
          </strong>
        </div>
        <div>
          <span>Context freshness</span>
          <strong>{contextFresh ? "Current" : "Stale / unavailable"}</strong>
        </div>
      </div>

      {!isAdmin && (
        <div className="empty-state compact-empty-state">
          Controlled AI requests are ADMIN-only because analysis evidence may be sent to an
          external configured provider.
        </div>
      )}

      {isAdmin && (
        <form className="controlled-ai-form" onSubmit={submit}>
          <label>
            Assistance mode
            <select
              disabled={busy}
              onChange={(event) => {
                setMode(event.target.value);
                setResult(null);
              }}
              value={mode}
            >
              {MODES.map(([value, label]) => (
                <option key={value} value={value}>{label}</option>
              ))}
            </select>
          </label>
          <label className="wide-field">
            Optional operator question
            <textarea
              disabled={busy}
              maxLength="1000"
              onChange={(event) => setQuestion(event.target.value)}
              placeholder="Ask for clarification without asking the AI to make the security decision."
              value={question}
            />
          </label>
          <div className="button-row">
            <button disabled={!canAsk} type="submit">
              {busy ? "Generating advisory..." : "Generate advisory"}
            </button>
          </div>
          {!contextFresh && (
            <p className="hint-text">
              A completed analysis matching the tool's current fingerprint is required before AI
              assistance can run.
            </p>
          )}
        </form>
      )}

      {error && <div className="error-banner">{error}</div>}
      {result && <ControlledAIResult result={result} />}
    </section>
  );
}


function ControlledAIResult({ result }) {
  return (
    <div className="controlled-ai-result">
      <div className="controlled-ai-result-heading">
        <div>
          <span>Controlled advisory</span>
          <h4>{humanize(result.mode)}</h4>
        </div>
        <div className="controlled-ai-provider">
          <strong>{result.provider}</strong>
          <span>{result.fallback_used ? "fallback provider" : "primary provider"}</span>
        </div>
      </div>

      <div className="controlled-ai-safety-row">
        <span>{result.non_authoritative ? "Non-authoritative" : "Unexpected authority state"}</span>
        <span>{result.requires_human_review ? "AI output requires human review" : "AI review guard invalid"}</span>
        <span>{result.can_mutate_runtime ? "Mutation unexpectedly enabled" : "No runtime mutation"}</span>
      </div>

      <section className="controlled-ai-section">
        <h5>Summary</h5>
        <p>{result.summary}</p>
      </section>

      <section className="controlled-ai-section">
        <h5>Framework-recommended human action</h5>
        <strong>{humanize(result.recommended_action)}</strong>
        <p>{result.rationale}</p>
        <small>Confidence: {formatConfidence(result.confidence)}</small>
      </section>

      <StringList title="Risk factors" values={result.risk_factors} />
      <OptionList title="Template options" values={result.template_options} />
      <OptionList title="Adapter options" values={result.adapter_options} />
      <StringList title="Evidence references" values={result.evidence_refs} />
      <StringList title="Uncertainties" values={result.uncertainties} />

      {result.draft_kind !== "NONE" && (
        <section className="controlled-ai-section">
          <h5>Non-authoritative draft preview · {humanize(result.draft_kind)}</h5>
          <p>
            This preview is not a Control Plane DRAFT and cannot become active until an
            administrator explicitly uses the normal Contract / Security Pack workflow.
          </p>
          <pre className="controlled-ai-preview">
            {JSON.stringify(result.draft_preview, null, 2)}
          </pre>
        </section>
      )}
    </div>
  );
}


function StringList({ title, values = [] }) {
  if (!values?.length) return null;
  return (
    <section className="controlled-ai-section">
      <h5>{title}</h5>
      <ul>
        {values.map((value, index) => <li key={`${title}-${index}-${value}`}>{value}</li>)}
      </ul>
    </section>
  );
}


function OptionList({ title, values = [] }) {
  if (!values?.length) return null;
  return (
    <section className="controlled-ai-section">
      <h5>{title}</h5>
      <div className="controlled-ai-options">
        {values.map((value) => (
          <article key={value.id}>
            <strong>{value.title}</strong>
            <span>{value.id}</span>
            <p>{value.reason}</p>
          </article>
        ))}
      </div>
    </section>
  );
}


function shorten(value) {
  if (!value) return "-";
  return value.length > 18 ? `${value.slice(0, 12)}...${value.slice(-6)}` : value;
}


function humanize(value) {
  return String(value || "-").replaceAll("_", " ").toLowerCase().replace(
    /(^|\s)\S/g,
    (character) => character.toUpperCase(),
  );
}


function formatConfidence(value) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return "-";
  return `${Math.round(numeric * 100)}%`;
}


export default ControlledAIAssistant;
