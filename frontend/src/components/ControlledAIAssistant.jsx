import { useLayoutEffect, useMemo, useRef, useState } from "react";

import {
  requestControlledAIAssistance,
  safeErrorMessage,
} from "../api/client";
import { createAdvisoryResponseGuard } from "../utils/advisoryResponseGuard";


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
  const guardRef = useRef(null);
  if (guardRef.current === null) {
    guardRef.current = createAdvisoryResponseGuard();
  }
  const contextKey = JSON.stringify([
    tool?.id ?? null,
    tool?.current_fingerprint ?? null,
    currentAnalysis?.id ?? null,
    isAdmin,
  ]);

  useLayoutEffect(() => {
    guardRef.current.activate(contextKey);
    setBusy(false);
    setResult(null);
    setError("");
    setQuestion("");
    setMode("EXPLAIN");
    return () => guardRef.current.invalidate();
  }, [contextKey]);

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
    const request = guardRef.current.begin(contextKey);
    if (!request) return;
    setBusy(true);
    setError("");
    setResult(null);
    try {
      const payload = {
        mode,
        question: question.trim() || null,
      };
      const response = await requestControlledAIAssistance(tool.id, payload);
      if (guardRef.current.accepts(request, contextKey)) {
        setResult(response);
      }
    } catch (err) {
      if (guardRef.current.accepts(request, contextKey)) {
        setError(safeErrorMessage(err));
      }
    } finally {
      if (guardRef.current.accepts(request, contextKey)) {
        setBusy(false);
      }
    }
  }

  return (
    <section className="controlled-ai-panel" aria-label="Controlled AI assistance">
      <div className="controlled-ai-guardrail">
        <div><strong>AI explanation</strong><span>Helpful guidance, not a security decision.</span></div>
      </div>
      <details className="operator-technical-details">
        <summary>Analysis context</summary>
        <div className="controlled-ai-context">
          <div><span>Evidence</span><strong>{evidenceSummary}</strong></div>
          <div><span>Tool fingerprint</span><strong title={tool?.current_fingerprint || ""}>{shorten(tool?.current_fingerprint)}</strong></div>
          <div><span>Evidence status</span><strong>{contextFresh ? "Current" : "Out of date or unavailable"}</strong></div>
        </div>
      </details>
      {!isAdmin && (
        <div className="empty-state compact-empty-state">
          Only an administrator can request an AI explanation.
        </div>
      )}

      {isAdmin && (
        <form className="controlled-ai-form" onSubmit={submit}>
          <p className="hint-text" role="note">
            Uses your configured AI provider. Analysis data may be shared with it.
          </p>
          <details className="operator-technical-details">
            <summary>Ask a specific question or choose another type of help</summary>
            <label>
              Type of help
              <select disabled={busy} onChange={(event) => {
                setMode(event.target.value);
                setResult(null);
              }} value={mode}>
                {MODES.map(([value, label]) => (
                  <option key={value} value={value}>{label}</option>
                ))}
              </select>
            </label>
            <label className="wide-field">
              Your question (optional)
              <textarea disabled={busy} maxLength="1000"
                onChange={(event) => setQuestion(event.target.value)}
                placeholder="What would you like to understand?"
                value={question} />
            </label>
            <p className="hint-text">Do not enter passwords or secrets.</p>
          </details>
          <button disabled={!canAsk} type="submit">
            {busy ? "Explaining..." : "Explain this result"}
          </button>
          {!contextFresh && (
            <p role="status">A current analysis is needed before AI can explain it.</p>
          )}
        </form>
      )}

      {error && <div className="error-banner">{error}</div>}
      {result && <ControlledAIResult result={result} />}
    </section>
  );
}


function ControlledAIResult({ result }) {
  const safeResult = result.non_authoritative === true
    && result.requires_human_review === true
    && result.can_mutate_runtime === false;
  return (
    <div className="controlled-ai-result">
      <h4>AI explanation</h4>
      {!safeResult && (
        <p className="error-banner" role="alert">
          This response does not meet the expected safety restrictions. Do not use it for a security decision.
        </p>
      )}
      <section className="controlled-ai-section">
        <h5>What it means</h5>
        <p>{result.summary}</p>
      </section>
      <section className="controlled-ai-section">
        <h5>What to review</h5>
        <p>{result.rationale}</p>
      </section>
      <p className="hint-text">AI suggestions must be checked by an administrator.</p>
      <details className="operator-technical-details">
        <summary>Supporting evidence and advanced options</summary>
        <div className="controlled-ai-result-heading">
          <div><span>Mode</span><strong>{humanize(result.mode)}</strong></div>
          <div className="controlled-ai-provider">
            <strong>{result.provider}</strong>
            <span>{result.fallback_used ? "Fallback provider" : "Configured provider"}</span>
          </div>
        </div>
        <p>Suggested action: {humanize(result.recommended_action)}.
          Reported confidence: {formatConfidence(result.confidence)}.</p>
        <StringList title="Risk factors" values={result.risk_factors} />
        <StringList title="Uncertainties" values={result.uncertainties} />
        <StringList title="Evidence references" values={result.evidence_refs} />
        <OptionList title="Template options" values={result.template_options} />
        <OptionList title="Adapter options" values={result.adapter_options} />
        {result.draft_kind !== "NONE" && (
          <section className="controlled-ai-section">
            <h5>Unapproved draft preview ? {humanize(result.draft_kind)}</h5>
            <p>This is not a published configuration or permission.</p>
            <pre className="controlled-ai-preview">{JSON.stringify(result.draft_preview, null, 2)}</pre>
          </section>
        )}
      </details>
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
