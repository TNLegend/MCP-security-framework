import { useLayoutEffect, useRef, useState } from "react";

import { requestControlledAIAssistance } from "../api/client";
import { createAdvisoryResponseGuard } from "../utils/advisoryResponseGuard";
import { assistantErrorMessage, currentAssistantAnalysis, matchesAssistantResponse } from "../utils/controlledAI";


const MODES = [
  ["EXPLAIN", "Explain decision"],
  ["RISK_SUMMARY", "Risk summary"],
  ["SUGGEST_NEXT_STEP", "Suggest next step"],
  ["COMPARE_OPTIONS", "Compare options"],
  ["DRAFT_ONBOARDING", "Draft onboarding"],
];

const ACTIONS = {
  NO_CHANGE: "Keep the current configuration",
  KEEP_BLOCKED: "Keep the tool blocked",
  HUMAN_REVIEW: "Review the current findings and approval state",
  CREATE_CONTRACT_DRAFT: "Review the proposed contract draft",
  CREATE_SECURITY_PACK_DRAFT: "Review the proposed security pack draft",
  REVIEW_ADAPTER: "Review the adapter with an administrator",
  REANALYZE: "Run the tool analysis again",
};

function ControlledAIAssistant({ bundle, isAdmin = false, tool }) {
  const [mode, setMode] = useState("EXPLAIN");
  const [question, setQuestion] = useState("");
  const [result, setResult] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const currentAnalysis = bundle?.analyses?.[0] || null;
  const expectedAnalysis = currentAssistantAnalysis(tool, currentAnalysis);
  const canAsk = Boolean(isAdmin && tool?.id && expectedAnalysis && !busy);
  const guardRef = useRef(null);
  if (guardRef.current === null) {
    guardRef.current = createAdvisoryResponseGuard();
  }
  const contextKey = JSON.stringify([
    tool?.id ?? null,
    tool?.current_fingerprint ?? null,
    expectedAnalysis,
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
        expected_analysis: expectedAnalysis,
      };
      const response = await requestControlledAIAssistance(tool.id, payload);
      if (guardRef.current.accepts(request, contextKey)) {
        if (matchesAssistantResponse(response, tool.id, mode, expectedAnalysis)) {
          setResult(response);
        } else {
          setError(assistantErrorMessage({ code: "controlled_ai_analysis_changed" }));
        }
      }
    } catch (err) {
      if (guardRef.current.accepts(request, contextKey)) {
        setError(assistantErrorMessage(err));
      }
    } finally {
      if (guardRef.current.accepts(request, contextKey)) {
        setBusy(false);
      }
    }
  }

  return (
    <section className="controlled-ai-panel" aria-label="AI assistance">
      <div className="controlled-ai-guardrail">
        <div><strong>AI assistance</strong><span>Explore the selected tool’s analysis or review possible next steps.</span></div>
      </div>
      <dl className="inline-metadata">
        <div><dt>Analysis</dt><dd>{expectedAnalysis ? humanize(currentAnalysis.analysis_status) : "Current analysis unavailable"}</dd></div>
        <div><dt>Review</dt><dd>{expectedAnalysis ? humanize(currentAnalysis.review_status) : "Unavailable"}</dd></div>
      </dl>
      {bundle?.errors?.findings && (
        <p role="status">The findings could not be loaded in this view. Check the Findings tab before acting on advice.</p>
      )}
      <details className="operator-technical-details">
        <summary>Technical details</summary>
        <div className="controlled-ai-context">
          <div><span>Analysis record</span><strong>{expectedAnalysis?.id ?? "Unavailable"}</strong></div>
          <div><span>Tool fingerprint</span><strong title={tool?.current_fingerprint || ""}>{shorten(tool?.current_fingerprint)}</strong></div>
          <div><span>Analysis context hash</span><strong title={expectedAnalysis?.context_hash || ""}>{shorten(expectedAnalysis?.context_hash)}</strong></div>
        </div>
      </details>
      {!isAdmin && (
        <div className="empty-state compact-empty-state">
          Only an administrator can request an AI explanation.
        </div>
      )}

      {isAdmin && (
        <form aria-busy={busy} className="controlled-ai-form" onSubmit={submit}>
          <p className="hint-text" role="note">
            Sends analysis metadata and your question to the configured AI provider and, if needed, its fallback. Onboarding help also sends tool metadata.
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
            <p className="hint-text">Keep credentials and sensitive data out of your question.</p>
          </details>
          <button disabled={!canAsk} type="submit">
            {busy ? "Requesting assistance…" : (mode === "EXPLAIN"
              ? "Explain this result"
              : MODES.find(([value]) => value === mode)?.[1])}
          </button>
          {!expectedAnalysis && (
            <p role="status">Refresh the selected tool or run its analysis before requesting assistance.</p>
          )}
        </form>
      )}

      <p className="visually-hidden" role="status">{busy ? "Requesting AI assistance." : result ? "AI assistance is ready." : ""}</p>
      {error && <div className="error-banner" role="alert">{error}</div>}
      {result && <ControlledAIResult result={result} />}
    </section>
  );
}


function ControlledAIResult({ result }) {
  const safeResult = result.non_authoritative === true
    && result.requires_human_review === true
    && result.can_mutate_runtime === false;
  // Fail closed on untrusted AI metadata. Showing the generated content
  // after a warning would still expose unapproved advice or draft actions.
  if (!safeResult) {
    return <div className="controlled-ai-result" role="alert">
      <h4>AI explanation withheld</h4>
      <p>The response did not meet the safeguards for advisory content. Continue using the recorded analysis and normal review workflow.</p>
    </div>;
  }
  const isDraft = result.draft_kind !== "NONE";
  return (
    <div className="controlled-ai-result">
      <h4>{isDraft ? "AI-generated onboarding proposal" : "AI-assisted review"}</h4>
      <section className="controlled-ai-section">
        <h5>{isDraft ? "What was proposed" : "What the framework recorded"}</h5>
        <p>{result.summary}</p>
      </section>
      <section className="controlled-ai-section">
        <h5>What to do next</h5>
        <p><strong>{ACTIONS[result.recommended_action] || "Review the recorded analysis"}</strong></p>
        <p>{result.rationale}</p>
      </section>
      <StringList title={isDraft ? "Proposal uncertainties" : "What remains unknown"} values={result.uncertainties} />
      {!result.evidence_refs?.length && (
        <p className="hint-text">No evidence references were selected. Review the findings and recorded analysis directly.</p>
      )}
      <p className="hint-text">An administrator reviews any suggestions through the normal approval workflow.</p>
      <details className="operator-technical-details">
        <summary>Supporting evidence and advanced options</summary>
        <div className="controlled-ai-result-heading">
          <div><span>Mode</span><strong>{humanize(result.mode)}</strong></div>
          <div className="controlled-ai-provider">
            <strong>{result.provider}</strong>
            <span>{result.fallback_used ? "Fallback provider" : "Configured provider"}</span>
          </div>
        </div>
        <p>Advisory confidence: {formatConfidence(result.confidence)}. This score describes the assistance only.</p>
        <StringList title="Risk factors" values={result.risk_factors} />
        <StringList title={isDraft ? "Related analysis references" : "Framework evidence references selected by AI"} values={result.evidence_refs} />
        <OptionList title="Template options" values={result.template_options} />
        <OptionList title="Adapter options" values={result.adapter_options} />
        {isDraft && (
          <section className="controlled-ai-section">
            <h5>{humanize(result.draft_kind)} preview</h5>
            <p>Review the proposed draft before using the approval workflow.</p>
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
  if (!value) return "Unavailable";
  return value.length > 18 ? `${value.slice(0, 12)}...${value.slice(-6)}` : value;
}


function humanize(value) {
  return String(value || "Unknown").replaceAll("_", " ").toLowerCase().replace(
    /(^|\s)\S/g,
    (character) => character.toUpperCase(),
  );
}


function formatConfidence(value) {
  return Number.isFinite(value) ? `${Math.round(value * 100)}%` : "Unavailable";
}


export default ControlledAIAssistant;
