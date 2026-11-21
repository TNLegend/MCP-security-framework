import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { fetchM4Semantics } from "../api/client";

function showHead(event, field) {
  const value = event?.classification?.heads?.[field];
  return value?.label || "Unresolved";
}

function formatSpan(span) {
  if (!span) return "Unresolved";
  return String(span.text || "") + " (" + span.start + "–" + span.end + ")";
}

export default function M4SemanticsPanel({ tool, latestAnalysis }) {
  const [result, setResult] = useState(null);
  const [waiting, setWaiting] = useState(false);
  const [error, setError] = useState("");
  const [requestKey, setRequestKey] = useState("");
  const currentToolIdentity = String(tool?.id ?? "") + ":" + String(tool?.current_fingerprint ?? "");
  const requestGeneration = useRef(0);

  // Invalidate even an already-started response when the selected MCP tool
  // changes. A layout effect fences results before the new view is painted.
  useLayoutEffect(() => {
    requestGeneration.current += 1;
  }, [currentToolIdentity]);

  useEffect(() => {
    setResult(null);
    setError("");
    setRequestKey("");
    setWaiting(false);
  }, [currentToolIdentity]);

  async function runM4() {
    if (!tool?.id || waiting) return;
    const key = currentToolIdentity;
    const generation = ++requestGeneration.current;
    setRequestKey(key);
    setWaiting(true);
    setResult(null);
    setError("");
    try {
      const out = await fetchM4Semantics(tool.id);
      if (generation !== requestGeneration.current) return;
      if (out?.source_fingerprint !== tool.current_fingerprint) {
        setError("Tool fingerprint changed. Refresh before using this analysis.");
        return;
      }
      if (out?.mode !== "SHADOW" || out?.authority !== "NON_AUTHORITATIVE") {
        setError("A valid description report was not returned.");
        return;
      }
      setResult(out);
    } catch (err) {
      if (generation === requestGeneration.current) {
        setError(err?.message || "Description analysis unavailable");
      }
    } finally {
      if (generation === requestGeneration.current) setWaiting(false);
    }
  }

  const advisory = result?.m4_advisory_module_views;
  const downstream = result?.m4_downstream_advisory;
  const m3 = downstream?.m3;
  const m6 = downstream?.m6;
  const m7 = downstream?.m7;
  // The controlling analyzer may already have a signed, fingerprint-bound M4
  // output. Do not interpret an older tool version as a current analysis.
  const mainM4 = latestAnalysis?.fingerprint === tool?.current_fingerprint
    ? latestAnalysis?.semantic_scores?.m4_structured_semantics
    : null;
  const report = result?.model_output;
  const events = Array.isArray(report?.events) ? report.events : [];
  const sourceProof = result?.m1_parsed_source_proof;
  const envelope = sourceProof?.envelope;
  const omissions = envelope?.coverage?.omissions || [];
  const evidence = envelope?.evidence || [];

  return (
    <section className="m4-advisory-panel" aria-label="Description analysis">
      <h4>Description check</h4>
      <p className="hint-text">Reviews what the tool claims it can do. Suggestions are not verified behavior.</p>
      {mainM4 && (
        <details className="operator-technical-details"><summary>Previous description analysis</summary><section className="m4-main-analysis-evidence" aria-label="Recorded description evidence">
          <h5>Recorded description evidence</h5>
          <p className="hint-text">
            This evidence is bound to the current tool fingerprint.
            The model did not independently verify advertised behavior.
            Security decisions still require independent checks and ADMIN review.
          </p>
          <dl className="inline-metadata">
            <div><dt>Structured operations</dt><dd>{mainM4?.m6?.candidate_operation_count ?? "Unknown"}</dd></div>
            <div><dt>Instruction candidates</dt><dd>{mainM4?.m3?.model_directives?.length ?? "Unknown"}</dd></div>
            <div><dt>Uncertain events</dt><dd>{mainM4?.m7?.events_with_uncertainty ?? "Unknown"}</dd></div>
            <div><dt>Risk verdict</dt><dd>{mainM4?.m7?.risk_decision ?? "NOT_EVALUATED"}</dd></div>
          </dl>
          <p className="hint-text">Description model evidence reference (SHA-256):
            <code>{mainM4?.m4_model_identity_sha256 || "NOT_VERIFIED"}</code>
          </p>
        </section></details>
      )}
      <button type="button" className="secondary-action"
        disabled={!tool?.id || waiting} onClick={runM4}>
        {waiting ? "Analyzing tool description…" : "Analyze description"}
      </button>
      {requestKey && waiting && (
        <p role="status" className="hint-text">
          Checking the description. This does not change approval.
        </p>
      )}
      {error && <p role="alert" className="error-banner">{error}</p>}
      {report && (
        <>
          <div className="operator-description-result" role="status">
            <strong>{events.length} possible action(s) found in the description.</strong>
            <p>This is an AI interpretation, not a confirmed security finding.</p>
          </div>
          <details className="operator-technical-details">
            <summary>Complete technical report</summary>
          <p className="hint-text m4-source-identity">
            Source fingerprint: <code>{result?.source_fingerprint}</code>
            {" · "}Report status: <strong>Advisory only / not an authorization decision</strong>
            {" · "}Source path: {report?.source_path}
          </p>
          <div className="analysis-overview-list">
            <p className="hint-text">
              Recorded source verification: <strong>{result?.envelope_validation_status}</strong>
            </p>
            {sourceProof ? (
              <p className="hint-text" role="note">
                {evidence.length} exact text evidence span(s) validated against the recorded
                original tool observation. This does not attest raw network bytes.
                {" · "}Snapshot: <code>{sourceProof.snapshot_id}</code>
              </p>
            ) : (
              <p className="hint-text" role="note">
                This report lacks a matching recorded protocol observation.
                Source attestation remains unverified: {result?.provenance_limitation || "unknown"}.
              </p>
            )}
            <p className="hint-text m4-source-identity">
              Description model/source fingerprint (SHA-256): <code>{result?.m4_model_identity_sha256 || "NOT_VERIFIED"}</code>
              {" · "}A local SHA-256 fingerprint is not a permission, authentication, or ADMIN approval.
            </p>
            <p className="hint-text">
              Description models · English-only · no automatic security decisions.
            </p>
          </div>
          {downstream && (
            <section className="m4-downstream-views" aria-label="Other security check references">
              <h5>How this report supports other security checks</h5>
              <p className="hint-text">
                Advisory evidence only. Other security checks may inspect these candidates,
                but no prompt-injection verdict, contract decision, drift decision,
                risk score, approval or runtime authorization is created here.
              </p>
              <dl className="inline-metadata">
                <div>
                  <dt>Possible instructions</dt>
                  <dd>{m3?.model_directives?.length ?? "Unknown"} directive candidate(s)
                    {" · "}{m3?.prompt_injection_verdict ?? "NOT_EVALUATED"}</dd>
                </div>
                <div>
                  <dt>Potential operations</dt>
                  <dd>{m6?.candidate_operation_count ?? "Unknown"} operation candidate(s)
                    {" · "}{m6?.contract_consistency_decision ?? "NOT_EVALUATED"}</dd>
                </div>
                <div>
                  <dt>Uncertainty</dt>
                  <dd>{m7?.events_with_uncertainty ?? "Unknown"} uncertain event(s)
                    {" · "}{m7?.risk_decision ?? "NOT_EVALUATED"}</dd>
                </div>
              </dl>
              {m3?.model_directives?.length > 0 && (
                <ul className="hint-text">
                  {m3.model_directives.map((directive) => (
                    <li key={directive.event_id}>
                      Directive candidate: <code>{directive.text_evidence?.text || "UNKNOWN"}</code>
                      {" · "}{directive.proposed_force || "UNKNOWN"}
                      {" · "}{directive.proposed_actor || "UNKNOWN"}
                      {" · "}Model hypothesis, not an instruction verdict
                    </li>
                  ))}
                </ul>
              )}
              <p className="hint-text">
                Claims promoted to security facts: <strong>{advisory?.claims_promoted_to_fact ?? "UNKNOWN"}</strong>
                {" · "}Security decision changes: <strong>{advisory?.security_decision_changes || "NOT_EVALUATED"}</strong>
              </p>
            </section>
          )}
          {events.length === 0 && (
            <p className="empty-state">
              No predicate detected. This does not prove absence of capabilities.
            </p>
          )}
          <div className="finding-list">
            {events.map((event) => (
              <article className="finding-card m4-event-card" key={event.event_id}>
                <div className="finding-heading">
                  <strong>{formatSpan(event.predicate)}</strong>
                  <span>Model hypothesis</span>
                </div>
                <dl className="inline-metadata">
                  <div><dt>Actor</dt><dd>{showHead(event, "actor")}</dd></div>
                  <div><dt>Polarity</dt><dd>{showHead(event, "polarity")}</dd></div>
                  <div><dt>Speech act</dt><dd>{showHead(event, "speech_act")}</dd></div>
                  <div><dt>Directive</dt><dd>{showHead(event, "directive_force")}</dd></div>
                </dl>
                <p>Predicate evidence: <code>{event.predicate?.text}</code></p>
                {event.links?.length > 0 && (
                  <ul>
                    {event.links.map((link, i) => (
                      <li key={event.event_id + ":" + link.role + ":" + i}>
                        {link.role}: <code>{formatSpan(link.tail)}</code>
                        {" · "}{link.support || "UNRESOLVED"}
                      </li>
                    ))}
                  </ul>
                )}
                {event.uncertainty_reasons?.length > 0 && (
                  <p className="hint-text">
                    Unresolved: {event.uncertainty_reasons.join(", ")}
                  </p>
                )}
              </article>
            ))}
          </div>
          {omissions.length > 0 && (
            <details>
              <summary>Description coverage limitations ({omissions.length})</summary>
              <ul>
                {omissions.map((omission, i) => (
                  <li key={String(i)}>{omission.reason} ({omission.path})</li>
                ))}
              </ul>
            </details>
          )}
          {report.unresolved_predictions?.length > 0 && (
            <p className="hint-text">
              {report.unresolved_predictions.length} relation(s) or span(s)
              could not be resolved and were not promoted to facts.
            </p>
          )}
          <p className="hint-text" role="note">
            This experimental report is not stored as an approval, risk decision,
            policy, finding or runtime permission.
          </p>
          </details>
        </>
      )}
    </section>
  );
}
