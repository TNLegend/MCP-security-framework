import { useEffect, useMemo, useState } from "react";
import { approveTool, blockTool, fetchToolAnalysisBundle } from "../api/client";
import ControlledAIAssistant from "../components/ControlledAIAssistant";
import ToolContractOnboarding from "../components/ToolContractOnboarding";
import {
  activateRowOnKeyboard,
  hasNonEmptyAnalysisEvidence,
  validateToolJustification,
} from "../utils/validation";

function ToolAnalysis({
  analyses = [],
  isAdmin = false,
  loading = false,
  onRefresh,
  servers = [],
  tools = [],
}) {
  const [selectedToolId, setSelectedToolId] = useState(null);
  const [bundle, setBundle] = useState(null);
  const [bundleToolId, setBundleToolId] = useState(null);
  const [bundleLoading, setBundleLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  const [reviewDialog, setReviewDialog] = useState(null);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [activeTab, setActiveTab] = useState("overview");

  const toolsById = useMemo(() => new Map(tools.map((tool) => [tool.id, tool])), [tools]);
  const serversById = useMemo(
    () => new Map(servers.map((server) => [server.id, server])),
    [servers],
  );
  const selectedTool = toolsById.get(selectedToolId) || null;
  const selectedToolFingerprint = selectedTool?.current_fingerprint || "";
  const selectedToolLastAnalyzedAt = selectedTool?.last_analyzed_at || "";
  const activeBundle = bundleToolId === selectedToolId ? bundle : null;
  const relevantAnalyses = selectedTool
    ? analyses.filter((analysis) => analysis.tool_id === selectedTool.id)
    : analyses;
  const latestAnalysis = activeBundle?.analyses?.[0] || relevantAnalyses[0] || null;
  const selectedServer = selectedTool ? serversById.get(selectedTool.server_id) : null;
  const approveDisabledReason = approvalDisabledReason(selectedTool, latestAnalysis);
  const blockDisabledReason = blockActionDisabledReason(selectedTool, latestAnalysis);

  useEffect(() => {
    if (tools.length === 0) {
      setSelectedToolId(null);
      return;
    }
    if (!tools.some((tool) => tool.id === selectedToolId)) {
      setSelectedToolId(tools[0].id);
    }
  }, [selectedToolId, tools]);

  useEffect(() => {
    let cancelled = false;
    if (!selectedToolId) {
      setBundle(null);
      setBundleToolId(null);
      return;
    }
    setBundle(null);
    setBundleToolId(null);
    setBundleLoading(true);
    setError("");
    fetchToolAnalysisBundle(selectedToolId)
      .then((result) => {
        if (!cancelled) {
          setBundle(result);
          setBundleToolId(selectedToolId);
        }
      })
      .catch((err) => {
        if (!cancelled) {
          setBundle(null);
          setBundleToolId(null);
          setError(err.message || "Could not load tool analysis");
        }
      })
      .finally(() => {
        if (!cancelled) {
          setBundleLoading(false);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [selectedToolId, selectedToolFingerprint, selectedToolLastAnalyzedAt]);

  useEffect(() => {
    setActiveTab("overview");
  }, [selectedToolId]);

  function openReview(action) {
    const disabledReason =
      action === "Allow" ? approveDisabledReason : blockDisabledReason;
    if (disabledReason) {
      setError(disabledReason);
      return;
    }
    setReviewDialog({
      action,
      justification: "",
      error: "",
    });
  }

  async function submitReview(event) {
    event.preventDefault();
    if (!reviewDialog || !selectedTool?.current_fingerprint) {
      return;
    }
    const justificationError = validateToolJustification(reviewDialog.justification);
    if (justificationError) {
      setReviewDialog({ ...reviewDialog, error: justificationError });
      return;
    }
    setBusy(true);
    setError("");
    setMessage("");
    try {
      if (reviewDialog.action === "Allow") {
        await approveTool(
          selectedTool.id,
          selectedTool.current_fingerprint,
          reviewDialog.justification.trim(),
        );
      } else {
        await blockTool(
          selectedTool.id,
          selectedTool.current_fingerprint,
          reviewDialog.justification.trim(),
        );
      }
      setMessage(`${reviewDialog.action} recorded.`);
      setReviewDialog(null);
      await onRefresh?.();
      setBundle(await fetchToolAnalysisBundle(selectedTool.id));
      setBundleToolId(selectedTool.id);
    } catch (err) {
      setError(err.message || `${reviewDialog.action} failed`);
    } finally {
      setBusy(false);
    }
  }

  if (loading) {
    return (
      <section className="page-section">
        <div className="section-heading">
          <h2>Tool Analysis</h2>
          <p>Loading analyzer evidence...</p>
        </div>
      </section>
    );
  }

  return (
    <section className="page-section">
      <div className="section-heading">
        <h2>Tool Analysis</h2>
        <p>{analyses.length} analysis record(s)</p>
      </div>

      {message && <div className="success-banner">{message}</div>}
      {error && <div className="error-banner">{error}</div>}

      <div className="analysis-layout">
        <div className="inventory-section">
          <div className="section-heading compact-heading">
            <h3>Tools</h3>
            <p>{tools.length} total</p>
          </div>
          <div className="table-shell analysis-tool-table">
            <table>
              <thead>
                <tr>
                  <th>Server</th>
                  <th>Tool</th>
                  <th>Status</th>
                  <th>Review</th>
                  <th>Risk</th>
                </tr>
              </thead>
              <tbody>
                {tools.length === 0 ? (
                  <tr>
                    <td colSpan="5">No tools discovered.</td>
                  </tr>
                ) : (
                  tools.map((tool) => {
                    const server = serversById.get(tool.server_id);
                    const selectTool = () => setSelectedToolId(tool.id);
                    return (
                      <tr
                        className={selectedTool?.id === tool.id ? "selected-row" : ""}
                        key={tool.id}
                        onClick={selectTool}
                        onKeyDown={(event) => activateRowOnKeyboard(event, selectTool)}
                        role="button"
                        tabIndex="0"
                      >
                        <td>
                          <span
                            className="table-ellipsis"
                            title={server?.server_info_title || server?.name || String(tool.server_id)}
                          >
                            {server?.server_info_title || server?.name || tool.server_id}
                          </span>
                        </td>
                        <td><span className="table-ellipsis" title={tool.title || tool.name}>{tool.title || tool.name}</span></td>
                        <td>
                          <Badge value={tool.analysis_status} />
                        </td>
                        <td>
                          <Badge value={tool.review_status} />
                        </td>
                        <td>{tool.risk_score}</td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>

        <div className="detail-panel">
          <h3>{selectedTool ? selectedTool.title || selectedTool.name : "No tool selected"}</h3>
          {selectedTool && (
            <>
              {bundleLoading && <p>Loading selected tool evidence...</p>}
              <dl className="compact-dl">
                <div>
                  <dt>Server</dt>
                  <dd>{selectedServer?.server_info_title || selectedServer?.name || selectedTool.server_id}</dd>
                </div>
                <div>
                  <dt>Current fingerprint</dt>
                  <dd>{shorten(selectedTool.current_fingerprint)}</dd>
                </div>
                <div>
                  <dt>Approved fingerprint match</dt>
                  <dd>{selectedTool.approved_fingerprint_match ? "true" : "false"}</dd>
                </div>
                <div>
                  <dt>Analysis context</dt>
                  <dd>{shorten(latestAnalysis?.analysis_context_hash)}</dd>
                </div>
                <div>
                  <dt>Semantic signal</dt>
                  <dd>{selectedTool.semantic_flagged ? "true" : "false"}</dd>
                </div>
                <div>
                  <dt>Critical deterministic finding</dt>
                  <dd>{selectedTool.deterministic_critical_finding ? "true" : "false"}</dd>
                </div>
              </dl>

              {isAdmin && (
                <div className="button-row">
                  <button
                    disabled={busy || Boolean(approveDisabledReason)}
                    onClick={() => openReview("Allow")}
                    title={approveDisabledReason}
                    type="button"
                  >
                    Allow
                  </button>
                  <button
                    disabled={busy || Boolean(blockDisabledReason)}
                    onClick={() => openReview("Block")}
                    title={blockDisabledReason}
                    type="button"
                  >
                    Block
                  </button>
                </div>
              )}
              {approveDisabledReason && isAdmin && (
                <p className="hint-text">{approveDisabledReason}</p>
              )}

              <AnalysisWorkspace
                activeTab={activeTab}
                bundle={activeBundle}
                isAdmin={isAdmin}
                latestAnalysis={latestAnalysis}
                onComplete={onRefresh}
                onSelectTab={setActiveTab}
                tool={selectedTool}
              />
            </>
          )}
        </div>
      </div>
      {reviewDialog && (
        <div className="modal-backdrop" role="presentation">
          <section aria-modal="true" className="modal-panel" role="dialog">
            <h3>{reviewDialog.action} Tool</h3>
            <p>
              {selectedServer?.server_info_title || selectedServer?.name || selectedTool?.server_id}
              {" / "}
              {selectedTool?.title || selectedTool?.name}
            </p>
            <form className="form-grid" onSubmit={submitReview}>
              <label className="wide-field">
                Justification
                <textarea
                  aria-describedby="review-justification-error"
                  aria-invalid={Boolean(reviewDialog.error)}
                  maxLength="2000"
                  minLength="8"
                  onChange={(event) =>
                    setReviewDialog({
                      ...reviewDialog,
                      justification: event.target.value,
                      error: "",
                    })
                  }
                  required
                  value={reviewDialog.justification}
                />
                <span className="field-error" id="review-justification-error">
                  {reviewDialog.error}
                </span>
              </label>
              <div className="button-row">
                <button className="secondary-action" disabled={busy} type="submit">
                  {busy ? "Submitting..." : reviewDialog.action}
                </button>
                <button disabled={busy} onClick={() => setReviewDialog(null)} type="button">
                  Cancel
                </button>
              </div>
            </form>
          </section>
        </div>
      )}
    </section>
  );
}

const ANALYSIS_TABS = [
  ["overview", "Overview"],
  ["findings", "Findings"],
  ["semantic", "Semantic"],
  ["ai", "AI Assist"],
  ["history", "History"],
  ["contract", "Contract"],
  ["raw", "Raw evidence"],
];

function AnalysisWorkspace({ activeTab, bundle, isAdmin, latestAnalysis, onComplete, onSelectTab, tool }) {
  const findings = (bundle?.findings || []).filter(
    (finding) => !latestAnalysis?.id || !finding.analysis_id || finding.analysis_id === latestAnalysis.id,
  );
  return (
    <div className="analysis-workspace">
      <div aria-label="Analysis evidence" className="tab-list" role="tablist">
        {ANALYSIS_TABS.map(([id, label]) => (
          <button
            aria-selected={activeTab === id}
            className={activeTab === id ? "active-tab" : ""}
            key={id}
            onClick={() => onSelectTab(id)}
            role="tab"
            type="button"
          >
            {label}
          </button>
        ))}
      </div>
      <div className="tab-content" role="tabpanel">
        {activeTab === "overview" && <AnalysisOverview bundle={bundle} latestAnalysis={latestAnalysis} tool={tool} />}
        {activeTab === "findings" && <FindingsView error={bundle?.errors?.findings} findings={findings} />}
        {activeTab === "semantic" && <SemanticScores error={bundle?.errors?.analyses} scores={latestAnalysis?.semantic_scores} />}
        {activeTab === "ai" && (
          <ControlledAIAssistant bundle={bundle} isAdmin={isAdmin} tool={tool} />
        )}
        {activeTab === "history" && <AnalysisHistory bundle={bundle} />}
        {activeTab === "contract" && (
          <ToolContractOnboarding isAdmin={isAdmin} onComplete={onComplete} tool={tool} />
        )}
        {activeTab === "raw" && <RawEvidence bundle={bundle} />}
      </div>
    </div>
  );
}

function AnalysisOverview({ bundle, latestAnalysis, tool }) {
  return (
    <>
      <SectionError error={bundle?.errors?.status} title="Analysis status" />
      <div className="analysis-stat-grid">
        <AnalysisStat label="Analysis" value={latestAnalysis?.analysis_status || tool.analysis_status} badge />
        <AnalysisStat label="Review" value={latestAnalysis?.review_status || tool.review_status} badge />
        <AnalysisStat label="Risk level" value={latestAnalysis?.risk_level || tool.risk_level} badge />
        <AnalysisStat label="Risk score" value={latestAnalysis?.risk_score ?? tool.risk_score ?? "-"} />
        <AnalysisStat label="Consistency" value={latestAnalysis?.consistency_status || tool.consistency_status} badge />
        <AnalysisStat label="Drift" value={latestAnalysis?.drift_status || tool.drift_status} badge />
      </div>
      <dl className="compact-dl analysis-overview-list">
        <InfoRow label="Analyzer revision" value={latestAnalysis?.analyzer_revision || tool.analyzer_revision} />
        <InfoRow label="Completed" value={formatDate(latestAnalysis?.completed_at)} />
        <InfoRow label="Semantic decision" value={formatSemanticDecision(latestAnalysis?.semantic_scores)} />
        <InfoRow label="Deterministic critical finding" value={tool.deterministic_critical_finding ? "Yes" : "No"} />
      </dl>
    </>
  );
}

function AnalysisStat({ badge = false, label, value }) {
  return <div className="analysis-stat"><span>{label}</span>{badge ? <Badge value={value} /> : <strong>{value}</strong>}</div>;
}

function InfoRow({ label, value }) {
  return <div><dt>{label}</dt><dd>{value ?? "-"}</dd></div>;
}

function FindingsView({ error, findings }) {
  if (error) return <SectionError error={error} title="Findings" />;
  if (findings.length === 0) return <div className="empty-state">No findings for the latest analysis.</div>;
  return (
    <div className="finding-list">
      {findings.map((finding, index) => (
        <article className="finding-card" key={finding.id || `${finding.code}-${index}`}>
          <div className="finding-heading">
            <div><strong>{finding.title || finding.code || "Analysis finding"}</strong><span>{finding.code || finding.source || "Analyzer"}</span></div>
            <Badge value={finding.severity} />
          </div>
          <p>{finding.summary || finding.message || finding.evidence?.summary || "No summary provided."}</p>
          {finding.recommendation && <div className="finding-recommendation"><strong>Recommendation</strong><span>{finding.recommendation}</span></div>}
          <dl className="inline-metadata">
            <div><dt>Source</dt><dd>{finding.source || "-"}</dd></div>
            <div><dt>Confidence</dt><dd>{formatConfidence(finding.confidence)}</dd></div>
          </dl>
        </article>
      ))}
    </div>
  );
}

function SemanticScores({ error, scores }) {
  if (error) return <SectionError error={error} title="Semantic scores" />;
  const rows = semanticScoreRows(scores);
  const factGroups = semanticFactGroups(scores?.facts);
  return (
    <>
      <div className="semantic-decision">
        <AnalysisStat label="Model flagged" value={scores?.model_flagged ? "Yes" : "No"} />
        <AnalysisStat label="Corroborated" value={scores?.corroborated ? "Yes" : "No"} />
        <AnalysisStat label="Actionable flag" value={scores?.flagged ? "Yes" : "No"} />
        <AnalysisStat label="Model abstained" value={scores?.abstained ? "Yes" : "No"} />
        <AnalysisStat label="Sensitive" value={scores?.facts?.is_sensitive ? "Yes" : "No"} />
        <AnalysisStat label="Reversibility" value={humanize(scores?.facts?.reversibility || "unknown")} />
      </div>
      <div className="semantic-facts">
        <div className="semantic-facts-heading">
          <h4>Observed facts</h4>
          <span>{scores?.facts?.unknown_reasons?.length ? "Incomplete semantics" : "Semantics evidenced"}</span>
        </div>
        {factGroups.length === 0 ? (
          <div className="empty-state">No structured semantic facts available.</div>
        ) : (
          <dl className="semantic-fact-list">
            {factGroups.map(([label, facts]) => (
              <div key={label}>
                <dt>{label}</dt>
                <dd>
                  {facts.map((fact) => (
                    <span
                      className="semantic-fact"
                      key={`${label}-${fact.value}`}
                      title={factEvidenceTitle(fact)}
                    >
                      {humanize(fact.value)} · {formatConfidence(fact.confidence)}
                    </span>
                  ))}
                </dd>
              </div>
            ))}
          </dl>
        )}
        {scores?.facts?.unknown_reasons?.length > 0 && (
          <p className="hint-text">
            Missing evidence: {scores.facts.unknown_reasons.map(humanize).join(", ")}.
          </p>
        )}
      </div>
      {rows.length === 0 ? <div className="empty-state">No semantic category scores available.</div> : (
        <div className="table-shell"><table><thead><tr><th>Category</th><th>Score</th></tr></thead><tbody>
          {rows.map(([category, score]) => <tr key={category}><td>{humanize(category)}</td><td>{formatScore(score)}</td></tr>)}
        </tbody></table></div>
      )}
    </>
  );
}

function AnalysisHistory({ bundle }) {
  return (
    <div className="history-sections">
      <HistoryTable error={bundle?.errors?.analyses} rows={bundle?.analyses || []} title="Analyses" />
      <HistoryTable error={bundle?.errors?.versions} rows={bundle?.versions || []} title="Observed versions" />
      <HistoryTable error={bundle?.errors?.reviews} rows={bundle?.reviews || []} title="Reviews" />
    </div>
  );
}

function HistoryTable({ error, rows, title }) {
  return (
    <section>
      <h4>{title}</h4>
      <SectionError error={error} title={title} />
      {!error && (rows.length === 0 ? <div className="empty-state">No {title.toLowerCase()} recorded.</div> : (
        <div className="table-shell history-table"><table><thead><tr><th>Recorded</th><th>Status</th><th>Fingerprint</th></tr></thead><tbody>
          {rows.map((row, index) => {
            const status = row.analysis_status || row.review_status || row.status || row.action || "-";
            return <tr key={row.id || index}><td title={formatDate(row.completed_at || row.created_at || row.observed_at || row.first_seen_at)}>{formatDate(row.completed_at || row.created_at || row.observed_at || row.first_seen_at)}</td><td><span className="history-status" title={status}>{humanize(status)}</span></td><td><span className="history-fingerprint" title={row.fingerprint || "-"}>{shorten(row.fingerprint)}</span></td></tr>;
          })}
        </tbody></table></div>
      ))}
    </section>
  );
}

function RawEvidence({ bundle }) {
  const sections = [
    ["Analysis status", bundle?.status, bundle?.errors?.status],
    ["Baseline", bundle?.baseline, bundle?.errors?.baseline],
    ["Drift / diff", bundle?.diff, bundle?.errors?.diff],
    ["Findings", bundle?.findings || [], bundle?.errors?.findings],
  ];
  return sections.map(([title, value, error]) => <Metadata error={error} key={title} title={title} value={value} />);
}

function SectionError({ error, title }) {
  return error ? <div className="error-text">{title} unavailable: {error}</div> : null;
}

function Metadata({ error, title, value }) {
  return (
    <section className="metadata-section stacked-section">
      <h4>{title}</h4>
      {error && <div className="error-text">{title} unavailable: {error}</div>}
      <pre className="json-block">{formatJson(value)}</pre>
    </section>
  );
}

function semanticScoreRows(scores) {
  const source = scores?.scores || scores?.category_scores || {};
  return Object.entries(source)
    .filter(([, value]) => typeof value === "number")
    .sort((left, right) => right[1] - left[1]);
}

function semanticFactGroups(facts) {
  if (!facts) return [];
  return [
    ["Actions", facts.actions],
    ["Resources", facts.resources],
    ["Data", facts.data_categories],
    ["Side effects", facts.side_effects],
    ["Destinations", facts.external_destinations],
    ["Privileges", facts.privileges],
    ["Scope", facts.scopes],
  ].filter(([, values]) => Array.isArray(values) && values.length > 0);
}

function factEvidenceTitle(fact) {
  return (fact?.evidence || [])
    .map((item) => `${item.source}: ${item.excerpt}`)
    .join("\n");
}

function formatSemanticDecision(scores) {
  if (!scores) return "Unavailable";
  if (scores.flagged) return "Corroborated semantic risk";
  if (scores.abstained) return "Model abstained; deterministic facts retained";
  if (scores.model_flagged) return "Model signal not corroborated";
  return "No semantic risk signal";
}

function formatScore(value) {
  return typeof value === "number" ? value.toFixed(3) : "-";
}

function formatConfidence(value) {
  if (typeof value !== "number") return "-";
  return value > 1 ? `${Math.round(value)}%` : `${Math.round(value * 100)}%`;
}

function humanize(value) {
  return String(value || "").replace(/_/g, " ").replace(/^./, (letter) => letter.toUpperCase());
}

function formatDate(value) {
  if (!value) return "-";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
}

function approvalDisabledReason(tool, latestAnalysis) {
  if (!tool?.current_fingerprint) {
    return "Cannot allow: no current fingerprint.";
  }
  if (!latestAnalysis) {
    return "Cannot allow: no latest analysis.";
  }
  if (latestAnalysis.fingerprint !== tool.current_fingerprint) {
    return "Cannot allow: latest analysis does not match current fingerprint.";
  }
  if (!latestAnalysis.completed_at) {
    return "Cannot allow: analysis is incomplete.";
  }
  if (!latestAnalysis.analysis_context_hash) {
    return "Cannot allow: analysis context hash is missing.";
  }
  if (!/^[a-f0-9]{64}$/i.test(latestAnalysis.analysis_context_hash)) {
    return "Cannot allow: analysis context hash is invalid.";
  }
  if (
    ["PENDING_ANALYSIS", "ANALYSIS_FAILED", "BLOCKED", "QUARANTINED", "STALE"].includes(
      latestAnalysis.analysis_status,
    )
  ) {
    return `Cannot allow: ${latestAnalysis.analysis_status.toLowerCase()}.`;
  }
  if (
    !hasNonEmptyAnalysisEvidence(latestAnalysis.semantic_scores) ||
    !hasNonEmptyAnalysisEvidence(latestAnalysis.drift_result) ||
    !hasNonEmptyAnalysisEvidence(latestAnalysis.model_versions)
  ) {
    return "Cannot allow: analysis results are incomplete.";
  }
  if (
    latestAnalysis.analysis_status === "REVIEW_REQUIRED" &&
    !["REVIEW_REQUIRED", "APPROVED", "ADMIN_ALLOWED"].includes(latestAnalysis.review_status)
  ) {
    return "Cannot allow: review status is not eligible for admin approval.";
  }
  return "";
}

function blockActionDisabledReason(tool, latestAnalysis) {
  if (!tool?.current_fingerprint) {
    return "Cannot block: no current fingerprint.";
  }
  if (!latestAnalysis) {
    return "Cannot block: no latest analysis.";
  }
  if (latestAnalysis.fingerprint !== tool.current_fingerprint) {
    return "Cannot block: latest analysis does not match current fingerprint.";
  }
  return "";
}

function Badge({ value }) {
  return <span className={`badge ${badgeClass(value)}`}>{value || "unknown"}</span>;
}

function badgeClass(value) {
  const normalized = String(value || "").toLowerCase();
  if (["approved", "admin_allowed", "consistent", "none", "low"].includes(normalized)) {
    return "badge-success";
  }
  if (["blocked", "critical", "high"].includes(normalized)) {
    return "badge-danger";
  }
  if (["review_required", "quarantined", "analysis_failed", "medium"].includes(normalized)) {
    return "badge-warning";
  }
  return "badge-muted";
}

function formatJson(value) {
  if (value === null || value === undefined || value === "") {
    return "-";
  }
  return JSON.stringify(value, null, 2);
}

function shorten(value) {
  if (!value) {
    return "-";
  }
  return `${String(value).slice(0, 12)}...${String(value).slice(-8)}`;
}

export default ToolAnalysis;
