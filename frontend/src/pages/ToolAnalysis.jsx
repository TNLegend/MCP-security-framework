import { formatServerTime } from "../utils/serverTime.js";
import "./workflowPages.css";
import { useEffect, useMemo, useRef, useState } from "react";
import { approveTool, blockTool, fetchToolAnalysisBundle, safeErrorMessage } from "../api/client";
import ControlledAIAssistant from "../components/ControlledAIAssistant";
import M4SemanticsPanel from "../components/m4semanticspanel";
import { Pagination, usePagination } from "../components/Pagination";
import ToolContractOnboarding from "../components/ToolContractOnboarding";
import { useDialogFocus } from "../utils/useDialogFocus";
import { driftChangeDescription, driftComparisonState, isCurrentAnalysis, nextAnalysisAction, riskLedgerMatchesRecord } from "../utils/analysisPresentation";
import { validateToolJustification } from "../utils/validation";

function ToolAnalysis({
  analyses = [],
  requestedToolId = null,
  isAdmin = false,
  loading = false,
  onRefresh,
  servers = [],
  tools = [],
}) {
  const [selectedToolId, setSelectedToolId] = useState(null);
  const handledDeepLink = useRef(null);
  const [bundle, setBundle] = useState(null);
  const [bundleToolId, setBundleToolId] = useState(null);
  const [bundleLoading, setBundleLoading] = useState(false);
  const [reviewRefresh, setReviewRefresh] = useState(0);
  const [busy, setBusy] = useState(false);
  const [reviewDialog, setReviewDialog] = useState(null);
  const modalRef = useRef(null);
  useDialogFocus(Boolean(reviewDialog && isAdmin), modalRef);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [activeTab, setActiveTab] = useState("overview");
  const [toolSearch, setToolSearch] = useState("");
  const [toolStateFilter, setToolStateFilter] = useState("ALL");
  const serverLookup = useMemo(() => new Map(servers.map((server) => [server.id, server])), [servers]);
  const filteredTools = useMemo(() => tools.filter((tool) => {
    const query = toolSearch.trim().toLowerCase();
    const state = String(tool.analysis_status || "").toUpperCase();
    if (toolStateFilter === "REVIEW" &&
      !["REVIEW_REQUIRED", "PENDING_ANALYSIS", "QUARANTINED", "ANALYSIS_FAILED", "STALE"].includes(state)) return false;
    if (toolStateFilter === "BLOCKED" && state !== "BLOCKED") return false;
    if (toolStateFilter === "APPROVED" &&
      !["APPROVED", "ADMIN_ALLOWED"].includes(state)) return false;
    if (!query) return true;
    const server = serverLookup.get(tool.server_id);
    return [tool.title, tool.name, server?.name, server?.server_info_title]
      .some((value) => String(value || "").toLowerCase().includes(query));
  }), [tools, serverLookup, toolSearch, toolStateFilter]);
  const toolPagination = usePagination(filteredTools,
    toolSearch + "|" + toolStateFilter + "|" + filteredTools.length);

  useEffect(() => {
    if (!reviewDialog) {
      return undefined;
    }
    function handleEscape(event) {
      if (event.key !== "Escape" || busy) {
        return;
      }
      event.preventDefault();
      setReviewDialog(null);
    }
    window.addEventListener("keydown", handleEscape);
    return () => window.removeEventListener("keydown", handleEscape);
  }, [busy, reviewDialog]);

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
  // Review actions require a fetched, current bundle, not cached list-only data.
  const reviewAnalysis = activeBundle?.analyses?.[0] || null;
  const selectedServer = selectedTool ? serversById.get(selectedTool.server_id) : null;
  const approveDisabledReason = bundleLoading
    ? "Cannot allow: current evidence is still loading."
    : approvalDisabledReason(activeBundle, reviewAnalysis);
  const blockDisabledReason = bundleLoading
    ? "Cannot block: current evidence is still loading."
    : blockActionDisabledReason(selectedTool, reviewAnalysis);

  useEffect(() => {
    if (tools.length === 0) {
      setSelectedToolId(null);
      return;
    }
    const deepLink = requestedToolId === null ? null : String(requestedToolId);
    if (deepLink !== null && handledDeepLink.current !== deepLink) {
      handledDeepLink.current = deepLink;
      const requested = tools.find((tool) => String(tool.id) === deepLink);
      // Fail closed: an audit link to a deleted/foreign tool must never silently
      // open another tool and present unrelated findings as matching evidence.
      setSelectedToolId(requested?.id ?? null);
      if (requested) {
        const index = filteredTools.findIndex((tool) => tool.id === requested.id);
        if (index >= 0) toolPagination.setPage(Math.floor(index / toolPagination.pageSize) + 1);
      }
      return;
    }
    if (deepLink === null) handledDeepLink.current = null;
    if (!tools.some((tool) => tool.id === selectedToolId)) {
      setSelectedToolId(deepLink === null ? tools[0].id : null);
    }
  }, [selectedToolId, requestedToolId, tools]);

  useEffect(() => {
    let cancelled = false;
    if (!selectedToolId) {
      setBundle(null);
      setBundleToolId(null);
      setBundleLoading(false);
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
          setError(safeErrorMessage(err) || "Could not load tool analysis");
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
  }, [selectedToolId, selectedToolFingerprint, selectedToolLastAnalyzedAt, reviewRefresh]);

  // Begin with the overall assessment. Advisory M4 remains available in its own tab.
  useEffect(() => {
    setActiveTab("overview");
  }, [selectedToolId, isAdmin]);

  function openReview(action) {
    const disabledReason =
      action === "Allow" ? approveDisabledReason : blockDisabledReason;
    if (disabledReason) {
      setError(disabledReason);
      return;
    }
    setReviewDialog({
      action,
      toolId: selectedTool.id,
      fingerprint: selectedTool.current_fingerprint,
      analysisContextHash: reviewAnalysis?.analysis_context_hash || null,
      justification: "",
      error: "",
    });
  }

  async function submitReview(event) {
    event.preventDefault();
    if (!isAdmin || busy || !reviewDialog || !selectedTool?.current_fingerprint) {
      return;
    }
    if (reviewDialog.toolId !== selectedTool.id
      || reviewDialog.fingerprint !== selectedTool.current_fingerprint
      || reviewDialog.analysisContextHash !== (reviewAnalysis?.analysis_context_hash || null)) {
      setReviewDialog(null);
      setError("The tool or analysis changed. Reopen the review using current evidence.");
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
    } catch (err) {
      const detail = safeErrorMessage(err);
      const receiptUncertain = !err?.status || err.status >= 500;
      setReviewDialog((current) => current ? {
        ...current,
        error: receiptUncertain
          ? detail + " Verify the recorded review before submitting again."
          : detail,
      } : current);
      setBusy(false);
      return;
    }

    setMessage(reviewDialog.action === "Allow" ? "Tool review approved." : "Tool block recorded.");
    setReviewDialog(null);
    setBundle(null);
    setBundleToolId(null);
    setReviewRefresh((current) => current + 1);
    try {
      await onRefresh?.();
    } catch {
      setError("The review was recorded. The inventory could not be refreshed. Reload the evidence before making another decision.");
    } finally {
      setBusy(false);
    }
  }

  if (loading && tools.length === 0) {
    return (
      <section className="page-section">
        <div className="section-heading">
          <h2>Security review</h2>
          <p>Loading security results...</p>
        </div>
      </section>
    );
  }

  return (
    <section className="page-section tool-review-page">
      <div className="section-heading">
        <div>
          <h2>Security review</h2>
          <p>Find an MCP tool, inspect its evidence, and record a review decision.</p>
        </div>
      </div>
      <nav aria-label="Security review sections" className="workflow-links">
        <a href="#review-tools">Tool list</a>
        {selectedTool && <a href="#review-selected-tool">Selected tool</a>}
      </nav>
      <p className="hint-text" role="note">An approved review does not automatically allow an MCP call.</p>

      {message && <div className="success-banner" role="status">{message}</div>}
      {error && <div className="error-banner" role="alert">{error}</div>}

      <div className="analysis-layout">
        <div className="inventory-section">
          <div className="section-heading compact-heading">
            <h3 id="review-tools">Select a tool</h3>
            <p>{filteredTools.length} displayed / {tools.length} total</p>
          </div>
          <div className="analysis-tool-filters">
            <label>
              Search tools or servers
              <input
                maxLength={200}
                onChange={(event) => setToolSearch(event.target.value)}
                placeholder="Tool or server name"
                type="search"
                value={toolSearch}
              />
            </label>
            <label>
              Analysis status
              <select value={toolStateFilter} onChange={(event) => setToolStateFilter(event.target.value)}>
                <option value="ALL">All states</option>
                <option value="REVIEW">Needs analysis / review</option>
                <option value="BLOCKED">Blocked</option>
                <option value="APPROVED">Analysis approved (not runtime permission)</option>
              </select>
            </label>
            <button className="tiny-action" onClick={() => {
              setToolSearch("");
              setToolStateFilter("ALL");
            }} type="button">
              Clear filters
            </button>
          </div>
          {selectedTool && !filteredTools.some((tool) => tool.id === selectedTool.id) && (
            <p role="status" className="hint-text">
              The current filters exclude the selected tool.
              <a href="#review-selected-tool"> View its details.</a>
            </p>
          )}
          <p className="analysis-mobile-hint hint-text">Scroll sideways to view analysis, review and risk for every tool.</p>
          <div className="table-shell analysis-tool-table" role="region" tabIndex="0" aria-label="Tool list, horizontally scrollable on small screens">
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
                {filteredTools.length === 0 ? (
                  <tr>
                    <td colSpan="5">{tools.length ? "No tools match these filters." : "No tools discovered."}</td>
                  </tr>
                ) : (
                  toolPagination.pageItems.map((tool) => {
                    const server = serversById.get(tool.server_id);
                    const selectTool = () => setSelectedToolId(tool.id);
                    return (
                      <tr
                        className={selectedTool?.id === tool.id ? "selected-row" : ""}
                        key={tool.id}
                        onClick={selectTool}
                      >
                        <td>
                          <span
                            className="table-ellipsis"
                            title={server?.server_info_title || server?.name || String(tool.server_id)}
                          >
                            {server?.server_info_title || server?.name || tool.server_id}
                          </span>
                        </td>
                        <td><button className="table-selection" aria-pressed={selectedTool?.id === tool.id}
                          title={tool.title || tool.name} onClick={(event) => { event.stopPropagation(); selectTool(); }}
                          type="button">{tool.title || tool.name}</button></td>
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
          <Pagination
            label="Analyzed tools"
            onPageChange={toolPagination.setPage}
            page={toolPagination.page}
            pageCount={toolPagination.pageCount}
            total={toolPagination.total}
          />
        </div>

        <div className="detail-panel">
          {requestedToolId !== null && !tools.some((tool) =>
            String(tool.id) === String(requestedToolId)) && !loading && (
            <p role="alert" className="error-banner">
              The tool linked by the audit record (ID {String(requestedToolId).slice(0, 40)})
              is not in the current inventory. No other tool has been substituted.
              Check whether the original server was archived.
            </p>
          )}
          <h3 id="review-selected-tool">{selectedTool ? selectedTool.title || selectedTool.name : "No tool selected"}</h3>
          {selectedServer && <p className="hint-text">{selectedServer.server_info_title || selectedServer.name}</p>}
          {selectedTool && (
            <>
              {bundleLoading && <p role="status" className="workflow-progress">Loading selected tool evidence…</p>}
              <div className="analysis-quick-summary" aria-label="Tool security status">
                <div><span>Risk</span><strong>{humanize(selectedTool.risk_level || "Unknown")}</strong></div>
                <div><span>Review</span><strong>{displayReviewStatus(selectedTool.review_status)}</strong></div>
                <div><span>Execution authority</span><strong>Checked by runtime policy</strong></div>
              </div>
              {activeBundle?.baseline?.approval_provenance && (
                <p className="hint-text" aria-label="Baseline approval provenance">
                  Approved baseline: {activeBundle.baseline.approval_provenance.label}
                </p>
              )}
              <details className="analysis-technical-identity">
                <summary>Technical identifiers</summary>
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
              </details>

              <ReviewActionControls
                isAdmin={isAdmin}
                busy={busy}
                approveDisabledReason={approveDisabledReason}
                blockDisabledReason={blockDisabledReason}
                onApprove={() => openReview("Allow")}
                onBlock={() => openReview("Block")}
              />

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
      {isAdmin && reviewDialog && (
        <div className="modal-backdrop" role="presentation">
          <section aria-modal="true" aria-labelledby="analysis-review-dialog-title"
            className="modal-panel" ref={modalRef} role="dialog" tabIndex={-1}>
            <h3 id="analysis-review-dialog-title">{reviewDialog.action === "Allow" ? "Approve review" : "Block tool"}</h3>
            <p>
              {selectedServer?.server_info_title || selectedServer?.name || selectedTool?.server_id}
              {" / "}
              {selectedTool?.title || selectedTool?.name}
            </p>
            <p className="hint-text">This records a review decision. Runtime access is checked separately.</p>
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
                <span className="field-error" id="review-justification-error" role="alert">
                  {reviewDialog.error}
                </span>
              </label>
              <div className="button-row">
                <button className="secondary-action" disabled={busy} type="submit">
                  {busy ? "Saving..." : reviewDialog.action === "Allow" ? "Confirm review approval" : "Confirm block"}
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
  ["overview", "Summary"],
  ["m4-neural", "Description check"],
  ["findings", "Detected issues"],
  ["ai", "Explain with AI"],
  ["history", "History"],
  ["contract", "Tool settings"],
  ["raw", "Technical details"],
];

function AnalysisWorkspace({ activeTab, bundle, isAdmin, latestAnalysis, onComplete, onSelectTab, tool }) {
  function handleTabKeyDown(event) {
    if (!["ArrowRight", "ArrowLeft", "Home", "End"].includes(event.key)) return;
    const tabs = [...event.currentTarget.parentElement.querySelectorAll('[role="tab"]')];
    const index = tabs.indexOf(event.currentTarget);
    if (index < 0 || tabs.length === 0) return;
    const next = event.key === "Home" ? 0
      : event.key === "End" ? tabs.length - 1
        : event.key === "ArrowRight" ? (index + 1) % tabs.length
          : (index - 1 + tabs.length) % tabs.length;
    event.preventDefault();
    tabs[next].focus();
    onSelectTab(tabs[next].dataset.tabId);
  }
  const findings = (bundle?.findings || []).filter(
    (finding) => !latestAnalysis?.id || !finding.analysis_id || finding.analysis_id === latestAnalysis.id,
  );
  return (
    <div className="analysis-workspace">
      <div aria-label="Analysis evidence" className="tab-list" role="tablist">
        {ANALYSIS_TABS.filter(([id]) => id !== "m4-neural" || isAdmin).map(([id, label]) => (
          <button
            aria-controls="analysis-evidence-panel"
            aria-selected={activeTab === id}
            className={activeTab === id ? "active-tab" : ""}
            data-tab-id={id}
            id={"analysis-tab-" + id}
            key={id}
            onClick={() => onSelectTab(id)}
            onKeyDown={handleTabKeyDown}
            role="tab"
            tabIndex={activeTab === id ? 0 : -1}
            type="button"
          >
            {label}
          </button>
        ))}
      </div>
      <div aria-labelledby={"analysis-tab-" + activeTab}
        className="tab-content" id="analysis-evidence-panel" role="tabpanel" tabIndex={0}>
        {activeTab === "overview" && (
          <AnalysisOverview
            bundle={bundle}
            isAdmin={isAdmin}
            latestAnalysis={latestAnalysis}
            onAskAI={() => onSelectTab("ai")}
            tool={tool}
          />
        )}
        {activeTab === "findings" && <FindingsView error={bundle?.errors?.findings} findings={findings} />}
        {activeTab === "m4-neural" && isAdmin && (
          <M4SemanticsPanel key={String(tool?.id) + ":" + String(tool?.current_fingerprint || "")} latestAnalysis={latestAnalysis} tool={tool} />
        )}
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

function AnalysisOverview({ bundle, isAdmin, latestAnalysis, onAskAI, tool }) {
  const current = isCurrentAnalysis(tool, latestAnalysis, bundle);
  const ledger = current && riskLedgerMatchesRecord(latestAnalysis)
    ? latestAnalysis?.semantic_scores?.m7_risk_evidence : null;
  const findings = current && !bundle?.errors?.findings
    ? (bundle?.findings || []).filter((finding) =>
        !finding.analysis_id || finding.analysis_id === latestAnalysis.id)
    : null;
  const changes = current && Array.isArray(latestAnalysis?.drift_result?.changes)
    ? latestAnalysis.drift_result.changes : null;
  const drift = driftComparisonState(latestAnalysis, bundle, current);
  // TA-02: the persisted M3 SHADOW projection, never a label/regex guess.
  const m3 = current ? latestAnalysis?.m3_shadow : null;
  const restriction = bundle?.status?.status_reason_detail;
  return (
    <>
      <SectionError error={bundle?.errors?.status} title="Security results" />
      <section className="operator-summary" aria-label="Security summary">
        <div className="operator-summary-head">
          <h4>Security summary</h4>
          <strong>{current ? humanize(latestAnalysis?.risk_level || tool.risk_level) : "Not up to date"}</strong>
        </div>
        {!current ? (
          <p role="status">A current security check is unavailable. Refresh before making a decision.</p>
        ) : (
          <>
            <div className="operator-checks">
              <div>
                <span>Instruction-injection check (advisory)</span>
                <strong>{m3SummaryLine(m3)}</strong>
              </div>
              <div className={"drift-state drift-state-" + drift.state} data-drift-state={drift.state}>
                <span>Tool changes</span>
                <span className="drift-value">
                  <strong>{drift.label}</strong>
                  <small>{drift.detail}</small>
                </span>
              </div>
              <div>
                <span>Other security findings</span>
                <strong>{findings === null ? "Result unavailable"
                  : findings.length === 0 ? "No findings recorded"
                    : findings.length + " finding(s) to review"}</strong>
              </div>
            </div>
            <M3ShadowDetails m3={m3} />
          </>
        )}
      </section>

      {restriction && (
        <section className="operator-caution" aria-label="Why this tool is restricted">
          <h4>Why is this tool restricted?</h4>
          <p>{restriction.label}</p>
          <p><strong>What to do:</strong> {restriction.next_action}</p>
          <p className="muted-text">Restriction code: <code>{restriction.code}</code></p>
        </section>
      )}

      <RiskEvidenceSummary evidence={ledger} current={current} findings={findings} />

      {current && changes?.length > 0 && (
        <section className="operator-changes" aria-label="Tool changes">
          <h4>What changed?</h4>
          <ul>
            {changes.slice(0, 3).map((change, index) => {
              const item = driftChangeDescription(change);
              return (
                <li key={index}>
                  <strong>{item.title}</strong>
                  {item.detail && item.detail !== "Exact change recorded" && <span>{item.detail}</span>}
                </li>
              );
            })}
          </ul>
          {changes.length > 3 && <p>{changes.length - 3} more in Technical details.</p>}
        </section>
      )}

      <section className="operator-next-step" aria-label="Suggested next step">
        <h4>Next step</h4>
        <p>{nextAnalysisAction(tool, latestAnalysis, current)}</p>
        {isAdmin && current && (
          <button className="secondary-action" type="button" onClick={onAskAI}>
            Explain with AI
          </button>
        )}
      </section>

      <details className="operator-technical-details">
        <summary>Technical analysis details</summary>
        <dl className="compact-dl analysis-overview-list">
          <InfoRow label="Analysis status" value={latestAnalysis?.analysis_status || tool.analysis_status} />
          <InfoRow label="Review status" value={latestAnalysis?.review_status || tool.review_status} />
          <InfoRow label="Risk score" value={current ? latestAnalysis?.risk_score : "Not verified"} />
          <InfoRow label="Consistency check" value={latestAnalysis?.consistency_status || tool.consistency_status} />
          <InfoRow label="Drift check" value={latestAnalysis?.drift_status || tool.drift_status} />
          <InfoRow label="Analyzer revision" value={latestAnalysis?.analyzer_revision || tool.analyzer_revision} />
          <InfoRow label="Completed" value={formatDate(latestAnalysis?.completed_at)} />
          <InfoRow label="Historical analyzer signal" value={formatSemanticDecision(latestAnalysis?.semantic_scores)} />
        </dl>
        <p>Some checks can be incomplete. This report does not authorize MCP execution.</p>
      </details>
    </>
  );
}

const M3_UNAVAILABLE = {
  M3_NOT_RECORDED_FOR_THIS_ANALYSIS: "Not recorded for this analysis (recorded before the check was persisted). Re-run the analysis to record it.",
  ANALYSIS_FAILED_BEFORE_M3: "Unavailable: the analysis failed before this check ran.",
  M3_REPORT_NOT_PRODUCED: "Unavailable: the check produced no report.",
  M3_REPORT_NOT_RETAINED_BY_DISCOVERY_STAGE: "Unavailable: this staged analysis did not keep the check report.",
  M3_REPORT_AUTHORITY_INVALID: "Unavailable: the report was rejected because it claimed decision authority.",
};

const M3_RESULT = {
  OBSERVATION_PRESENT: "Possible instruction signals found; review them.",
  NO_CANDIDATE_NOT_A_CLEAN_VERDICT: "No signal found. This is not a clean verdict.",
  INCOMPLETE_INSPECTION_OBSERVATION_PRESENT: "Signals found, but the inspection was incomplete.",
  INCOMPLETE_INSPECTION_NO_CANDIDATE_NOT_A_CLEAN_VERDICT: "No signal found in an incomplete inspection.",
};

export function m3SummaryLine(m3) {
  if (!m3) return "Result unavailable";
  if (!m3.available) return M3_UNAVAILABLE[m3.unavailable_reason] || "Unavailable";
  return M3_RESULT[m3.result_status] || "Recorded; see details";
}

// TA-02: advisory evidence only. Never presented as allowing or blocking.
function M3ShadowDetails({ m3 }) {
  if (!m3?.available) return null;
  return (
    <details className="m3-shadow-details">
      <summary>Instruction-injection check details (advisory, does not decide)</summary>
      <p>Passive observation only. This check cannot allow or block a tool; recorded security findings and your review decide.</p>
      <dl className="compact-dl">
        <InfoRow label="Inspection" value={humanize(m3.scope?.execution_status || "unknown")} />
        <InfoRow label="Fields inspected" value={m3.scope?.inspected_fields ?? "Unknown"} />
        <InfoRow label="Language coverage" value={humanize(m3.scope?.language_coverage || "unknown")} />
        <InfoRow label="Signals" value={`${m3.signal_count ?? 0}${m3.signals_truncated ? " (list truncated)" : ""}`} />
      </dl>
      {m3.signals?.length > 0 && (
        <ul>
          {m3.signals.map((signal, index) => (
            <li key={index}>
              <code>{signal.rule_id || "unknown rule"}</code> in <code>{signal.field_pointer || "unknown field"}</code>
              {" "}({humanize(signal.evidence_level || "unresolved")}{signal.source_bound ? ", located in source" : ", not located"})
            </li>
          ))}
        </ul>
      )}
      {m3.limitations?.length > 0 && (
        <p>Limits: {m3.limitations.map(humanize).join("; ")}.</p>
      )}
    </details>
  );
}

function RiskEvidenceSummary({ evidence, current, findings }) {
  const drivers = Array.isArray(evidence?.risk_drivers) ? evidence.risk_drivers : [];
  return (
    <section className="operator-risk-reasons" aria-label="Risk explanation">
      <h4>Why this risk?</h4>
      {!current ? (
        <p>Current evidence is unavailable.</p>
      ) : !evidence ? (
        <p>Detailed reasons are unavailable for this analysis.</p>
      ) : drivers.length === 0 ? (
        <p>No specific risk drivers were recorded. This does not prove the tool is safe.</p>
      ) : (
        <>
          <ul>
            {drivers.slice(0, 3).map((driver, index) => (
              <li key={driver.evidence_summary_sha256 || index}>
                {driver.source_type === "DRIFT"
                  ? "Tool description or contract changed"
                  : friendlyFindingTitle((findings || []).find((finding) => finding.code === driver.code) || {})}
              </li>
            ))}
          </ul>
          {drivers.length > 3 && <p>More details are available in Technical details.</p>}
          <details className="operator-risk-technical">
            <summary>Evidence and coverage details</summary>
            <p>Risk score: {evidence.risk_score} / 100.
              Coverage: {humanize(evidence.coverage?.status || "UNKNOWN")}.
              Independent corroboration: {humanize(evidence.corroboration_status || "UNKNOWN")}.
              Authorization: not evaluated.</p>
            <ul>
              {drivers.map((driver,index) => <li key={index}>
                {driver.source_type}: {driver.code || driver.status || "Unknown"} ?
                contribution {driver.contribution ?? "?"}
              </li>)}
            </ul>
          </details>
        </>
      )}
    </section>
  );
}

function AnalysisStat({ badge = false, label, value }) {
  return <div className="analysis-stat"><span>{label}</span>{badge ? <Badge value={value} /> : <strong>{value}</strong>}</div>;
}

function InfoRow({ label, value }) {
  return <div><dt>{label}</dt><dd>{value ?? "-"}</dd></div>;
}

// TA-02 / XC-03: show what the backend recorded. The GUI never reclassifies a
// finding (e.g. as "prompt injection") from words in its code or title.
export function friendlyFindingTitle(finding) {
  // The finding catalogue may contain upstream, untrusted tool text.
  // Render it as text (React escapes markup), with a strict display budget.
  const original = typeof finding?.title === "string" ? finding.title : "";
  const title = original.replace(/[\u0000-\u001f\u007f-\u009f]/g, " ").replace(/\s+/g, " ").trim();
  if (title && !/^[A-Z0-9_ -]+$/.test(title)) {
    return title.length > 140 ? title.slice(0, 139).trimEnd() + "…" : title;
  }
  const code = typeof finding?.code === "string"
    ? finding.code.replace(/[^A-Za-z0-9_ -]/g, "").slice(0, 96) : "";
  return code ? humanize(code.toLowerCase()) : "Security finding to review";
}

// A source is displayed only if the corresponding finding actually carries
// a bounded, structured JSON pointer/offset; never invent a line of source
// code or print a machine-local absolute path.
export function findingEvidenceLocation(finding) {
  const evidence = finding?.evidence;
  if (!evidence || typeof evidence !== "object" || Array.isArray(evidence)) return null;
  const location = evidence.location && typeof evidence.location === "object"
    ? evidence.location : evidence;
  const path = location.source_path ?? location.source_pointer ?? location.path;
  if (typeof path !== "string" || !/^\/(?:[^~/]|~[01])+(?:\/(?:[^~/]|~[01])+)*$/.test(path)
      || path.length > 200 || path.split("/").some((part) => part === "." || part === "..")) return null;
  const start = location.start ?? location.start_offset;
  const end = location.end ?? location.end_offset;
  if (start === undefined && end === undefined) return path + " (field)";
  if (!Number.isInteger(start) || !Number.isInteger(end) || start < 0
      || end <= start || end > 1000000) return null;
  return path + " (characters " + start + "–" + end + ")";
}
const FINDING_IMPACT = {
  BLOCK: "Blocks the tool during deterministic security analysis",
  REVIEW: "Requires a human security review; not an independent block",
  INFO: "Informational observation; no independent blocking decision",
};

export function findingImpactLabel(finding) {
  return FINDING_IMPACT[finding?.evidence?.decision] ||
    "Decision impact not recorded; severity alone does not prove a block.";
}

export function FindingsView({ error, findings }) {
  const findingPagination = usePagination(findings, String(findings.length));
  if (error) return <SectionError error={error} title="Findings" />;
  if (findings.length === 0) return <div className="empty-state">No findings for the latest analysis.</div>;
  return (
    <div className="finding-list">
      {findingPagination.pageItems.map((finding, index) => (
        <article className="finding-card" key={finding.id || `${finding.code}-${index}`}>
          <div className="finding-heading">
            <div><strong>{friendlyFindingTitle(finding)}</strong></div>
            <Badge value={finding.severity} />
          </div>
          <p className="hint-text" role="note">
            <strong>Decision impact:</strong>{" "}
            {findingImpactLabel(finding)}
          </p>
          <p>{finding.summary || finding.message || finding.evidence?.summary || "No summary provided."}</p>
          {finding.recommendation && <div className="finding-recommendation"><strong>Recommendation</strong><span>{finding.recommendation}</span></div>}
          <details className="operator-technical-details">
            <summary>Finding evidence</summary>
            <dl className="inline-metadata">
              <div><dt>Code</dt><dd>{finding.code || "-"}</dd></div>
              <div><dt>Source</dt><dd>{finding.source || "-"}</dd></div>
              <div><dt>Exact source location</dt><dd>{findingEvidenceLocation(finding) || "Not recorded in this finding"}</dd></div>
              <div><dt>Confidence</dt><dd>{formatConfidence(finding.confidence)}</dd></div>
            </dl>
          </details>
        </article>
      ))}
      <Pagination
        label="Analysis findings"
        onPageChange={findingPagination.setPage}
        page={findingPagination.page}
        pageCount={findingPagination.pageCount}
        total={findingPagination.total}
      />
    </div>
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
  const historyPagination = usePagination(rows, `${title}|${rows.length}`);
  return (
    <section>
      <h4>{title}</h4>
      <SectionError error={error} title={title} />
      {!error && (rows.length === 0 ? <div className="empty-state">No {title.toLowerCase()} recorded.</div> : (
        <div className="table-shell history-table"><table><thead><tr><th>Recorded</th><th>Status</th><th>Fingerprint</th><th>Evidence / reviewer</th></tr></thead><tbody>
          {historyPagination.pageItems.map((row, index) => {
            const status = row.analysis_status || row.review_status || row.status || row.action || "-";
            return <tr key={row.id || index}>
              <td title={formatDate(row.completed_at || row.created_at || row.observed_at || row.first_seen_at)}>{formatDate(row.completed_at || row.created_at || row.observed_at || row.first_seen_at)}</td>
              <td><span className="history-status" title={status}>{humanize(status)}</span></td>
              <td><span className="history-fingerprint" title={row.fingerprint || "-"}>{shorten(row.fingerprint)}</span></td>
              <td>{title === "Reviews" ? (
                <details><summary>Why was this review recorded?</summary>
                  <p><strong>Reviewer:</strong> {row.reviewer || "Not recorded"}</p>
                  <p><strong>Justification:</strong> {row.justification || "No justification preserved"}</p>
                  <p><strong>Version:</strong> {row.version_id ?? "Unknown"}; Analysis: {row.analysis_id ?? "Unknown"}</p>
                  <p><strong>Reviewed fingerprint:</strong> <code>{row.fingerprint || "Not recorded"}</code></p>
                  <p>This historical review is tied to the recorded observation;
                    it does not automatically authorize a different tool version
                    or a Runtime call.</p>
                </details>
              ) : <span>Open the technical evidence for this analysis or observation.
                This table does not claim independent source verification.</span>}</td>
            </tr>;
          })}
        </tbody></table></div>
      ))}
      {!error && (
        <Pagination
          label={title}
          onPageChange={historyPagination.setPage}
          page={historyPagination.page}
          pageCount={historyPagination.pageCount}
          total={historyPagination.total}
        />
      )}
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

function formatSemanticDecision(scores) {
  if (!scores) return "Unavailable";
  if (scores.flagged) return "Previous analyzer: flagged";
  if (scores.abstained) return "Previous analyzer: abstained";
  if (scores.model_flagged) return "Previous analyzer: uncorroborated signal";
  return "Previous analyzer: no flag";
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

function displayReviewStatus(value) {
  const key = String(value || "UNKNOWN").toUpperCase();
  return {
    REVIEW_REQUIRED: "Needs review",
    PENDING: "Pending",
    APPROVED: "Approved automatically (framework baseline)",
    ADMIN_ALLOWED: "Approved by an administrator",
    BLOCKED: "Blocked",
  }[key] || humanize(value || "Unknown");
}

function formatDate(value) {
  return formatServerTime(value);
}

const ELIGIBILITY_NEXT_ACTION = {
  RUN_ANALYSIS: "Run the tool analysis again.",
  RUN_DISCOVERY: "Refresh discovery for this server.",
  WAIT_OR_RERUN_ANALYSIS: "Wait for the analysis to finish, or run it again.",
  RESOLVE_ANALYSIS_STATUS: "Resolve the analysis status first (blocked, failed or restricted tools cannot be allowed).",
  RESOLVE_REVIEW_STATUS: "Resolve the review status first.",
  RECORD_REVIEW_DECISION: "Record a review decision with a justification.",
};

// TA-06: the eligibility decision comes from the backend contract only.
// This function only renders it; it never recomputes the security rule.
export function approvalDisabledReason(bundle, latestAnalysis) {
  if (bundle?.errors?.eligibility) {
    return "Cannot allow: eligibility could not be verified. Refresh before deciding.";
  }
  const eligibility = bundle?.eligibility;
  if (!eligibility) {
    return "Cannot allow: eligibility has not been loaded.";
  }
  if (eligibility.fingerprint && latestAnalysis?.fingerprint
      && eligibility.fingerprint !== latestAnalysis.fingerprint) {
    return "Cannot allow: the evidence changed while loading. Refresh before deciding.";
  }
  if (!eligibility.eligible) {
    const first = eligibility.reasons?.[0];
    const next = ELIGIBILITY_NEXT_ACTION[eligibility.next_action];
    return `Cannot allow: ${first?.message || "not eligible."}${next ? ` ${next}` : ""}`;
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
  const key = String(value || "unknown").toUpperCase();
  const labels = {
    REVIEW_REQUIRED: "Needs review",
    PENDING_ANALYSIS: "Not analyzed",
    ANALYSIS_FAILED: "Check failed",
    ADMIN_ALLOWED: "Approved by an administrator",
    APPROVED: "Approved automatically (framework baseline)",
    QUARANTINED: "Restricted",
  };
  const label = labels[key] || key.replaceAll("_", " ").toLowerCase().replace(/^./, (x) => x.toUpperCase());
  return <span className={"badge " + badgeClass(value)}>{label}</span>;
}

function badgeClass(value) {
  const normalized = String(value || "").toLowerCase();
  if (["approved", "admin_allowed", "consistent", "none"].includes(normalized)) {
    return "badge-success";
  }
  if (["blocked", "critical", "high"].includes(normalized)) {
    return "badge-danger";
  }
  if (["review_required", "quarantined", "analysis_failed", "medium", "low"].includes(normalized)) {
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

// Disabled controls do not reliably receive keyboard focus or reveal title tooltips.
// Keep both security preconditions visible to ADMIN users and associate each
// control with its reason. The backend remains authoritative for every action.
export function ReviewActionControls({
  isAdmin, busy = false, approveDisabledReason = "", blockDisabledReason = "",
  onApprove, onBlock,
}) {
  if (!isAdmin) return null;
  return (
    <>
      <div className="button-row">
        <button className="secondary-action" type="button"
          disabled={busy || Boolean(approveDisabledReason)}
          aria-describedby={approveDisabledReason ? "review-approval-unavailable" : undefined}
          onClick={onApprove}>
          Approve review
        </button>
        <button className="danger-action" type="button"
          disabled={busy || Boolean(blockDisabledReason)}
          aria-describedby={blockDisabledReason ? "review-block-unavailable" : undefined}
          onClick={onBlock}>
          Block tool
        </button>
      </div>
      {approveDisabledReason && (
        <p className="hint-text" id="review-approval-unavailable" role="note">
          <strong>Approval unavailable:</strong> {approveDisabledReason}
        </p>
      )}
      {blockDisabledReason && (
        <p className="hint-text" id="review-block-unavailable" role="note">
          <strong>Block action unavailable:</strong> {blockDisabledReason}
        </p>
      )}
    </>
  );
}

export default ToolAnalysis;
