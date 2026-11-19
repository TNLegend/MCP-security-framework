import { useEffect, useMemo, useState } from "react";
import { approveTool, blockTool, fetchToolAnalysisBundle } from "../api/client";
import ControlledAIAssistant from "../components/ControlledAIAssistant";
import M4SemanticsPanel from "../components/m4semanticspanel";
import { Pagination, usePagination } from "../components/Pagination";
import ToolContractOnboarding from "../components/ToolContractOnboarding";
import { analysisModuleCards, driftChangeDescription, nextAnalysisAction, riskLedgerMatchesRecord } from "../utils/analysisPresentation";
import {
  activateRowOnKeyboard,
  hasNonEmptyAnalysisEvidence,
  validateToolJustification,
} from "../utils/validation";

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
  const [bundle, setBundle] = useState(null);
  const [bundleToolId, setBundleToolId] = useState(null);
  const [bundleLoading, setBundleLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  const [reviewDialog, setReviewDialog] = useState(null);
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
    : approvalDisabledReason(selectedTool, reviewAnalysis);
  const blockDisabledReason = bundleLoading
    ? "Cannot block: current evidence is still loading."
    : blockActionDisabledReason(selectedTool, reviewAnalysis);

  useEffect(() => {
    if (tools.length === 0) {
      setSelectedToolId(null);
      return;
    }
    if (!tools.some((tool) => tool.id === selectedToolId)) {
      const requested = tools.find((tool) => String(tool.id) === String(requestedToolId));
      setSelectedToolId(requested?.id ?? tools[0].id);
      if (requested) {
        const index = filteredTools.findIndex((tool) => tool.id === requested.id);
        if (index >= 0) toolPagination.setPage(Math.floor(index / toolPagination.pageSize) + 1);
      }
    }
  }, [selectedToolId, requestedToolId, tools]);

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
    if (!reviewDialog || !selectedTool?.current_fingerprint) {
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
      <p className="hint-text" role="note">
        Analyzer findings are advisory, not proof that a tool is safe or unsafe.
        An approved analysis does not grant execution rights. Runtime access
        still requires a valid signed configuration, explicit approval, and
        applicable security contracts.
      </p>

      {message && <div className="success-banner">{message}</div>}
      {error && <div className="error-banner">{error}</div>}

      <div className="analysis-layout">
        <div className="inventory-section">
          <div className="section-heading compact-heading">
            <h3>Tools</h3>
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
              The selected tool is hidden by the current filters; its details remain visible on the right.
            </p>
          )}
          <p className="analysis-mobile-hint hint-text">Scroll sideways to view analysis, review and risk for every tool.</p>
          <div className="table-shell analysis-tool-table" tabIndex="0" aria-label="Tool list, horizontally scrollable on small screens">
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
          <Pagination
            label="Analyzed tools"
            onPageChange={toolPagination.setPage}
            page={toolPagination.page}
            pageCount={toolPagination.pageCount}
            total={toolPagination.total}
          />
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
          <section aria-modal="true" aria-labelledby="analysis-review-dialog-title" className="modal-panel" role="dialog">
            <h3 id="analysis-review-dialog-title">Record {reviewDialog.action} review</h3>
            <p>
              {selectedServer?.server_info_title || selectedServer?.name || selectedTool?.server_id}
              {" / "}
              {selectedTool?.title || selectedTool?.name}
            </p>
            <p className="hint-text">
              This records an administrative analysis decision, not permission to execute an MCP tool.
              Runtime execution still requires signed configuration and the applicable policies.
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
  ["m4-neural", "M4 analysis (SHADOW)"],
  ["overview", "Overview"],
  ["findings", "Findings"],
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
        {ANALYSIS_TABS.filter(([id]) => id !== "m4-neural" || isAdmin).map(([id, label]) => (
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
  const isCurrent = Boolean(bundle && tool?.current_fingerprint
    && bundle?.analyses?.[0]?.id === latestAnalysis?.id
    && !bundle?.errors?.analyses
    && latestAnalysis?.fingerprint === tool.current_fingerprint
    && latestAnalysis?.completed_at
    && tool.analysis_status !== "STALE"
    && latestAnalysis.analysis_status !== "STALE");
  const riskEvidence = isCurrent && riskLedgerMatchesRecord(latestAnalysis)
    ? latestAnalysis?.semantic_scores?.m7_risk_evidence : null;
  const moduleDisplay = analysisModuleCards(tool, latestAnalysis, bundle);
  const changes = moduleDisplay.current && Array.isArray(latestAnalysis?.drift_result?.changes)
    ? latestAnalysis.drift_result.changes : null;
  const similarity = moduleDisplay.current ? latestAnalysis?.drift_result?.similarity : null;
  return (
    <>
      <SectionError error={bundle?.errors?.status} title="Analysis status" />
      <section className="analysis-guidance" aria-label="Analysis next steps">
        <h4>What should I do next?</h4>
        <p>{nextAnalysisAction(tool, latestAnalysis, moduleDisplay.current)}</p>
        <p className="hint-text">Review status and runtime authorization are separate. An approved analysis never by itself permits execution.</p>
        {isAdmin && isCurrent && (
          <button className="secondary-action" type="button" onClick={onAskAI}>
            Ask AI to explain this analysis (advisory only)
          </button>
        )}
      </section>
      <div className="analysis-stat-grid">
        <AnalysisStat label="Current tool state" value={tool.analysis_status} badge />
        <AnalysisStat label="Latest analysis record" value={latestAnalysis?.analysis_status || tool.analysis_status} badge />
        <AnalysisStat label="Review" value={latestAnalysis?.review_status || tool.review_status} badge />
        <AnalysisStat label="Risk level" value={latestAnalysis?.risk_level || tool.risk_level} badge />
        <AnalysisStat label="Risk score" value={latestAnalysis?.risk_score ?? tool.risk_score ?? "-"} />
        <AnalysisStat label="Consistency" value={latestAnalysis?.consistency_status || tool.consistency_status} badge />
        <AnalysisStat label="Drift" value={latestAnalysis?.drift_status || tool.drift_status} badge />
      </div>
      {latestAnalysis?.analysis_status && latestAnalysis.analysis_status !== tool.analysis_status && (
        <p className="hint-text" role="status">
          This analysis record has a different status from the current tool state.
          Historical approval evidence does not authorize runtime execution.
        </p>
      )}
      {latestAnalysis?.evidence_provenance?.state === "REUSED" && (
        <p className="hint-text" role="status">
          Existing analysis evidence reused; no new semantic inference.
          Original analysis status: {latestAnalysis.evidence_provenance.raw_analysis_status}.
          Administrative acceptance preserves the original findings.
        </p>
      )}
      <RiskEvidenceSummary evidence={riskEvidence} isCurrent={isCurrent} />
      <section className="analysis-modules" aria-label="M1 through M7 explained">
        <div className="section-heading compact-heading">
          <h4>What the seven modules tell us</h4>
          <p>Recorded evidence, not automatic permission</p>
        </div>
        <div className="analysis-module-grid">
          {moduleDisplay.cards.map((card) => (
            <article className="analysis-module-card" key={card.id}>
              <div className="analysis-module-heading">
                <span className="analysis-module-id">{card.id}</span>
                <strong>{card.title}</strong>
              </div>
              <p className="analysis-module-status">{card.status}</p>
              <p>{card.explanation}</p>
              <small>{card.detail}</small>
            </article>
          ))}
        </div>
      </section>
      <section className="analysis-drift-explainer" aria-label="M6 tool changes">
        <h4>What changed since the previous tool observation?</h4>
        {changes === null ? (
          <p>Current version-change evidence is unavailable. Do not assume that no changes occurred.</p>
        ) : changes.length === 0 ? (
          <p>No changes are recorded in the current comparison. This is not a runtime safety certification.</p>
        ) : (
          <>
            <p>{changes.length} recorded change(s). Exact details and provenance remain available in Raw evidence.</p>
            <ul className="analysis-drift-list">
              {changes.slice(0, 6).map((change, index) => {
                const description = driftChangeDescription(change);
                return (
                  <li key={index}>
                    <strong>{description.title}</strong>
                    <span>{description.detail}</span>
                    <Badge value={change?.severity || "unknown"} />
                  </li>
                );
              })}
            </ul>
            {changes.length > 6 && <p>{changes.length - 6} more change(s) are recorded in Raw evidence.</p>}
          </>
        )}
        {typeof similarity === "number" && Number.isFinite(similarity) && (
          <p className="hint-text">
            Recorded description similarity: {Math.round(similarity * 100)}% (exact comparison or E5 diagnostic, not a permission).
          </p>
        )}
      </section>
      <dl className="compact-dl analysis-overview-list">
        <InfoRow label="Analyzer revision" value={latestAnalysis?.analyzer_revision || tool.analyzer_revision} />
        <InfoRow label="Completed" value={formatDate(latestAnalysis?.completed_at)} />
        <InfoRow label="Historical analyzer signal" value={formatSemanticDecision(latestAnalysis?.semantic_scores)} />
        <InfoRow label="Deterministic critical finding" value={tool.deterministic_critical_finding ? "Yes" : "No"} />
      </dl>
    </>
  );
}

function RiskEvidenceSummary({ evidence, isCurrent }) {
  const drivers = Array.isArray(evidence?.risk_drivers) ? evidence.risk_drivers : [];
  return (
    <section className="analysis-risk-explanation" aria-label="M7 risk explanation">
      <h4>Why this risk level?</h4>
      {!isCurrent ? (
        <p role="status">No completed, current bundle evidence is available. Historical or stale results must not be treated as current.</p>
      ) : evidence?.schema !== "m7_deterministic_risk_evidence_v1" ? (
        <p role="status">A consistent M7 explanation is unavailable for this current record. The score alone does not establish safety or authorization.</p>
      ) : (
        <>
          <p>
            M7 risk score: <strong>{evidence.risk_score} / 100</strong>.
            The highest deterministic finding or M6 drift contribution determines this score;
            advisory model predictions do not add to it.
          </p>
          {drivers.length === 0 ? (
            <p>No deterministic risk drivers are recorded in this explanation. This does not prove the tool is safe.</p>
          ) : (
            <ul className="analysis-risk-drivers">
              {drivers.slice(0, 5).map((driver, index) => (
                <li key={driver.source_type + "-" + (driver.code || driver.status) + "-" + (driver.evidence_summary_sha256 || index)}>
                  <strong>{driver.source_type === "DRIFT" ? "M6 drift: " + humanize(driver.status) : humanize(driver.code)}</strong>
                  <span>Contribution {driver.contribution} / 100</span>
                  {driver.source_path && <small>Evidence source: {driver.source_path}</small>}
                </li>
              ))}
            </ul>
          )}
          {drivers.length > 5 && <p>{drivers.length - 5} additional drivers are in the technical evidence.</p>}
          <p className="hint-text">
            Coverage: {humanize(evidence.coverage?.status || "UNKNOWN")}.
            {evidence.coverage?.status !== "COMPLETE" && " Missing evidence is not proof of safety."}
            {" "}Independent corroboration: {humanize(evidence.corroboration_status || "UNKNOWN")}.
            {" "}Authorization: not evaluated by M7.
          </p>
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

function FindingsView({ error, findings }) {
  const findingPagination = usePagination(findings, String(findings.length));
  if (error) return <SectionError error={error} title="Findings" />;
  if (findings.length === 0) return <div className="empty-state">No findings for the latest analysis.</div>;
  return (
    <div className="finding-list">
      {findingPagination.pageItems.map((finding, index) => (
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
        <div className="table-shell history-table"><table><thead><tr><th>Recorded</th><th>Status</th><th>Fingerprint</th></tr></thead><tbody>
          {historyPagination.pageItems.map((row, index) => {
            const status = row.analysis_status || row.review_status || row.status || row.action || "-";
            return <tr key={row.id || index}><td title={formatDate(row.completed_at || row.created_at || row.observed_at || row.first_seen_at)}>{formatDate(row.completed_at || row.created_at || row.observed_at || row.first_seen_at)}</td><td><span className="history-status" title={status}>{humanize(status)}</span></td><td><span className="history-fingerprint" title={row.fingerprint || "-"}>{shorten(row.fingerprint)}</span></td></tr>;
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

export default ToolAnalysis;
