import { useMemo, useState } from "react";
import { approveTool, blockTool, fetchToolAnalysisBundle } from "../api/client";

function ToolAnalysis({ analyses = [], isAdmin = false, loading = false, onRefresh, servers = [], tools = [] }) {
  const [selectedToolId, setSelectedToolId] = useState(tools[0]?.id ?? null);
  const [bundle, setBundle] = useState(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  const toolsById = useMemo(() => new Map(tools.map((tool) => [tool.id, tool])), [tools]);
  const serversById = useMemo(
    () => new Map(servers.map((server) => [server.id, server])),
    [servers],
  );
  const selectedTool = toolsById.get(selectedToolId) || tools[0] || null;
  const relevantAnalyses = selectedTool
    ? analyses.filter((analysis) => analysis.tool_id === selectedTool.id)
    : analyses;
  const latestAnalysis = bundle?.analyses?.[0] || relevantAnalyses[0] || null;
  const selectedServer = selectedTool ? serversById.get(selectedTool.server_id) : null;

  async function loadBundle(toolId) {
    setSelectedToolId(toolId);
    setError("");
    setMessage("");
    try {
      setBundle(await fetchToolAnalysisBundle(toolId));
    } catch (err) {
      setBundle(null);
      setError(err.message || "Could not load tool analysis");
    }
  }

  async function review(action) {
    if (!selectedTool?.current_fingerprint) {
      setError("Selected tool has no current fingerprint.");
      return;
    }
    const justification = window.prompt(`${action} justification`);
    if (!justification) {
      return;
    }
    setBusy(true);
    setError("");
    setMessage("");
    try {
      if (action === "Approve") {
        await approveTool(selectedTool.id, selectedTool.current_fingerprint, justification);
      } else {
        await blockTool(selectedTool.id, selectedTool.current_fingerprint, justification);
      }
      setMessage(`${action} recorded.`);
      await onRefresh?.();
      await loadBundle(selectedTool.id);
    } catch (err) {
      setError(err.message || `${action} failed`);
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

      <div className="split-layout">
        <div className="inventory-section">
          <div className="section-heading compact-heading">
            <h3>Tools</h3>
            <p>{tools.length} total</p>
          </div>
          <div className="table-shell">
            <table>
              <thead>
                <tr>
                  <th>Tool</th>
                  <th>Status</th>
                  <th>Review</th>
                  <th>Risk</th>
                </tr>
              </thead>
              <tbody>
                {tools.length === 0 ? (
                  <tr>
                    <td colSpan="4">No tools discovered.</td>
                  </tr>
                ) : (
                  tools.map((tool) => (
                    <tr
                      className={selectedTool?.id === tool.id ? "selected-row" : ""}
                      key={tool.id}
                      onClick={() => loadBundle(tool.id)}
                      role="button"
                      tabIndex="0"
                    >
                      <td>{tool.title || tool.name}</td>
                      <td>
                        <Badge value={tool.analysis_status} />
                      </td>
                      <td>
                        <Badge value={tool.review_status} />
                      </td>
                      <td>{tool.risk_score}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        <div className="detail-panel">
          <h3>{selectedTool ? selectedTool.title || selectedTool.name : "No tool selected"}</h3>
          {selectedTool && (
            <>
              <dl className="compact-dl">
                <div>
                  <dt>server</dt>
                  <dd>{selectedServer?.server_info_title || selectedServer?.name || selectedTool.server_id}</dd>
                </div>
                <div>
                  <dt>current_fingerprint</dt>
                  <dd>{shorten(selectedTool.current_fingerprint)}</dd>
                </div>
                <div>
                  <dt>approved_fingerprint_match</dt>
                  <dd>{selectedTool.approved_fingerprint_match ? "true" : "false"}</dd>
                </div>
                <div>
                  <dt>analysis_context_hash</dt>
                  <dd>{shorten(latestAnalysis?.analysis_context_hash)}</dd>
                </div>
                <div>
                  <dt>semantic_flagged</dt>
                  <dd>{selectedTool.semantic_flagged ? "true" : "false"}</dd>
                </div>
                <div>
                  <dt>deterministic_critical_finding</dt>
                  <dd>{selectedTool.deterministic_critical_finding ? "true" : "false"}</dd>
                </div>
              </dl>

              {isAdmin && (
                <div className="button-row">
                  <button disabled={busy} onClick={() => review("Approve")} type="button">
                    Approve
                  </button>
                  <button disabled={busy} onClick={() => review("Block")} type="button">
                    Block
                  </button>
                </div>
              )}

              <Metadata title="Baseline" value={bundle?.baseline} />
              <Metadata title="Drift / Diff" value={bundle?.diff} />
              <Metadata title="Findings" value={bundle?.findings || []} />
              <Metadata title="Latest semantic scores" value={latestAnalysis?.semantic_scores} />
            </>
          )}
        </div>
      </div>
    </section>
  );
}

function Metadata({ title, value }) {
  return (
    <section className="metadata-section stacked-section">
      <h4>{title}</h4>
      <pre className="json-block">{formatJson(value)}</pre>
    </section>
  );
}

function Badge({ value }) {
  return <span className={`badge ${badgeClass(value)}`}>{value || "unknown"}</span>;
}

function badgeClass(value) {
  const normalized = String(value || "").toLowerCase();
  if (["approved", "consistent", "none", "low"].includes(normalized)) {
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
