import { useEffect, useMemo, useState } from "react";
import { discoverHttpMcpServer, fetchToolAnalysisBundle } from "../api/client";
import { buildGovernedEndpoint } from "../utils/gateway";

function Inventory({
  isAdmin = false,
  onRefresh,
  runtimeStatus,
  servers = [],
  tools = [],
  loading = false,
}) {
  const [selectedServerId, setSelectedServerId] = useState(null);
  const [selectedToolId, setSelectedToolId] = useState(null);
  const [toolAnalysis, setToolAnalysis] = useState(null);
  const [toolAnalysisLoading, setToolAnalysisLoading] = useState(false);
  const [endpoint, setEndpoint] = useState("http://127.0.0.1:9000/mcp");
  const [authMode, setAuthMode] = useState("NONE");
  const [credentialRef, setCredentialRef] = useState("");
  const [discovering, setDiscovering] = useState(false);
  const [discoverResult, setDiscoverResult] = useState("");
  const [discoverError, setDiscoverError] = useState("");

  const selectedServer = useMemo(
    () => servers.find((server) => server.id === selectedServerId) || null,
    [selectedServerId, servers],
  );

  const selectedServerTools = useMemo(() => {
    if (!selectedServer) {
      return [];
    }

    return tools.filter((tool) => tool.server_id === selectedServer.id);
  }, [selectedServer, tools]);

  const selectedTool = useMemo(
    () => selectedServerTools.find((tool) => tool.id === selectedToolId) || null,
    [selectedServerTools, selectedToolId],
  );

  const sensitiveToolCount = tools.filter((tool) => tool.is_sensitive === true).length;
  const pendingCount =
    servers.filter((server) => hasPendingStatus(server, "server")).length +
    tools.filter((tool) => hasPendingStatus(tool, "tool")).length;

  useEffect(() => {
    if (servers.length === 0) {
      setSelectedServerId(null);
      return;
    }

    const selectedStillExists = servers.some((server) => server.id === selectedServerId);
    if (!selectedStillExists) {
      setSelectedServerId(servers[0].id);
    }
  }, [selectedServerId, servers]);

  useEffect(() => {
    if (!selectedServer) {
      setSelectedToolId(null);
      return;
    }

    const selectedToolBelongsToServer = selectedServerTools.some(
      (tool) => tool.id === selectedToolId,
    );

    if (!selectedToolBelongsToServer) {
      setSelectedToolId(selectedServerTools[0]?.id ?? null);
    }
  }, [selectedServer, selectedServerTools, selectedToolId]);

  useEffect(() => {
    let cancelled = false;
    if (!selectedTool) {
      setToolAnalysis(null);
      return;
    }

    setToolAnalysisLoading(true);
    fetchToolAnalysisBundle(selectedTool.id)
      .then((bundle) => {
        if (!cancelled) {
          setToolAnalysis(bundle);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setToolAnalysis(null);
        }
      })
      .finally(() => {
        if (!cancelled) {
          setToolAnalysisLoading(false);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [selectedTool]);

  if (loading) {
    return (
      <section className="page-section">
        <div className="section-heading">
          <h2>MCP Inventory</h2>
          <p>Loading inventory...</p>
        </div>
      </section>
    );
  }

  return (
    <section className="page-section">
      <div className="section-heading">
        <h2>MCP Inventory</h2>
        <p>{servers.length} server(s), {tools.length} tool(s)</p>
      </div>

      {isAdmin && (
        <form className="action-panel inline-form" onSubmit={handleDiscover}>
          <label>
            MCP HTTP endpoint
            <input
              onChange={(event) => setEndpoint(event.target.value)}
              placeholder="http://127.0.0.1:9000/mcp"
              required
              type="url"
              value={endpoint}
            />
          </label>
          <label>
            Upstream authentication
            <select onChange={(event) => setAuthMode(event.target.value)} value={authMode}>
              <option value="NONE">None</option>
              <option value="BEARER">Bearer credential reference</option>
            </select>
          </label>
          {authMode === "BEARER" && (
            <label>
              Credential secret reference
              <input
                onChange={(event) => setCredentialRef(event.target.value)}
                placeholder="mcp/vendor/service.token"
                required
                value={credentialRef}
              />
            </label>
          )}
          <button className="secondary-action" disabled={discovering} type="submit">
            {discovering ? "Discovering..." : "Register / Discover MCP"}
          </button>
          {discoverResult && <span className="success-text">{discoverResult}</span>}
          {discoverError && <span className="error-text">{discoverError}</span>}
        </form>
      )}

      <div className="summary-grid">
        <SummaryCard label="MCP Servers" value={servers.length} />
        <SummaryCard label="MCP Tools" value={tools.length} />
        <SummaryCard label="Sensitive Tools" value={sensitiveToolCount} />
        <SummaryCard label="Pending Analysis" value={pendingCount} />
      </div>

      <div className="inventory-layout">
        <div className="inventory-section">
          <div className="section-heading compact-heading">
            <h3>MCP Servers</h3>
            <p>{servers.length} total</p>
          </div>
          <ServerTable
            servers={servers}
            tools={tools}
            selectedServerId={selectedServerId}
            onSelectServer={setSelectedServerId}
          />
        </div>

        {selectedServer ? (
          <ServerDetailPanel server={selectedServer} gatewayStatus={runtimeStatus?.gateway} />
        ) : (
          <EmptyState />
        )}

        {selectedServer && (
          <div className="inventory-section">
            <div className="section-heading compact-heading">
              <h3>Tools For Selected Server</h3>
              <p>{selectedServerTools.length} tool(s)</p>
            </div>
            <ToolsTable
              tools={selectedServerTools}
              selectedToolId={selectedToolId}
              onSelectTool={setSelectedToolId}
            />
          </div>
        )}

        {selectedTool && (
          <ToolDetailPanel
            tool={selectedTool}
            analysis={toolAnalysis}
            analysisLoading={toolAnalysisLoading}
          />
        )}
      </div>
    </section>
  );

  async function handleDiscover(event) {
    event.preventDefault();
    setDiscovering(true);
    setDiscoverError("");
    setDiscoverResult("");
    try {
      const result = await discoverHttpMcpServer(
        endpoint,
        "2025-11-25",
        authMode,
        credentialRef,
      );
      setDiscoverResult(
        `Imported ${result.total_tools_imported} tool(s); ${result.tools_quarantined} require review.`,
      );
      await onRefresh?.();
    } catch (err) {
      setDiscoverError(err.message || "Discovery failed");
    } finally {
      setDiscovering(false);
    }
  }
}

function SummaryCard({ label, value }) {
  return (
    <div className="summary-card">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function ServerTable({ servers, tools, selectedServerId, onSelectServer }) {
  if (servers.length === 0) {
    return <EmptyState />;
  }

  return (
    <div className="table-shell inventory-table">
      <table>
        <thead>
          <tr>
            <th>Server</th>
            <th>Endpoint</th>
            <th>Transport</th>
            <th>Protocol</th>
            <th>Tools</th>
            <th>Trust</th>
            <th>Security</th>
            <th>Last seen</th>
          </tr>
        </thead>
        <tbody>
          {servers.map((server) => {
            const toolCount = tools.filter((tool) => tool.server_id === server.id).length;

            return (
              <tr
                className={server.id === selectedServerId ? "selected-row" : ""}
                key={server.id}
                onClick={() => onSelectServer(server.id)}
                role="button"
                tabIndex="0"
              >
                <td>{getServerDisplayName(server)}</td>
                <td>{displayValue(server.endpoint)}</td>
                <td>{displayValue(server.transport)}</td>
                <td>{displayValue(server.protocol_version)}</td>
                <td>{toolCount}</td>
                <td>
                  <Badge value={server.trust_status} />
                </td>
                <td>
                  <Badge value={server.security_status} />
                </td>
                <td>{formatDate(server.last_seen_at)}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function ToolsTable({ tools, selectedToolId, onSelectTool }) {
  if (tools.length === 0) {
    return (
      <div className="empty-state">
        No tools imported for the selected MCP server.
      </div>
    );
  }

  return (
    <div className="table-shell inventory-table">
      <table>
        <thead>
          <tr>
            <th>Tool</th>
            <th>Description</th>
            <th>Sensitivity</th>
            <th>Risk</th>
            <th>Policy</th>
            <th>Sensitive</th>
            <th>Last analyzed</th>
          </tr>
        </thead>
        <tbody>
          {tools.map((tool) => (
            <tr
              className={tool.id === selectedToolId ? "selected-row" : ""}
              key={tool.id}
              onClick={() => onSelectTool(tool.id)}
              role="button"
              tabIndex="0"
            >
              <td>{getToolDisplayName(tool)}</td>
              <td>{displayValue(tool.description)}</td>
              <td>
                <Badge value={tool.sensitivity} />
              </td>
              <td>{displayValue(tool.risk_score)}</td>
              <td>
                <Badge value={tool.policy_status} />
              </td>
              <td>{tool.is_sensitive ? "yes" : "no"}</td>
              <td>{formatDate(tool.last_analyzed_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ServerDetailPanel({ server, gatewayStatus }) {
  const governedEndpoint = buildGovernedEndpoint(gatewayStatus, server.id);
  return (
    <div className="detail-panel">
      <h3>{getServerDisplayName(server)}</h3>
      <div className="endpoint-pair">
        <div>
          <span>Upstream</span>
          <code>{displayValue(server.endpoint)}</code>
        </div>
        <div>
          <span>Governed Endpoint</span>
          <code>{governedEndpoint || "Gateway endpoint unavailable"}</code>
          {governedEndpoint && (
            <button
              className="tiny-action"
              onClick={() => navigator.clipboard?.writeText(governedEndpoint)}
              type="button"
            >
              Copy
            </button>
          )}
        </div>
      </div>
      <div className="metadata-grid">
        <MetadataSection
          title="MCP native metadata"
          items={[
            ["protocol_version", server.protocol_version],
            ["transport", server.transport],
            ["auth_mode", server.auth_mode],
            ["endpoint", server.endpoint],
            ["server_info_name", server.server_info_name],
            ["server_info_title", server.server_info_title],
            ["server_info_version", server.server_info_version],
            ["server_info_description", server.server_info_description],
            ["server_info_website_url", server.server_info_website_url],
            ["capabilities", server.capabilities, "json"],
            ["instructions", server.instructions],
            ["raw_initialize_result", server.raw_initialize_result, "json"],
          ]}
        />
        <MetadataSection
          title="Framework security metadata"
          items={[
            ["trust_status", server.trust_status, "badge"],
            ["security_status", server.security_status, "badge"],
            ["status", server.status],
            ["last_seen_at", formatDate(server.last_seen_at)],
            ["last_scan_at", formatDate(server.last_scan_at)],
            ["notes", server.notes],
          ]}
        />
      </div>
    </div>
  );
}

function ToolDetailPanel({ tool, analysis, analysisLoading }) {
  const latestAnalysis = analysis?.analyses?.[0] || null;

  return (
    <div className="detail-panel">
      <h3>{getToolDisplayName(tool)}</h3>
      <div className="metadata-grid">
        <MetadataSection
          title="MCP native tool metadata"
          items={[
            ["name", tool.name],
            ["title", tool.title],
            ["description", tool.description],
            ["icons", tool.icons, "json"],
            ["input_schema", tool.input_schema, "json"],
            ["output_schema", tool.output_schema, "json"],
            ["annotations", tool.annotations, "json"],
            ["execution", tool.execution, "json"],
            ["raw_tool_definition", tool.raw_tool_definition, "json"],
          ]}
        />
        <MetadataSection
          title="Framework security metadata"
          items={[
            ["risk_score", tool.risk_score],
            ["sensitivity", tool.sensitivity, "badge"],
            ["description_risk_score", tool.description_risk_score],
            ["policy_status", tool.policy_status, "badge"],
            ["is_sensitive", tool.is_sensitive ? "true" : "false"],
            ["status", tool.status],
            ["last_analyzed_at", formatDate(tool.last_analyzed_at)],
            ["analysis_status", tool.analysis_status, "badge"],
            ["risk_level", tool.risk_level, "badge"],
            ["semantic_flagged", tool.semantic_flagged ? "true" : "false"],
            [
              "deterministic_critical_finding",
              tool.deterministic_critical_finding ? "true" : "false",
            ],
            ["consistency_status", tool.consistency_status, "badge"],
            ["drift_status", tool.drift_status, "badge"],
            ["review_status", tool.review_status, "badge"],
            ["current_fingerprint", shortenFingerprint(tool.current_fingerprint)],
            ["approved_fingerprint", shortenFingerprint(tool.approved_fingerprint)],
            [
              "approved_fingerprint_match",
              tool.approved_fingerprint_match ? "true" : "false",
            ],
            ["analyzer_revision", tool.analyzer_revision],
          ]}
        />
        <MetadataSection
          title="Tool analysis"
          items={
            analysisLoading
              ? [["loading", "Loading analysis..."]]
              : [
                  ["latest_analysis", latestAnalysis?.id],
                  ["semantic_scores", latestAnalysis?.semantic_scores, "json"],
                  ["model_versions", latestAnalysis?.model_versions, "json"],
                  ["baseline", analysis?.baseline, "json"],
                  ["version_count", analysis?.versions?.length ?? 0],
                  ["drift", analysis?.diff, "json"],
                  ["findings", summarizeFindings(analysis?.findings), "json"],
                ]
          }
        />
      </div>
    </div>
  );
}

function MetadataSection({ title, items }) {
  return (
    <section className="metadata-section">
      <h4>{title}</h4>
      <dl>
        {items.map(([label, value, type]) => (
          <div className="metadata-row" key={label}>
            <dt>{label}</dt>
            <dd>
              {type === "json" ? (
                <pre className="json-block">{formatJson(value)}</pre>
              ) : type === "badge" ? (
                <Badge value={value} />
              ) : (
                displayValue(value)
              )}
            </dd>
          </div>
        ))}
      </dl>
    </section>
  );
}

function EmptyState() {
  return (
    <div className="empty-state">
      No MCP server discovered yet. An ADMIN can register and discover an MCP HTTP
      endpoint from this page.
    </div>
  );
}

function Badge({ value }) {
  const display = displayValue(value);
  return <span className={`badge ${getBadgeClass(value)}`}>{display}</span>;
}

function formatDate(value) {
  if (!value) {
    return "\u2014";
  }

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return String(value);
  }

  return date.toLocaleString();
}

function formatJson(value) {
  if (value === null || value === undefined || value === "") {
    return "\u2014";
  }

  if (typeof value === "string") {
    try {
      return JSON.stringify(JSON.parse(value), null, 2);
    } catch {
      return value;
    }
  }

  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

function displayValue(value) {
  if (value === null || value === undefined || value === "") {
    return "\u2014";
  }

  return value;
}

function shortenFingerprint(value) {
  if (!value) {
    return value;
  }
  return `${String(value).slice(0, 12)}...${String(value).slice(-8)}`;
}

function summarizeFindings(findings = []) {
  return findings.map((finding) => ({
    code: finding.code,
    category: finding.category,
    source: finding.source,
    severity: finding.severity,
    confidence: finding.confidence,
    evidence: finding.evidence,
    recommendation: finding.recommendation,
  }));
}

function getBadgeClass(value) {
  const normalized = String(value || "unknown").toLowerCase();

  if (normalized === "low" || normalized === "allowed_by_default") {
    return "badge-low";
  }

  if (
    normalized === "medium" ||
    normalized === "pending_analysis" ||
    normalized === "quarantined" ||
    normalized === "review_required" ||
    normalized === "analysis_failed" ||
    normalized === "pending_review" ||
    normalized === "requires_policy_check"
  ) {
    return "badge-medium badge-warning";
  }

  if (normalized === "high" || normalized === "blocked" || normalized === "critical") {
    return "badge-high";
  }

  if (normalized === "lab_trusted" || normalized === "approved" || normalized === "consistent") {
    return "badge-success";
  }

  return "badge-unknown";
}

function getServerDisplayName(server) {
  return (
    server.server_info_title ||
    server.server_info_name ||
    server.name ||
    server.endpoint ||
    "Unnamed MCP Server"
  );
}

function getToolDisplayName(tool) {
  return tool.title || tool.name || "Unnamed Tool";
}

function hasPendingStatus(item, type) {
  if (type === "server") {
    return (
      !item.security_status ||
      item.security_status === "pending_analysis" ||
      item.security_status === "pending_review"
    );
  }

  return (
    !item.policy_status ||
    item.policy_status === "pending_analysis" ||
    item.policy_status === "pending_review" ||
    item.analysis_status === "PENDING_ANALYSIS" ||
    item.analysis_status === "QUARANTINED" ||
    item.analysis_status === "REVIEW_REQUIRED" ||
    item.analysis_status === "ANALYSIS_FAILED"
  );
}

export default Inventory;
