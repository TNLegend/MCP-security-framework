import { useEffect, useMemo, useState } from "react";

function Inventory({ servers = [], tools = [], loading = false }) {
  const [selectedServerId, setSelectedServerId] = useState(null);
  const [selectedToolId, setSelectedToolId] = useState(null);

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
          <ServerDetailPanel server={selectedServer} />
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

        {selectedTool && <ToolDetailPanel tool={selectedTool} />}
      </div>
    </section>
  );
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

function ServerDetailPanel({ server }) {
  return (
    <div className="detail-panel">
      <h3>{getServerDisplayName(server)}</h3>
      <div className="metadata-grid">
        <MetadataSection
          title="MCP native metadata"
          items={[
            ["protocol_version", server.protocol_version],
            ["transport", server.transport],
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

function ToolDetailPanel({ tool }) {
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
          ]}
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
      No MCP server discovered yet. Start the backend, start the MCP HTTP lab
      server, then run the discovery script.
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

function getBadgeClass(value) {
  const normalized = String(value || "unknown").toLowerCase();

  if (normalized === "low" || normalized === "allowed_by_default") {
    return "badge-low";
  }

  if (
    normalized === "medium" ||
    normalized === "pending_analysis" ||
    normalized === "pending_review" ||
    normalized === "requires_policy_check"
  ) {
    return "badge-medium badge-warning";
  }

  if (normalized === "high") {
    return "badge-high";
  }

  if (normalized === "lab_trusted") {
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
    item.policy_status === "pending_review"
  );
}

export default Inventory;
