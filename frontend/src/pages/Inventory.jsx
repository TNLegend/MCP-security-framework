import { formatServerTime } from "../utils/serverTime.js";
import "./workflowPages.css";
import { useEffect, useMemo, useRef, useState } from "react";
import {
  archiveServer,
  trustServer,
  revokeServerTrust,
  disconnectOAuthMcpServer,
  discoverHttpMcpServer,
  discoverRegisteredMcpServer,
  fetchOAuthCallbackUri,
  fetchBuildSourceBindings,
  fetchToolAnalysisBundle,
  registerOAuthMcpServer,
  startOAuthConnection,
} from "../api/client";
import { useDialogFocus } from "../utils/useDialogFocus";
import { buildGovernedEndpoint } from "../utils/gateway";
import { Pagination, usePagination } from "../components/Pagination";
import {
  LIMITS,
  clearFieldError,
  discoverySubmissionArguments,
  oauthMcpRegistrationPayload,
  pendingToolAnalysisCount,
  reviewRequiredToolCount,
  validateReason,
} from "../utils/validation";

function Inventory({
  isAdmin = false,
  onNavigate,
  onRefresh,
  runtimeStatus,
  servers = [],
  tools = [],
  loading = false,
}) {
  const [selectedServerId, setSelectedServerId] = useState(null);
  const [selectedToolId, setSelectedToolId] = useState(null);
  const [toolAnalysis, setToolAnalysis] = useState(null);
  const [toolAnalysisToolId, setToolAnalysisToolId] = useState(null);
  const [toolAnalysisError, setToolAnalysisError] = useState("");
  const [toolAnalysisLoading, setToolAnalysisLoading] = useState(false);
  const [endpoint, setEndpoint] = useState("http://127.0.0.1:9000/mcp");
  const [authMode, setAuthMode] = useState("NONE");
  const [credentialRef, setCredentialRef] = useState("");
  const [oauthClientId, setOauthClientId] = useState("");
  const [oauthScopes, setOauthScopes] = useState("");
  const [oauthClientSecret, setOauthClientSecret] = useState("");
  const [oauthExpectedIssuer, setOauthExpectedIssuer] = useState("");
  const [oauthCallbackUri, setOauthCallbackUri] = useState("");
  const [discovering, setDiscovering] = useState(false);
  const [discoverResult, setDiscoverResult] = useState("");
  const [discoverError, setDiscoverError] = useState("");
  const [discoverFieldErrors, setDiscoverFieldErrors] = useState({});
  const [includeArchived, setIncludeArchived] = useState(false);
  const [archiveDialog, setArchiveDialog] = useState(null);
  const [archiving, setArchiving] = useState(false);
  const [trustDialog, setTrustDialog] = useState(null);
  const [trustChanging, setTrustChanging] = useState(false);
  const [sourceBindings, setSourceBindings] = useState({});
  const [buildSourceLoading, setBuildSourceLoading] = useState(false);
  const [buildSourceError, setBuildSourceError] = useState("");
  const [inventorySearch, setInventorySearch] = useState("");
  const [buildSourceFilter, setBuildSourceFilter] = useState("ALL");
  const [serverSort, setServerSort] = useState("DEFAULT");
  const [toolSearch, setToolSearch] = useState("");
  const archiveRef = useRef(null);
  const trustRef = useRef(null);

  useEffect(() => {
    if (!archiveDialog && !trustDialog) {
      return undefined;
    }
    function handleEscape(event) {
      if (event.key !== "Escape" || archiving || trustChanging) {
        return;
      }
      event.preventDefault();
      if (archiveDialog) {
        setArchiveDialog(null);
      }
      if (trustDialog) {
        setTrustDialog(null);
      }
    }
    window.addEventListener("keydown", handleEscape);
    return () => window.removeEventListener("keydown", handleEscape);
  }, [archiveDialog, archiving, trustChanging, trustDialog]);

  const visibleServers = useMemo(
    () => includeArchived ? servers : servers.filter((server) => server.status !== "archived"),
    [includeArchived, servers],
  );
  const visibleServerIds = useMemo(
    () => new Set(visibleServers.map((server) => server.id)),
    [visibleServers],
  );
  const visibleTools = useMemo(
    () => tools.filter((tool) => visibleServerIds.has(tool.server_id)),
    [tools, visibleServerIds],
  );

  const selectedServer = useMemo(
    () => visibleServers.find((server) => server.id === selectedServerId) || null,
    [selectedServerId, visibleServers],
  );

  useDialogFocus(Boolean(archiveDialog && isAdmin && selectedServer?.id === archiveDialog.serverId), archiveRef);
  useDialogFocus(Boolean(trustDialog && isAdmin && selectedServer?.id === trustDialog.serverId), trustRef);

  const selectedServerTools = useMemo(() => {
    if (!selectedServer) {
      return [];
    }

    return visibleTools.filter((tool) => tool.server_id === selectedServer.id);
  }, [selectedServer, visibleTools]);

  const selectedTool = useMemo(
    () => selectedServerTools.find((tool) => tool.id === selectedToolId) || null,
    [selectedServerTools, selectedToolId],
  );
  const selectedToolFingerprint = selectedTool?.current_fingerprint || "";
  const selectedToolLastAnalyzedAt = selectedTool?.last_analyzed_at || "";
  const selectedToolAnalysis = toolAnalysisToolId === selectedToolId ? toolAnalysis : null;

  const sensitiveToolCount = visibleTools.filter((tool) => tool.is_sensitive === true).length;
  const pendingCount = pendingToolAnalysisCount(visibleTools);
  const reviewRequiredCount = reviewRequiredToolCount(visibleTools);
  const buildSourceBinding = selectedServer
    ? sourceBindings[String(selectedServer.id)] || null
    : null;
  const filteredServers = useMemo(() => {
    const query = inventorySearch.trim().toLowerCase();
    return visibleServers.filter((server) => {
      const binding = sourceBindings[String(server.id)] || null;
      if (buildSourceFilter === "CONFIGURED" && !binding) return false;
      if (buildSourceFilter === "UNCONFIGURED" && binding) return false;
      if (
        ["LOCAL_DIRECTORY", "GIT_REPOSITORY"].includes(buildSourceFilter)
        && binding?.target_type !== buildSourceFilter
      ) {
        return false;
      }
      if (!query) return true;
      return [
        server.name,
        server.server_info_name,
        server.endpoint,
        server.transport,
        server.protocol_version,
        binding?.target_type,
        binding?.source_locator,
        binding?.source_ref,
      ].some((value) => String(value || "").toLowerCase().includes(query));
    }).sort((left, right) => {
      if (serverSort === "NAME") return getServerDisplayName(left).localeCompare(getServerDisplayName(right));
      if (serverSort === "RECENT") {
        return (Date.parse(right.last_seen_at) || 0) - (Date.parse(left.last_seen_at) || 0);
      }
      return 0;
    });
  }, [buildSourceFilter, inventorySearch, serverSort, sourceBindings, visibleServers]);
  const filteredServerTools = useMemo(() => {
    const query = toolSearch.trim().toLowerCase();
    return query ? selectedServerTools.filter((tool) => [tool.title, tool.name, tool.description].some(
      (value) => String(value || "").toLowerCase().includes(query),
    )) : selectedServerTools;
  }, [selectedServerTools, toolSearch]);
  const serverPagination = usePagination(
    filteredServers,
    `${includeArchived}|${inventorySearch}|${buildSourceFilter}|${serverSort}|${filteredServers.length}`,
  );
  const toolPagination = usePagination(
    filteredServerTools,
    `${selectedServerId || ""}|${toolSearch}|${filteredServerTools.length}`,
  );

  useEffect(() => {
    setToolSearch("");
  }, [selectedServerId]);

  useEffect(() => {
    if (visibleServers.length === 0) {
      setSelectedServerId(null);
      return;
    }

    const selectedStillExists = visibleServers.some((server) => server.id === selectedServerId);
    if (!selectedStillExists) {
      setSelectedServerId(visibleServers[0].id);
    }
  }, [selectedServerId, visibleServers]);

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
    setBuildSourceError("");
    if (!isAdmin) {
      setSourceBindings({});
      setBuildSourceLoading(false);
      return undefined;
    }
    setBuildSourceLoading(true);
    fetchBuildSourceBindings()
      .then((values) => {
        if (cancelled) return;
        const next = {};
        for (const binding of values || []) {
          next[String(binding.server_id)] = binding;
        }
        setSourceBindings(next);
      })
      .catch((err) => {
        if (!cancelled) {
          setSourceBindings({});
          setBuildSourceError(err.message || "Build source bindings unavailable.");
        }
      })
      .finally(() => {
        if (!cancelled) setBuildSourceLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [isAdmin, servers]);

  useEffect(() => {
    let cancelled = false;
    if (!selectedToolId) {
      setToolAnalysis(null);
      setToolAnalysisToolId(null);
      setToolAnalysisError("");
      return;
    }

    setToolAnalysis(null);
    setToolAnalysisToolId(null);
    setToolAnalysisLoading(true);
    setToolAnalysisError("");
    fetchToolAnalysisBundle(selectedToolId)
      .then((bundle) => {
        if (!cancelled) {
          setToolAnalysis(bundle);
          setToolAnalysisToolId(selectedToolId);
        }
      })
      .catch((err) => {
        if (!cancelled) {
          setToolAnalysis(null);
          setToolAnalysisToolId(null);
          setToolAnalysisError(err.message || "Tool analysis unavailable.");
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
  }, [selectedToolId, selectedToolFingerprint, selectedToolLastAnalyzedAt]);

  useEffect(() => {
    if (!isAdmin) return undefined;
    let cancelled = false;
    fetchOAuthCallbackUri()
      .then((result) => {
        if (!cancelled) setOauthCallbackUri(result.callback_uri || "");
      })
      .catch(() => {
        if (!cancelled) setOauthCallbackUri("");
      });
    return () => {
      cancelled = true;
    };
  }, [isAdmin]);

  if (loading && servers.length === 0 && tools.length === 0) {
    return (
      <section className="page-section">
        <div className="section-heading">
          <h2>MCP tools</h2>
          <p>Loading inventory...</p>
        </div>
      </section>
    );
  }

  return (
    <section className="page-section inventory-page">
      <div className="section-heading">
        <div>
          <h2>MCP tools</h2>
          <p>Connect servers, discover tools, and open a tool’s security review.</p>
        </div>
      </div>
      <nav aria-label="MCP inventory sections" className="workflow-links">
        <a href="#inventory-servers">Servers</a>
        {selectedServer && <a href="#inventory-server-details">Server details</a>}
        {selectedServer && <a href="#inventory-tools">Tools</a>}
        {selectedTool && <a href="#inventory-tool-details">Tool details</a>}
      </nav>

      {isAdmin && (
        <details className="operator-technical-details inventory-add-server">
          <summary>Add or connect an MCP server</summary>
          <form className="action-panel inventory-discovery-form" onSubmit={handleDiscover}>
          <label>
            Server address (URL)
            <input
              aria-describedby="discovery-endpoint-error"
              aria-invalid={Boolean(discoverFieldErrors.endpoint)}
              maxLength={LIMITS.discoveryEndpointMax}
              minLength={LIMITS.discoveryEndpointMin}
              onChange={(event) => {
                setEndpoint(event.target.value);
                setDiscoverFieldErrors((current) => clearFieldError(current, "endpoint"));
              }}
              placeholder="http://127.0.0.1:9000/mcp"
              required
              type="url"
              value={endpoint}
            />
            <FieldError id="discovery-endpoint-error" message={discoverFieldErrors.endpoint} />
          </label>
          <label>
            Authentication
            <select
              onChange={(event) => {
                setAuthMode(event.target.value);
                setDiscoverFieldErrors((current) => clearFieldError(current, "authMode"));
                if (event.target.value === "NONE") {
                  setCredentialRef("");
                  setDiscoverFieldErrors((current) =>
                    clearFieldError(current, "credentialRef"),
                  );
                }
              }}
              value={authMode}
            >
              <option value="NONE">None</option>
              <option value="BEARER">Bearer credential reference</option>
              <option value="OAUTH">OAuth 2.1 (PKCE)</option>
            </select>
          </label>
          {authMode === "BEARER" && (
            <label>
              Saved credential reference
              <input
                aria-describedby="discovery-credential-error"
                aria-invalid={Boolean(discoverFieldErrors.credentialRef)}
                maxLength={LIMITS.credentialRefMax}
                onChange={(event) => {
                  setCredentialRef(event.target.value);
                  setDiscoverFieldErrors((current) =>
                    clearFieldError(current, "credentialRef"),
                  );
                }}
                placeholder="mcp/vendor/service.token"
                required
                value={credentialRef}
              />
              <FieldError
                id="discovery-credential-error"
                message={discoverFieldErrors.credentialRef}
              />
            </label>
          )}
          {authMode === "OAUTH" && (
            <>
              <label>
                OAuth client ID (optional)
                <input
                  aria-describedby="oauth-client-id-error"
                  aria-invalid={Boolean(discoverFieldErrors.clientId)}
                  maxLength={LIMITS.oauthClientIdMax}
                  onChange={(event) => {
                    setOauthClientId(event.target.value);
                    setDiscoverFieldErrors((current) => clearFieldError(current, "clientId"));
                  }}
                  placeholder="Leave blank for dynamic registration"
                  value={oauthClientId}
                />
                <FieldError id="oauth-client-id-error" message={discoverFieldErrors.clientId} />
              </label>
              <label>
                Requested scopes
                <input
                  aria-describedby="oauth-scopes-error"
                  aria-invalid={Boolean(discoverFieldErrors.requestedScopes)}
                  maxLength={LIMITS.oauthScopesMax}
                  onChange={(event) => {
                    setOauthScopes(event.target.value);
                    setDiscoverFieldErrors((current) => clearFieldError(current, "requestedScopes"));
                  }}
                  placeholder="Optional, space separated"
                  value={oauthScopes}
                />
                <FieldError id="oauth-scopes-error" message={discoverFieldErrors.requestedScopes} />
              </label>
              <label>
                Expected authorization server (required with a client secret)
                <input
                  aria-describedby="oauth-expected-issuer-error"
                  aria-invalid={Boolean(discoverFieldErrors.expectedAuthorizationServer)}
                  maxLength={2048}
                  onChange={(event) => {
                    setOauthExpectedIssuer(event.target.value);
                    setDiscoverFieldErrors((current) => clearFieldError(current, "expectedAuthorizationServer"));
                  }}
                  placeholder="https://issuer.example.com"
                  type="url"
                  value={oauthExpectedIssuer}
                />
                <FieldError
                  id="oauth-expected-issuer-error"
                  message={discoverFieldErrors.expectedAuthorizationServer}
                />
              </label>
              <label>
                OAuth client secret
                <input
                  aria-describedby="oauth-client-secret-error"
                  aria-invalid={Boolean(discoverFieldErrors.clientSecret)}
                  autoComplete="new-password"
                  maxLength={LIMITS.oauthClientSecretMax}
                  onChange={(event) => {
                    setOauthClientSecret(event.target.value);
                    setDiscoverFieldErrors((current) => clearFieldError(current, "clientSecret"));
                  }}
                  placeholder="Optional for public clients"
                  type="password"
                  value={oauthClientSecret}
                />
                <FieldError id="oauth-client-secret-error" message={discoverFieldErrors.clientSecret} />
              </label>
              {oauthCallbackUri && (
                <div className="oauth-callback-display">
                  <span>Redirect URI</span>
                  <code>{oauthCallbackUri}</code>
                  <button
                    className="tiny-action"
                    onClick={() => navigator.clipboard?.writeText(oauthCallbackUri)}
                    type="button"
                  >
                    Copy
                  </button>
                </div>
              )}
            </>
          )}
          <button className="secondary-action" disabled={discovering} type="submit">
            {discovering
              ? (authMode === "OAUTH" ? "Opening authorization..." : "Discovering...")
              : (authMode === "OAUTH" ? "Register and connect OAuth" : "Connect server")}
          </button>
          </form>
        </details>
      )}
      {discoverResult && <div className="success-banner" role="status">{discoverResult}</div>}
      {discoverError && <div className="error-banner" role="alert">{discoverError}</div>}

      <div className="summary-grid inventory-summary-grid">
        <SummaryCard label="Servers" value={visibleServers.length} />
        <SummaryCard label="Tools" value={visibleTools.length} />
        <SummaryCard label="Need review" value={reviewRequiredCount} />
      </div>

      <details className="operator-technical-details inventory-extra-stats">
        <summary>Additional inventory numbers</summary>
        <div className="summary-grid">
          <SummaryCard label="Sensitive tools" value={sensitiveToolCount} />
          <SummaryCard label="Analysis pending" value={pendingCount} />
        </div>
      </details>

      <div className="inventory-layout">
        <section id="inventory-servers" className="inventory-section" aria-labelledby="inventory-servers-title">
          <div className="section-heading compact-heading">
            <div>
              <h3 id="inventory-servers-title">MCP Servers</h3>
              <p>{filteredServers.length} shown · {visibleServers.length} available</p>
            </div>
            <label className="toggle-control">
              <input
                checked={includeArchived}
                onChange={(event) => setIncludeArchived(event.target.checked)}
                type="checkbox"
              />
              Include archived
            </label>
          </div>
          <div className="inventory-source-controls">
            <input
              aria-label="Search MCP Inventory"
              onChange={(event) => setInventorySearch(event.target.value)}
              placeholder="Search name, endpoint, local path, Git repository..."
              type="search"
              value={inventorySearch}
            />
            <select
              aria-label="Filter MCP Inventory by Build source"
              disabled={!isAdmin}
              onChange={(event) => setBuildSourceFilter(event.target.value)}
              value={buildSourceFilter}
            >
              <option value="ALL">All Build sources</option>
              <option value="CONFIGURED">Source configured</option>
              <option value="LOCAL_DIRECTORY">Local sources</option>
              <option value="GIT_REPOSITORY">Git sources</option>
              <option value="UNCONFIGURED">Source not configured</option>
            </select>
            <select aria-label="Sort MCP servers" value={serverSort}
              onChange={(event) => setServerSort(event.target.value)}>
              <option value="DEFAULT">Default order</option>
              <option value="NAME">Name A to Z</option>
              <option value="RECENT">Most recently seen</option>
            </select>
          </div>
          {buildSourceError && <div className="error-text">{buildSourceError}</div>}
          {filteredServers.length === 0 && visibleServers.length > 0 ? (
            <div className="empty-state">
              <p>No servers match the current filters.</p>
              <button className="secondary-action" onClick={() => {
                setInventorySearch("");
                setBuildSourceFilter("ALL");
              }} type="button">Clear filters</button>
            </div>
          ) : <ServerTable
            isAdmin={isAdmin}
            servers={serverPagination.pageItems}
            sourceBindings={sourceBindings}
            tools={visibleTools}
            selectedServerId={selectedServerId}
            onSelectServer={setSelectedServerId}
          />}
          <Pagination
            label="MCP servers"
            onPageChange={serverPagination.setPage}
            page={serverPagination.page}
            pageCount={serverPagination.pageCount}
            total={serverPagination.total}
          />
        </section>

        {selectedServer ? (
          <ServerDetailPanel
            canArchive={isAdmin && selectedServer.status !== "archived"}
            canManageServer={isAdmin && selectedServer.status !== "archived"}
            canManageTrust={isAdmin && selectedServer.status !== "archived"}
            buildSourceBinding={buildSourceBinding}
            buildSourceError={buildSourceError}
            buildSourceLoading={buildSourceLoading}
            buildSourceVisible={isAdmin}
            connecting={discovering}
            discovering={discovering}
            gatewayStatus={runtimeStatus?.gateway}
            onConnectOAuth={() => handleConnectOAuth(selectedServer)}
            onDisconnectOAuth={() => handleDisconnectOAuth(selectedServer)}
            onDiscover={() => handleDiscoverRegistered(selectedServer)}
            onArchive={() => setArchiveDialog({ serverId: selectedServer.id, reason: "", error: "" })}
            onTrust={() => setTrustDialog({ serverId: selectedServer.id, mode: "trust", reason: "", error: "" })}
            onRevokeTrust={() => setTrustDialog({ serverId: selectedServer.id, mode: "revoke", reason: "", error: "" })}
            server={selectedServer}
            trustChanging={trustChanging}
          />
        ) : (
          <EmptyState />
        )}

        {selectedServer && (
          <section id="inventory-tools" className="inventory-section" aria-labelledby="inventory-tools-title">
            <div className="section-heading compact-heading">
              <h3 id="inventory-tools-title">Tools for the selected server</h3>
              <p>{filteredServerTools.length} shown · {selectedServerTools.length} available</p>
            </div>
            {selectedServerTools.length > 0 && (
              <div className="inventory-source-controls">
                <input aria-label="Search tools on the selected server" type="search"
                  placeholder="Search tool names or descriptions" value={toolSearch}
                  onChange={(event) => setToolSearch(event.target.value)} />
              </div>
            )}
            {filteredServerTools.length === 0 && selectedServerTools.length > 0 ? (
              <div className="empty-state">
                <p>No tools match this search.</p>
                <button className="secondary-action" onClick={() => setToolSearch("")} type="button">Clear tool search</button>
              </div>
            ) : <ToolsTable
              tools={toolPagination.pageItems}
              selectedToolId={selectedToolId}
              onSelectTool={setSelectedToolId}
            />}
            <Pagination
              label="MCP tools"
              onPageChange={toolPagination.setPage}
              page={toolPagination.page}
              pageCount={toolPagination.pageCount}
              total={toolPagination.total}
            />
          </section>
        )}

        {selectedTool && (
          <ToolDetailPanel
            tool={selectedTool}
            analysis={selectedToolAnalysis}
            analysisError={toolAnalysisError}
            analysisLoading={toolAnalysisLoading}
            onOpenAnalysis={() => onNavigate?.("analysis", selectedTool.id)}
          />
        )}
      </div>
      {isAdmin && archiveDialog && selectedServer?.id === archiveDialog.serverId && (
        <div className="modal-backdrop" role="presentation">
          <section aria-modal="true" aria-labelledby="inventory-archive-title" className="modal-panel" ref={archiveRef} role="dialog" tabIndex={-1}>
            <h3 id="inventory-archive-title">Archive MCP Server</h3>
            <p>Server: {getServerDisplayName(selectedServer)}</p>
            <p>Archived servers are listed when you select Include archived.</p>
            <form onSubmit={handleArchive}>
              <label>
                Reason
                <textarea
                  aria-describedby="archive-reason-error"
                  aria-invalid={Boolean(archiveDialog.error)}
                  maxLength={LIMITS.reasonMax}
                  minLength={LIMITS.reasonMin}
                  onChange={(event) => setArchiveDialog({ ...archiveDialog, reason: event.target.value, error: "" })}
                  required
                  value={archiveDialog.reason}
                />
                <FieldError id="archive-reason-error" message={archiveDialog.error} />
              </label>
              <div className="button-row">
                <button className="danger-action" disabled={archiving} type="submit">
                  {archiving ? "Archiving..." : "Archive"}
                </button>
                <button disabled={archiving} onClick={() => setArchiveDialog(null)} type="button">
                  Cancel
                </button>
              </div>
            </form>
          </section>
        </div>
      )}
      {isAdmin && trustDialog && selectedServer?.id === trustDialog.serverId && (
        <div className="modal-backdrop" role="presentation">
          <section aria-modal="true" aria-labelledby="inventory-trust-title" className="modal-panel" ref={trustRef} role="dialog" tabIndex={-1}>
            <h3 id="inventory-trust-title">{trustDialog.mode === "trust" ? "Trust MCP Server" : "Revoke MCP Server Trust"}</h3>
            <p>{getServerDisplayName(selectedServer)}</p>
            <form onSubmit={handleTrustChange}>
              <label>
                Reason
                <textarea
                  aria-describedby="trust-reason-error"
                  aria-invalid={Boolean(trustDialog.error)}
                  maxLength={LIMITS.reasonMax}
                  minLength={LIMITS.reasonMin}
                  onChange={(event) => setTrustDialog({ ...trustDialog, reason: event.target.value, error: "" })}
                  required
                  value={trustDialog.reason}
                />
                <FieldError id="trust-reason-error" message={trustDialog.error} />
              </label>
              <div className="button-row">
                <button
                  className={trustDialog.mode === "revoke" ? "danger-action" : "secondary-action"}
                  disabled={trustChanging}
                  type="submit"
                >
                  {trustChanging
                    ? "Updating trust..."
                    : (trustDialog.mode === "trust" ? "Trust server" : "Revoke trust")}
                </button>
                <button disabled={trustChanging} onClick={() => setTrustDialog(null)} type="button">
                  Cancel
                </button>
              </div>
            </form>
          </section>
        </div>
      )}
    </section>
  );

  async function handleDiscover(event) {
    event.preventDefault();
    if (discovering) {
      return;
    }
    if (authMode === "OAUTH") {
      const { errors, payload } = oauthMcpRegistrationPayload({
        endpoint,
        clientId: oauthClientId,
        requestedScopes: oauthScopes,
        clientSecret: oauthClientSecret,
        expectedAuthorizationServer: oauthExpectedIssuer,
      });
      setDiscoverFieldErrors(errors);
      if (Object.keys(errors).length > 0) {
        return;
      }
      setDiscovering(true);
      setDiscoverError("");
      setDiscoverResult("");
      try {
        const server = await registerOAuthMcpServer(payload);
        setSelectedServerId(server.id);
        await onRefresh?.();
        const connection = await startOAuthConnection(server.id);
        window.location.assign(connection.authorization_url);
      } catch (err) {
        setDiscoverError(err.message || "OAuth connection could not start.");
      } finally {
        setOauthClientSecret("");
        setDiscovering(false);
      }
      return;
    }
    const { errors, args } = discoverySubmissionArguments({ endpoint, authMode, credentialRef });
    setDiscoverFieldErrors(errors);
    if (Object.keys(errors).length > 0) {
      return;
    }
    setDiscovering(true);
    setDiscoverError("");
    setDiscoverResult("");
    try {
      const result = await discoverHttpMcpServer(...args);
      setDiscoverResult(
        `Imported ${result.total_tools_imported} tool(s); ${result.tools_quarantined} require review.`,
      );
      setDiscoverFieldErrors({});
      await onRefresh?.();
    } catch (err) {
      setDiscoverError(
        err.code === "request_timeout"
          ? "Discovery may still be running on the backend. Refresh the inventory before retrying to avoid duplicate work."
          : (err.message || "Discovery failed"),
      );
    } finally {
      setDiscovering(false);
    }
  }

  async function handleConnectOAuth(server) {
    if (!server || discovering) return;
    setDiscovering(true);
    setDiscoverError("");
    try {
      const connection = await startOAuthConnection(server.id);
      window.location.assign(connection.authorization_url);
    } catch (err) {
      setDiscoverError(err.message || "OAuth connection could not start.");
    } finally {
      setDiscovering(false);
    }
  }

  async function handleDisconnectOAuth(server) {
    if (!server || discovering) return;
    setDiscovering(true);
    setDiscoverError("");
    try {
      await disconnectOAuthMcpServer(server.id);
      await onRefresh?.();
    } catch (err) {
      setDiscoverError(err.message || "OAuth credential could not be disconnected.");
    } finally {
      setDiscovering(false);
    }
  }

  async function handleDiscoverRegistered(server) {
    if (!server || discovering) return;
    setDiscovering(true);
    setDiscoverError("");
    setDiscoverResult("");
    try {
      const result = await discoverRegisteredMcpServer(server.id);
      setDiscoverResult(
        `Imported ${result.total_tools_imported} tool(s); ${result.tools_quarantined} require review.`,
      );
      await onRefresh?.();
    } catch (err) {
      setDiscoverError(
        err.code === "request_timeout"
          ? "Rediscovery may still be running on the backend. Refresh the inventory before retrying."
          : (err.message || "Discovery failed."),
      );
    } finally {
      setDiscovering(false);
    }
  }

  async function handleTrustChange(event) {
    event.preventDefault();
    if (!isAdmin || !trustDialog || selectedServer?.id !== trustDialog.serverId || trustChanging) return;
    const reasonError = validateReason(trustDialog.reason);
    if (reasonError) {
      setTrustDialog({ ...trustDialog, error: reasonError });
      return;
    }
    setTrustChanging(true);
    setDiscoverError("");
    try {
      if (trustDialog.mode === "trust") {
        await trustServer(selectedServer.id, trustDialog.reason.trim());
      } else {
        await revokeServerTrust(selectedServer.id, trustDialog.reason.trim());
      }
      setTrustDialog(null);
      await onRefresh?.();
    } catch (err) {
      setTrustDialog({ ...trustDialog, error: err.message || "Server trust update failed." });
    } finally {
      setTrustChanging(false);
    }
  }

  async function handleArchive(event) {
    event.preventDefault();
    if (!isAdmin || !archiveDialog || selectedServer?.id !== archiveDialog.serverId || archiving) return;
    const reasonError = validateReason(archiveDialog.reason);
    if (reasonError) {
      setArchiveDialog({ ...archiveDialog, error: reasonError });
      return;
    }
    setArchiving(true);
    setDiscoverError("");
    try {
      await archiveServer(selectedServer.id, archiveDialog.reason.trim());
      setArchiveDialog(null);
      setSelectedServerId(null);
      await onRefresh?.();
    } catch (err) {
      setArchiveDialog({ ...archiveDialog, error: err.message || "Server archive failed." });
    } finally {
      setArchiving(false);
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

function ServerTable({
  isAdmin,
  onSelectServer,
  selectedServerId,
  servers,
  sourceBindings,
  tools,
}) {
  if (servers.length === 0) {
    return <EmptyState />;
  }

  return (
    <div className="table-shell inventory-table" role="region" tabIndex={0} aria-label="Inventory table">
      <table>
        <thead>
          <tr>
            <th>Server</th>
            <th>Endpoint</th>
            <th>Build source</th>
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
            const binding = sourceBindings[String(server.id)] || null;

            return (
              <tr
                className={server.id === selectedServerId ? "selected-row" : ""}
                key={server.id}
                onClick={() => onSelectServer(server.id)}
              >
                <td><button className="table-selection" aria-pressed={server.id === selectedServerId}
                  onClick={(event) => { event.stopPropagation(); onSelectServer(server.id); }} type="button">
                  {getServerDisplayName(server)}
                </button></td>
                <td><code className="inventory-endpoint-cell">{displayValue(server.endpoint)}</code></td>
                <td>
                  {isAdmin ? (
                    binding ? (
                      <div className="inventory-build-source-cell">
                        <strong>{binding.target_type === "LOCAL_DIRECTORY" ? "Local" : "Git"}</strong>
                        <code title={binding.source_locator}>{binding.source_locator}</code>
                        {binding.source_ref && <small>ref: {binding.source_ref}</small>}
                      </div>
                    ) : (
                      <span className="source-not-configured">Not configured</span>
                    )
                  ) : (
                    <span className="hint-text">ADMIN only</span>
                  )}
                </td>
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
    <div className="table-shell inventory-table" role="region" tabIndex={0} aria-label="Inventory table">
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
            >
              <td><button className="table-selection" aria-pressed={tool.id === selectedToolId}
                onClick={(event) => { event.stopPropagation(); onSelectTool(tool.id); }} type="button">
                {getToolDisplayName(tool)}
              </button></td>
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

function ServerDetailPanel({
  buildSourceBinding,
  buildSourceError,
  buildSourceLoading,
  buildSourceVisible,
  canArchive,
  canManageServer,
  canManageTrust,
  connecting,
  discovering,
  server,
  gatewayStatus,
  onArchive,
  onConnectOAuth,
  onDisconnectOAuth,
  onDiscover,
  onTrust,
  onRevokeTrust,
  trustChanging,
}) {
  const governedEndpoint = buildGovernedEndpoint(gatewayStatus, server.id);
  const isOAuth = server.auth_mode === "OAUTH";
  const canDiscover = canManageServer && server.status !== "archived" && (!isOAuth || server.oauth_status === "CONNECTED");
  return (
    <div className="detail-panel" id="inventory-server-details">
      <div className="detail-heading">
        <h3>{getServerDisplayName(server)}</h3>
        <div className="button-row compact-actions">
          {canDiscover && (
            <button className="tiny-action" disabled={discovering} onClick={onDiscover} type="button">
              {discovering ? "Discovering..." : "Discover tools"}
            </button>
          )}
          {canManageServer && isOAuth && server.oauth_status !== "CONNECTED" && (
            <button className="secondary-action" disabled={connecting} onClick={onConnectOAuth} type="button">
              {connecting ? "Connecting..." : "Connect OAuth"}
            </button>
          )}
          {canManageServer && isOAuth && server.oauth_status === "CONNECTED" && (
            <button className="tiny-action" disabled={connecting} onClick={onDisconnectOAuth} type="button">
              Disconnect OAuth
            </button>
          )}
          {canManageTrust && server.trust_status !== "trusted" && server.trust_status !== "lab_trusted" && (
            <button className="secondary-action" disabled={trustChanging} onClick={onTrust} type="button">
              {trustChanging ? "Updating trust..." : "Trust server"}
            </button>
          )}
          {canManageTrust && server.trust_status === "trusted" && (
            <button className="tiny-action" disabled={trustChanging} onClick={onRevokeTrust} type="button">
              Revoke trust
            </button>
          )}
          {canArchive && <button className="danger-action" onClick={onArchive} type="button">Archive</button>}
        </div>
      </div>
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
          collapsible
          title="MCP native metadata"
          items={[
            ["protocol_version", server.protocol_version],
            ["transport", server.transport],
            ["auth_mode", server.auth_mode],
            ["oauth_status", server.oauth_status, "badge"],
            ["oauth_last_error", server.oauth_last_error],
            ["oauth_connected_at", formatDate(server.oauth_connected_at)],
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
        <MetadataSection
          title="Build source traceability"
          items={
            buildSourceVisible
              ? [
                  [
                    "source_status",
                    buildSourceLoading
                      ? "loading"
                      : (buildSourceBinding ? "configured" : "not configured"),
                  ],
                  ["source_type", buildSourceBinding?.target_type],
                  ["source_location", buildSourceBinding?.source_locator],
                  ["source_ref", buildSourceBinding?.source_ref],
                  ["binding_updated_at", formatDate(buildSourceBinding?.updated_at)],
                  ["error", buildSourceError],
                ]
              : [["source_status", "ADMIN only"]]
          }
        />
      </div>
    </div>
  );
}

function ToolDetailPanel({ tool, analysis, analysisError, analysisLoading, onOpenAnalysis }) {
  const latestAnalysis = analysis?.analyses?.[0] || null;
  const sectionErrors = analysis?.errors || {};
  const latestAnalysisFindings = latestAnalysis
    ? (analysis?.findings || []).filter((finding) => finding.analysis_id === latestAnalysis.id)
    : [];

  return (
    <div className="detail-panel">
      <div className="detail-heading">
        <h3 id="inventory-tool-details">{getToolDisplayName(tool)}</h3>
        <button className="tiny-action" onClick={onOpenAnalysis} type="button">
          Open security review
        </button>
      </div>
      <div className="metadata-grid">
        <MetadataSection
          collapsible
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
          collapsible
          title="Analyzer evidence"
          items={
            analysisLoading
              ? [["loading", "Loading analysis..."]]
              : [
                  ["error", analysisError],
                  ["status", analysis?.status, "json"],
                  ["status_error", sectionErrors.status],
                  ["latest_analysis", latestAnalysis?.id],
                  ["semantic_scores", latestAnalysis?.semantic_scores, "json"],
                  ["model_versions", latestAnalysis?.model_versions, "json"],
                  ["analyses_error", sectionErrors.analyses],
                  ["baseline", analysis?.baseline, "json"],
                  ["baseline_error", sectionErrors.baseline],
                  ["version_count", analysis?.versions?.length ?? 0],
                  ["versions_error", sectionErrors.versions],
                  ["drift", analysis?.diff, "json"],
                  ["drift_error", sectionErrors.diff],
                  ["findings", summarizeFindings(latestAnalysisFindings), "json"],
                  ["findings_error", sectionErrors.findings],
                ]
          }
        />
      </div>
    </div>
  );
}

function MetadataSection({ collapsible = false, title, items }) {
  const content = (
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
  );

  if (collapsible) {
    return (
      <details className="metadata-disclosure">
        <summary>{title}</summary>
        {content}
      </details>
    );
  }

  return <section className="metadata-section"><h4>{title}</h4>{content}</section>;
}

function EmptyState() {
  return (
    <div className="empty-state">
      No MCP server discovered yet. An ADMIN can register and discover an MCP HTTP
      endpoint from this page.
    </div>
  );
}

function FieldError({ id, message }) {
  return message ? (
    <span className="field-error" id={id}>
      {message}
    </span>
  ) : null;
}

function Badge({ value }) {
  const display = displayValue(value);
  return <span className={`badge ${getBadgeClass(value)}`}>{display}</span>;
}

function formatDate(value) {
  return formatServerTime(value);
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

  if (
    normalized === "lab_trusted" ||
    normalized === "approved" ||
    normalized === "admin_allowed" ||
    normalized === "consistent"
  ) {
    return "badge-success";
  }

  return "badge-unknown";
}

function getServerDisplayName(server) {
  if (!server) return "MCP Server";
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

export default Inventory;
