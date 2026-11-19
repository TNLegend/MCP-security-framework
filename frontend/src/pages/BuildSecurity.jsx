import { useEffect, useMemo, useState } from "react";

import { Pagination, usePagination } from "../components/Pagination";

import {
  attachBuildScanToDraft,
  configureBuildSourceBinding,
  pickBuildLocalDirectory,
  fetchBuildScan,
  fetchBuildScanners,
  fetchBuildScans,
  fetchBuildScanSources,
  fetchBuildSourceBinding,
  fetchBuildSourceBindings,
  safeErrorMessage,
  startGitBuildScan,
  startInventoryBuildScan,
  startLocalBuildScan,
} from "../api/client";

const DEFAULT_REASON = "Run Build Security before publishing or deploying this MCP source.";

function BuildSecurity({
  isAdmin = false,
  onRefresh = null,
  revisions = [],
  servers = [],
}) {
  const activeServers = useMemo(
    () => servers.filter((server) => server.status !== "archived"),
    [servers],
  );
  const [scanners, setScanners] = useState([]);
  const [scans, setScans] = useState([]);
  const [selectedScan, setSelectedScan] = useState(null);
  const [loading, setLoading] = useState(true);
  const [detailLoading, setDetailLoading] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const [mode, setMode] = useState("LOCAL_DIRECTORY");
  const [governanceBusy, setGovernanceBusy] = useState(false);
  const [governanceDraftId, setGovernanceDraftId] = useState("");
  const [governanceMode, setGovernanceMode] = useState("REQUIRE_PASS");
  const [governanceMaxAge, setGovernanceMaxAge] = useState("168");
  const [governanceReason, setGovernanceReason] = useState(
    "Attach this exact Build Security evidence to the governed Runtime configuration.",
  );

  const draftRevisions = useMemo(
    () => revisions.filter((revision) => revision.status === "DRAFT"),
    [revisions],
  );

  const [pickerBusy, setPickerBusy] = useState(false);
  const [localSourcePath, setLocalSourcePath] = useState("");
  const [localDisplayName, setLocalDisplayName] = useState("mcp-source");
  const [localLinkedServerId, setLocalLinkedServerId] = useState("");
  const [localReason, setLocalReason] = useState(DEFAULT_REASON);

  const [gitDisplayName, setGitDisplayName] = useState("mcp-repository");
  const [repositoryUrl, setRepositoryUrl] = useState("");
  const [sourceRef, setSourceRef] = useState("HEAD");
  const [gitLinkedServerId, setGitLinkedServerId] = useState("");
  const [gitReason, setGitReason] = useState(DEFAULT_REASON);

  const [inventoryServerId, setInventoryServerId] = useState("");
  const [inventoryReason, setInventoryReason] = useState(DEFAULT_REASON);
  const [binding, setBinding] = useState(null);
  const [bindingLoading, setBindingLoading] = useState(false);
  const [bindingType, setBindingType] = useState("LOCAL_DIRECTORY");
  const [bindingLocalPath, setBindingLocalPath] = useState("");
  const [bindingGitUrl, setBindingGitUrl] = useState("");
  const [bindingGitRef, setBindingGitRef] = useState("HEAD");
  const [bindingReason, setBindingReason] = useState(
    "Associate this Inventory server with its governed Build source.",
  );
  const [sourceBindings, setSourceBindings] = useState({});
  const [scanSources, setScanSources] = useState({});
  const [scanSearch, setScanSearch] = useState("");
  const [scanSourceFilter, setScanSourceFilter] = useState("ALL");

  const filteredScans = useMemo(() => {
    const query = scanSearch.trim().toLowerCase();
    return scans.filter((scan) => {
      if (scanSourceFilter !== "ALL" && scan.target_type !== scanSourceFilter) {
        return false;
      }
      if (!query) return true;
      const server = activeServers.find(
        (candidate) => String(candidate.id) === String(scan.linked_server_id),
      );
      const source = scanSources[String(scan.id)] || null;
      return [
        scan.display_name,
        source?.source_locator,
        scan.source_revision,
        scan.source_fingerprint,
        server?.name,
        server?.endpoint,
      ].some((value) => String(value || "").toLowerCase().includes(query));
    });
  }, [activeServers, scanSearch, scanSourceFilter, scanSources, scans]);
  const scanPagination = usePagination(
    filteredScans,
    `${scanSearch}|${scanSourceFilter}|${filteredScans.length}`,
  );

  async function loadBuildData() {
    setLoading(true);
    setError("");
    const requests = [
      fetchBuildScanners(),
      fetchBuildScans({ limit: 500 }),
    ];
    if (isAdmin) {
      requests.push(fetchBuildSourceBindings(), fetchBuildScanSources());
    }
    const results = await Promise.allSettled(requests);

    const failures = [];
    if (results[0].status === "fulfilled") {
      setScanners(results[0].value || []);
    } else {
      failures.push(safeErrorMessage(results[0].reason));
    }
    if (results[1].status === "fulfilled") {
      setScans(results[1].value || []);
    } else {
      failures.push(safeErrorMessage(results[1].reason));
    }
    if (isAdmin && results[2]?.status === "fulfilled") {
      const nextBindings = {};
      for (const item of results[2].value || []) {
        nextBindings[String(item.server_id)] = item;
      }
      setSourceBindings(nextBindings);
    } else if (isAdmin && results[2]?.status === "rejected") {
      failures.push(safeErrorMessage(results[2].reason));
    }

    if (isAdmin && results[3]?.status === "fulfilled") {
      const nextSources = {};
      for (const item of results[3].value || []) {
        nextSources[String(item.scan_id)] = item;
      }
      setScanSources(nextSources);
    } else if (isAdmin && results[3]?.status === "rejected") {
      failures.push(safeErrorMessage(results[3].reason));
    }

    if (!isAdmin) {
      setSourceBindings({});
      setScanSources({});
    }
    if (failures.length > 0) {
      setError(failures.join(" "));
    }
    setLoading(false);
  }

  useEffect(() => {
    loadBuildData();
  }, [isAdmin]);

  useEffect(() => {
    if (draftRevisions.length === 0) {
      setGovernanceDraftId("");
      return;
    }
    if (!draftRevisions.some((revision) => revision.id === governanceDraftId)) {
      setGovernanceDraftId(draftRevisions[0].id);
    }
  }, [draftRevisions, governanceDraftId]);

  useEffect(() => {
    if (activeServers.length === 0) {
      setInventoryServerId("");
      return;
    }
    if (!activeServers.some((server) => String(server.id) === String(inventoryServerId))) {
      setInventoryServerId(String(activeServers[0].id));
    }
  }, [activeServers, inventoryServerId]);

  useEffect(() => {
    if (!isAdmin || !inventoryServerId) {
      setBinding(null);
      return;
    }
    let cancelled = false;
    setBinding(null);
    setBindingType("LOCAL_DIRECTORY");
    setBindingLocalPath("");
    setBindingGitUrl("");
    setBindingGitRef("HEAD");
    setBindingLoading(true);
    fetchBuildSourceBinding(inventoryServerId)
      .then(async (value) => {
        if (cancelled) return;
        setBinding(value);
        setSourceBindings((current) => ({
          ...current,
          [String(value.server_id)]: value,
        }));
        setBindingType(value.target_type);
        if (value.target_type === "LOCAL_DIRECTORY") {
          setBindingLocalPath(value.source_locator);
        } else {
          setBindingGitUrl(value.source_locator);
          setBindingGitRef(value.source_ref || "HEAD");
        }
      })
      .catch((err) => {
        if (cancelled) return;
        if (err?.status === 404) {
          setBinding(null);
          return;
        }
        setError(safeErrorMessage(err));
      })
      .finally(() => {
        if (!cancelled) setBindingLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [inventoryServerId, isAdmin]);

  async function chooseLocalDirectory(target) {
    if (!isAdmin || busy || pickerBusy) return;
    setPickerBusy(true);
    setError("");
    setMessage("");
    try {
      const selection = await pickBuildLocalDirectory();
      if (!selection?.selected || !selection.path) return;
      if (target === "inventory") {
        setBindingLocalPath(selection.path);
      } else {
        setLocalSourcePath(selection.path);
        setLocalDisplayName(selection.name || "mcp-source");
      }
    } catch (err) {
      setError(safeErrorMessage(err));
    } finally {
      setPickerBusy(false);
    }
  }

  async function openScan(scanId) {
    setDetailLoading(true);
    setError("");
    try {
      setSelectedScan(await fetchBuildScan(scanId));
    } catch (err) {
      setError(safeErrorMessage(err));
    } finally {
      setDetailLoading(false);
    }
  }

  async function runLocalScan(event) {
    event.preventDefault();
    if (!isAdmin || !localSourcePath || busy) return;
    setBusy(true);
    setError("");
    setMessage("");
    try {
      const created = await startLocalBuildScan({
        display_name: localDisplayName.trim(),
        source_locator: localSourcePath,
        linked_server_id: localLinkedServerId ? Number(localLinkedServerId) : null,
        reason: localReason.trim(),
      });
      setMessage(`Build scan ${created.id} completed with status ${created.status}.`);
      await loadBuildData();
      await openScan(created.id);
    } catch (err) {
      setError(safeErrorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  async function runGitScan(event) {
    event.preventDefault();
    if (!isAdmin || busy) return;
    setBusy(true);
    setError("");
    setMessage("");
    try {
      const created = await startGitBuildScan({
        display_name: gitDisplayName.trim(),
        repository_url: repositoryUrl.trim(),
        source_ref: sourceRef.trim() || "HEAD",
        linked_server_id: gitLinkedServerId ? Number(gitLinkedServerId) : null,
        reason: gitReason.trim(),
      });
      setMessage(`Build scan ${created.id} completed with status ${created.status}.`);
      await loadBuildData();
      await openScan(created.id);
    } catch (err) {
      setError(safeErrorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  async function saveBinding(event) {
    event.preventDefault();
    if (!isAdmin || !inventoryServerId || busy) return;
    setBusy(true);
    setError("");
    setMessage("");
    try {
      const payload = {
        target_type: bindingType,
        source_locator:
          bindingType === "LOCAL_DIRECTORY" ? bindingLocalPath.trim() : bindingGitUrl.trim(),
        source_ref: bindingType === "GIT_REPOSITORY" ? (bindingGitRef.trim() || "HEAD") : null,
        reason: bindingReason.trim(),
      };
      const saved = await configureBuildSourceBinding(inventoryServerId, payload);
      setBinding(saved);
      setSourceBindings((current) => ({
        ...current,
        [String(saved.server_id)]: saved,
      }));
      setMessage("Inventory Build source binding saved.");
    } catch (err) {
      setError(safeErrorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  async function attachSelectedScanToDraft(event) {
    event.preventDefault();
    const scan = selectedScan?.scan;
    if (
      !isAdmin ||
      governanceBusy ||
      !scan ||
      !["COMPLETED", "FAILED"].includes(scan.status) ||
      !scan.linked_server_id ||
      !governanceDraftId
    ) {
      return;
    }

    const maxAge = Number(governanceMaxAge);
    if (!Number.isInteger(maxAge) || maxAge < 1 || maxAge > 8760) {
      setError("Build evidence max age must be an integer between 1 and 8760 hours.");
      return;
    }

    setGovernanceBusy(true);
    setError("");
    setMessage("");
    try {
      const revision = await attachBuildScanToDraft(scan.id, {
        draft_revision_id: governanceDraftId,
        mode: governanceMode,
        max_evidence_age_hours: maxAge,
        reason: governanceReason.trim(),
      });
      setMessage(
        `Build evidence attached to Control Plane draft #${revision.revision_number}. Validate and publish that draft before Runtime can enforce it.`,
      );
      if (typeof onRefresh === "function") {
        await onRefresh();
      }
    } catch (err) {
      setError(safeErrorMessage(err));
    } finally {
      setGovernanceBusy(false);
    }
  }

  async function runInventoryScan() {
    if (!isAdmin || !inventoryServerId || busy) return;
    setBusy(true);
    setError("");
    setMessage("");
    try {
      const created = await startInventoryBuildScan(inventoryServerId, {
        reason: inventoryReason.trim(),
      });
      setMessage(`Inventory Build scan ${created.id} completed with status ${created.status}.`);
      await loadBuildData();
      await openScan(created.id);
    } catch (err) {
      setError(safeErrorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="page-section build-security-page">
      <div className="section-heading">
        <div>
          <h2>Code scans</h2>
          <p>Scan code for security problems before using it.</p>
        </div>
        <button className="secondary-action" disabled={loading || busy} onClick={loadBuildData} type="button">
          {loading ? "Refreshing..." : "Refresh"}
        </button>
      </div>

      <div className="build-scanner-grid" aria-label="Build scanner readiness">
        {scanners.map((scanner) => (
          <article className="status-panel compact-status" key={scanner.scanner_id}>
            <span>{({
              SEMGREP: "Code problems",
              GITLEAKS: "Exposed secrets",
              TRIVY: "Dependencies",
            })[String(scanner.scanner_id).toUpperCase()] || "Security check"}</span>
            <strong>{scanner.available ? "Ready" : "Unavailable"}</strong>
            <details>
              <summary>Scanner details</summary>
              <small>{scanner.scanner_id}: {scanner.version || scanner.reason_code || "Unavailable"}</small>
            </details>
            <p className="scanner-purpose">
              {({
                SEMGREP: "Scans source patterns for security issues.",
                GITLEAKS: "Searches for possible exposed secrets.",
                TRIVY: "Checks known vulnerabilities and unsafe configurations.",
              })[String(scanner.scanner_id).toUpperCase()] || "Scanner details are available in the scan report."}
            </p>
          </article>
        ))}
      </div>

      {error && <div className="error-banner">{error}</div>}
      {message && <div className="success-banner">{message}</div>}

      {isAdmin ? (
        <section className="detail-panel build-new-scan">
          <div className="operations-section-heading">
            <h3>New scan</h3>
            <small>Administrator only ? Checks code, secrets and dependencies</small>
          </div>

          <div className="build-mode-tabs" role="tablist" aria-label="Build target type">
            {[
              ["LOCAL_DIRECTORY", "Local directory"],
              ["GIT_REPOSITORY", "Git repository"],
              ["INVENTORY", "MCP Inventory"],
            ].map(([id, label]) => (
              <button
                className={mode === id ? "active" : ""}
                key={id}
                onClick={() => setMode(id)}
                type="button"
              >
                {label}
              </button>
            ))}
          </div>

          {mode === "LOCAL_DIRECTORY" && (
            <form className="build-target-form" onSubmit={runLocalScan}>
              <div className="build-native-picker">
                <div>
                  <strong>Local MCP source</strong>
                  <small>Open the native folder picker and choose the MCP directory to scan.</small>
                </div>
                <button
                  className="secondary-action"
                  disabled={busy || pickerBusy}
                  onClick={() => chooseLocalDirectory("scan")}
                  type="button"
                >
                  {pickerBusy ? "Opening folder picker..." : "Choose MCP folder..."}
                </button>
                <code className="build-selected-path">
                  {localSourcePath || "No MCP folder selected"}
                </code>
              </div>
              <label>
                Display name
                <input
                  maxLength="255"
                  onChange={(event) => setLocalDisplayName(event.target.value)}
                  required
                  value={localDisplayName}
                />
              </label>
              <ServerSelector
                label="Link to MCP Inventory (optional · matching saved binding required)"
                servers={activeServers}
                sourceBindings={sourceBindings}
                value={localLinkedServerId}
                onChange={setLocalLinkedServerId}
                optional
                showSource
              />
              <label>
                Scan reason
                <textarea
                  maxLength="2000"
                  minLength="3"
                  onChange={(event) => setLocalReason(event.target.value)}
                  required
                  value={localReason}
                />
              </label>
              <button
                className="secondary-action"
                disabled={busy || pickerBusy || !localSourcePath}
                type="submit"
              >
                {busy ? "Scanning..." : "Scan selected directory"}
              </button>
            </form>
          )}

          {mode === "GIT_REPOSITORY" && (
            <form className="build-target-form" onSubmit={runGitScan}>
              <label>
                Repository HTTPS URL
                <input
                  maxLength="2048"
                  onChange={(event) => setRepositoryUrl(event.target.value)}
                  placeholder="https://github.com/org/mcp-server.git"
                  required
                  type="url"
                  value={repositoryUrl}
                />
              </label>
              <label>
                Branch / tag / commit
                <input
                  maxLength="255"
                  onChange={(event) => setSourceRef(event.target.value)}
                  required
                  value={sourceRef}
                />
              </label>
              <label>
                Display name
                <input
                  maxLength="255"
                  onChange={(event) => setGitDisplayName(event.target.value)}
                  required
                  value={gitDisplayName}
                />
              </label>
              <ServerSelector
                label="Link to MCP Inventory (optional · matching saved binding required)"
                servers={activeServers}
                sourceBindings={sourceBindings}
                value={gitLinkedServerId}
                onChange={setGitLinkedServerId}
                optional
                showSource
              />
              <label>
                Scan reason
                <textarea
                  maxLength="2000"
                  minLength="3"
                  onChange={(event) => setGitReason(event.target.value)}
                  required
                  value={gitReason}
                />
              </label>
              <button className="secondary-action" disabled={busy} type="submit">
                {busy ? "Fetching and scanning..." : "Fetch immutable revision and scan"}
              </button>
            </form>
          )}

          {mode === "INVENTORY" && (
            <div className="build-inventory-flow">
              <ServerSelector
                label="MCP Inventory server"
                servers={activeServers}
                sourceBindings={sourceBindings}
                value={inventoryServerId}
                onChange={setInventoryServerId}
                showSource
              />
              <InventorySourceContext
                server={activeServers.find((server) => String(server.id) === String(inventoryServerId))}
                binding={binding}
                loading={bindingLoading}
              />

              <form className="build-target-form" onSubmit={saveBinding}>
                <div className="build-binding-summary">
                  <strong>Build source binding</strong>
                  <span>
                    {bindingLoading
                      ? "Loading..."
                      : binding
                        ? `${binding.target_type} configured`
                        : "Not configured"}
                  </span>
                </div>
                <label>
                  Source type
                  <select
                    onChange={(event) => setBindingType(event.target.value)}
                    value={bindingType}
                  >
                    <option value="LOCAL_DIRECTORY">Local directory</option>
                    <option value="GIT_REPOSITORY">Git repository</option>
                  </select>
                </label>
                {bindingType === "LOCAL_DIRECTORY" ? (
                  <div className="build-native-picker">
                    <div>
                      <strong>Local MCP source</strong>
                      <small>Choose the source folder for this Inventory server.</small>
                    </div>
                    <button
                      className="secondary-action"
                      disabled={busy || pickerBusy}
                      onClick={() => chooseLocalDirectory("inventory")}
                      type="button"
                    >
                      {pickerBusy ? "Opening folder picker..." : "Choose MCP folder..."}
                    </button>
                    <code className="build-selected-path">
                      {bindingLocalPath || "No MCP folder selected"}
                    </code>
                  </div>
                ) : (
                  <>
                    <label>
                      Repository HTTPS URL
                      <input
                        maxLength="2048"
                        onChange={(event) => setBindingGitUrl(event.target.value)}
                        required
                        type="url"
                        value={bindingGitUrl}
                      />
                    </label>
                    <label>
                      Branch / tag / commit
                      <input
                        maxLength="255"
                        onChange={(event) => setBindingGitRef(event.target.value)}
                        required
                        value={bindingGitRef}
                      />
                    </label>
                  </>
                )}
                <label>
                  Binding reason
                  <textarea
                    maxLength="2000"
                    minLength="3"
                    onChange={(event) => setBindingReason(event.target.value)}
                    required
                    value={bindingReason}
                  />
                </label>
                <button
                  className="secondary-action"
                  disabled={
                    busy ||
                    pickerBusy ||
                    !inventoryServerId ||
                    (bindingType === "LOCAL_DIRECTORY" && !bindingLocalPath)
                  }
                  type="submit"
                >
                  Save Build source binding
                </button>
              </form>

              <label className="build-inventory-reason">
                Scan reason
                <textarea
                  maxLength="2000"
                  minLength="3"
                  onChange={(event) => setInventoryReason(event.target.value)}
                  value={inventoryReason}
                />
              </label>
              <button
                className="secondary-action"
                disabled={busy || !inventoryServerId || !binding}
                onClick={runInventoryScan}
                type="button"
              >
                {busy ? "Scanning..." : "Scan configured Inventory source"}
              </button>
            </div>
          )}
        </section>
      ) : (
        <div className="empty-state">
          VIEWER can inspect Build Security evidence but cannot open the local folder picker,
          configure source bindings, or start scans.
        </div>
      )}

      <section className="detail-panel">
        <div className="operations-section-heading">
          <div>
            <h3>Build scan history</h3>
            <small>{filteredScans.length} shown · {scans.length} loaded</small>
          </div>
          <div className="build-history-filters">
            <input
              aria-label="Search Build scans"
              onChange={(event) => setScanSearch(event.target.value)}
              placeholder="Search MCP, path, repository, endpoint, revision..."
              type="search"
              value={scanSearch}
            />
            <select
              aria-label="Filter Build scans by source type"
              onChange={(event) => setScanSourceFilter(event.target.value)}
              value={scanSourceFilter}
            >
              <option value="ALL">All sources</option>
              <option value="LOCAL_DIRECTORY">Local</option>
              <option value="GIT_REPOSITORY">Git</option>
            </select>
          </div>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Created</th>
                <th>Target</th>
                <th>Name</th>
                <th>Source location</th>
                <th>Revision</th>
                <th>Fingerprint</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {scanPagination.pageItems.map((scan) => (
                <tr
                  className={selectedScan?.scan?.id === scan.id ? "selected-row" : ""}
                  key={scan.id}
                  onClick={() => openScan(scan.id)}
                >
                  <td>{formatDate(scan.created_at)}</td>
                  <td>{humanize(scan.target_type)}</td>
                  <td>{scan.display_name}</td>
                  <td>
                    <SourceLocator
                      isAdmin={isAdmin}
                      source={scanSources[String(scan.id)] || null}
                    />
                  </td>
                  <td><code>{shortHash(scan.source_revision)}</code></td>
                  <td><code>{shortHash(scan.source_fingerprint)}</code></td>
                  <td><StatusBadge value={scan.status} /></td>
                </tr>
              ))}
              {!loading && filteredScans.length === 0 && (
                <tr>
                  <td colSpan="7">
                    {scans.length === 0
                      ? "No Build Security scan has been recorded yet."
                      : "No Build scan matches the current search/filter."}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        <Pagination
          label="Build scans"
          onPageChange={scanPagination.setPage}
          page={scanPagination.page}
          pageCount={scanPagination.pageCount}
          total={scanPagination.total}
        />
      </section>

      {isAdmin && (
        <section className="detail-panel build-governance-panel">
          <div className="operations-section-heading">
            <div>
              <h3>Runtime governance</h3>
              <small>
                Attach a terminal Inventory-linked Build scan to a Control Plane DRAFT.
                OPA enforces it only after that draft is validated and published.
              </small>
            </div>
          </div>

          {!selectedScan ? (
            <p className="hint-text">
              Select a terminal Build scan before attaching Runtime evidence.
            </p>
          ) : !selectedScan.scan.linked_server_id ? (
            <div className="empty-state">
              This scan is not linked to an MCP Inventory server, so it cannot become
              authoritative Runtime evidence.
            </div>
          ) : (
            <form className="build-target-form" onSubmit={attachSelectedScanToDraft}>
              <div className="build-governance-summary">
                <div>
                  <span>Selected scan</span>
                  <strong>{selectedScan.scan.display_name}</strong>
                  <code>{shortHash(selectedScan.scan.source_fingerprint)}</code>
                </div>
                <div>
                  <span>Assessment</span>
                  <AssessmentBadge value={selectedScan.assessment?.status || "ERROR"} />
                </div>
              </div>

              <label>
                Control Plane DRAFT
                <select
                  disabled={governanceBusy || draftRevisions.length === 0}
                  onChange={(event) => setGovernanceDraftId(event.target.value)}
                  required
                  value={governanceDraftId}
                >
                  {draftRevisions.length === 0 && (
                    <option value="">No DRAFT revision available</option>
                  )}
                  {draftRevisions.map((revision) => (
                    <option key={revision.id} value={revision.id}>
                      Draft #{revision.revision_number} · {revision.change_summary || revision.id}
                    </option>
                  ))}
                </select>
              </label>

              <label>
                Runtime Build gate
                <select
                  disabled={governanceBusy}
                  onChange={(event) => setGovernanceMode(event.target.value)}
                  value={governanceMode}
                >
                  <option value="REQUIRE_PASS">REQUIRE_PASS — PASS only</option>
                  <option value="ALLOW_WARN">ALLOW_WARN — PASS or WARN</option>
                  <option value="DISABLED">DISABLED — record evidence without enforcing it</option>
                </select>
              </label>

              <label>
                Evidence max age (hours)
                <input
                  disabled={governanceBusy}
                  max="8760"
                  min="1"
                  onChange={(event) => setGovernanceMaxAge(event.target.value)}
                  required
                  type="number"
                  value={governanceMaxAge}
                />
              </label>

              <label>
                Change reason
                <textarea
                  disabled={governanceBusy}
                  maxLength="2000"
                  minLength="3"
                  onChange={(event) => setGovernanceReason(event.target.value)}
                  required
                  value={governanceReason}
                />
              </label>

              <button
                className="secondary-action"
                disabled={
                  governanceBusy ||
                  !["COMPLETED", "FAILED"].includes(selectedScan.scan.status) ||
                  !selectedScan.assessment ||
                  !governanceDraftId
                }
                type="submit"
              >
                {governanceBusy ? "Attaching evidence..." : "Attach exact Build evidence to DRAFT"}
              </button>
            </form>
          )}
        </section>
      )}

      <BuildScanDetail
        detail={selectedScan}
        isAdmin={isAdmin}
        loading={detailLoading}
        source={selectedScan ? scanSources[String(selectedScan.scan.id)] || null : null}
      />
    </section>
  );
}

function ServerSelector({
  label,
  onChange,
  optional = false,
  servers,
  sourceBindings = {},
  showSource = false,
  value,
}) {
  return (
    <label>
      {label}
      <select onChange={(event) => onChange(event.target.value)} value={value}>
        {optional && <option value="">Not linked</option>}
        {!optional && servers.length === 0 && <option value="">No active MCP server</option>}
        {servers.map((server) => {
          const binding = sourceBindings[String(server.id)] || null;
          return (
            <option key={server.id} value={server.id}>
              {serverOptionLabel(server, binding, showSource)}
            </option>
          );
        })}
      </select>
    </label>
  );
}

function InventorySourceContext({ server, binding, loading }) {
  if (!server) return null;
  return (
    <div className="build-source-context" aria-label="Selected MCP source context">
      <div>
        <span>MCP</span>
        <strong>{server.name || server.server_info_name || "Server #" + server.id}</strong>
        <small>Inventory #{server.id}</small>
      </div>
      <div>
        <span>Runtime endpoint</span>
        <code>{server.endpoint || "-"}</code>
      </div>
      <div>
        <span>Build source</span>
        {loading ? (
          <strong>Loading...</strong>
        ) : binding ? (
          <>
            <strong>{humanize(binding.target_type)}</strong>
            <code>{binding.source_locator}</code>
            {binding.source_ref && <small>ref: {binding.source_ref}</small>}
          </>
        ) : (
          <>
            <strong>NOT CONFIGURED</strong>
            <small>Configure the source before using Inventory-based Build scans.</small>
          </>
        )}
      </div>
    </div>
  );
}

function BuildScanDetail({ detail, isAdmin, loading, source }) {
  const findingPagination = usePagination(detail?.findings || [], detail?.scan?.id || "");
  if (loading) {
    return <section className="detail-panel">Loading Build scan evidence...</section>;
  }
  if (!detail) {
    return (
      <section className="detail-panel">
        <h3>Scan evidence</h3>
        <p className="hint-text">Select a Build scan to inspect normalized evidence.</p>
      </section>
    );
  }

  const assessment = detail.assessment;
  return (
    <section className="detail-panel build-scan-detail">
      <div className="operations-section-heading">
        <div>
          <h3>Scan evidence</h3>
          <small>{detail.scan.display_name} · {shortHash(detail.scan.source_fingerprint)}</small>
        </div>
        {assessment && <AssessmentBadge value={assessment.status} />}
      </div>

      <div className="build-source-evidence">
        <div>
          <span>Source type</span>
          <strong>{humanize(detail.scan.target_type)}</strong>
        </div>
        <div>
          <span>Source location</span>
          {isAdmin ? (
            <>
              <code>{source?.source_locator || "Source metadata unavailable"}</code>
              {source?.source_locator && (
                <button
                  className="tiny-action"
                  onClick={() => navigator.clipboard?.writeText(source.source_locator)}
                  type="button"
                >
                  Copy source location
                </button>
              )}
            </>
          ) : (
            <strong>ADMIN only</strong>
          )}
        </div>
        <div>
          <span>Revision</span>
          <code>{detail.scan.source_revision || "-"}</code>
        </div>
        <div>
          <span>Inventory link</span>
          <strong>{detail.scan.linked_server_id ? `#${detail.scan.linked_server_id}` : "Not linked"}</strong>
        </div>
      </div>

      {assessment && (
        <div className="build-assessment-grid">
          <article className="status-panel compact-status">
            <span>Assessment</span>
            <strong>{assessment.status}</strong>
            <small>{assessment.summary}</small>
          </article>
          <article className="status-panel compact-status">
            <span>Critical / High</span>
            <strong>{assessment.critical_count} / {assessment.high_count}</strong>
            <small>Policy {assessment.policy_version}</small>
          </article>
          <article className="status-panel compact-status">
            <span>Required scanners</span>
            <strong>{assessment.required_scanners_complete ? "COMPLETE" : "INCOMPLETE"}</strong>
            <small>{(assessment.reason_codes || []).join(", ") || "No assessment reason codes"}</small>
          </article>
        </div>
      )}

      <h4>Scanner runs</h4>
      <div className="build-scanner-run-list">
        {detail.scanner_runs.map((run) => (
          <article key={run.id}>
            <strong>{run.scanner_id}</strong>
            <span>{run.scanner_version || "-"}</span>
            <StatusBadge value={run.status} />
            <small>{run.finding_count} active finding(s)</small>
            {run.error_code && <small>{run.error_code}</small>}
          </article>
        ))}
      </div>

      <div className="operations-section-heading build-findings-heading">
        <h4>Normalized findings</h4>
        <small>
          {detail.finding_total} total
          {detail.findings_truncated ? " · first 500 shown" : ""}
        </small>
      </div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>State</th>
              <th>Severity</th>
              <th>Scanner</th>
              <th>Rule / CVE</th>
              <th>Location / package</th>
              <th>Remediation</th>
            </tr>
          </thead>
          <tbody>
            {findingPagination.pageItems.map((finding) => (
              <tr key={finding.id}>
                <td><StatusBadge value={finding.finding_state} /></td>
                <td><SeverityBadge value={finding.severity} /></td>
                <td>{finding.scanner_id}</td>
                <td>
                  <strong>{finding.vulnerability_id || finding.rule_id}</strong>
                  <small className="build-finding-title">{finding.title}</small>
                </td>
                <td>
                  {finding.package_name && (
                    <>
                      <code>{finding.package_name}@{finding.package_version || "?"}</code>
                      {finding.fixed_version && <small>fixed: {finding.fixed_version}</small>}
                    </>
                  )}
                  <code>{finding.file_path || "-"}</code>
                  {finding.line_start && <small>line {finding.line_start}</small>}
                  {finding.file_path && (
                    <>
                      <small className="build-resolved-location">
                        {resolvedFindingLocation(source, detail.scan, finding)}
                      </small>
                      {isAdmin && gitFindingHref(source, detail.scan, finding) && (
                        <a
                          className="tiny-action build-source-link"
                          href={gitFindingHref(source, detail.scan, finding)}
                          rel="noreferrer"
                          target="_blank"
                        >
                          Open source at scanned revision
                        </a>
                      )}
                    </>
                  )}
                </td>
                <td>{finding.remediation || "-"}</td>
              </tr>
            ))}
            {detail.findings.length === 0 && (
              <tr><td colSpan="6">No normalized findings for this scan.</td></tr>
            )}
          </tbody>
        </table>
      </div>
      <Pagination
        label="Build findings"
        onPageChange={findingPagination.setPage}
        page={findingPagination.page}
        pageCount={findingPagination.pageCount}
        total={findingPagination.total}
      />
    </section>
  );
}

function SourceLocator({ isAdmin, source }) {
  if (!isAdmin) {
    return <span className="hint-text">ADMIN only</span>;
  }
  if (!source?.source_locator) {
    return <span className="hint-text">Source unavailable</span>;
  }
  const isGit = source.target_type === "GIT_REPOSITORY";
  return (
    <div className="build-source-actions">
      <code className="build-source-cell" title={source.source_locator}>
        {source.source_locator}
      </code>
      <div className="button-row compact-actions">
        <button
          className="tiny-action"
          onClick={(event) => {
            event.stopPropagation();
            navigator.clipboard?.writeText(source.source_locator);
          }}
          type="button"
        >
          {isGit ? "Copy repository" : "Copy path"}
        </button>
        {isGit && /^https:\/\//i.test(source.source_locator) && (
          <a
            className="tiny-action button-link"
            href={source.source_locator}
            onClick={(event) => event.stopPropagation()}
            rel="noreferrer noopener"
            target="_blank"
          >
            Open repository
          </a>
        )}
      </div>
    </div>
  );
}

function serverOptionLabel(server, binding, showSource) {
  const name = server.name || server.server_info_name || "MCP Server";
  const base = `${name} (#${server.id})`;
  if (!showSource) return base;
  if (binding) {
    const type = binding.target_type === "LOCAL_DIRECTORY" ? "Local" : "Git";
    const ref = binding.source_ref ? ` @ ${binding.source_ref}` : "";
    return `${base} — ${type}: ${binding.source_locator}${ref}`;
  }
  return `${base} — Source not configured — Runtime: ${server.endpoint || "-"}`;
}

function resolvedFindingLocation(source, scan, finding) {
  const relative = String(finding.file_path || "").replaceAll("/", "\\");
  if (!relative) return "-";
  if (!source?.source_locator) {
    return `Relative source path: ${finding.file_path}`;
  }
  if (source.target_type === "LOCAL_DIRECTORY") {
    const root = String(source.source_locator).replace(/[\\/]+$/, "");
    return root ? `${root}\\${relative}` : relative;
  }
  const revision = source.source_revision || scan.source_revision || "unresolved revision";
  return `${source.source_locator} @ ${revision} :: ${finding.file_path}`;
}

function gitFindingHref(source, scan, finding) {
  const revision = source?.source_revision || scan.source_revision;
  if (
    source?.target_type !== "GIT_REPOSITORY"
    || !source.source_locator
    || !revision
    || !finding.file_path
  ) {
    return "";
  }
  const repository = String(source.source_locator).replace(/\.git$/i, "").replace(/\/$/, "");
  const relative = String(finding.file_path).replace(/^\/+/, "");
  if (repository.startsWith("https://github.com/")) {
    return `${repository}/blob/${encodeURIComponent(revision)}/${relative}`;
  }
  if (repository.startsWith("https://gitlab.com/")) {
    return `${repository}/-/blob/${encodeURIComponent(revision)}/${relative}`;
  }
  if (repository.startsWith("https://bitbucket.org/")) {
    return `${repository}/src/${encodeURIComponent(revision)}/${relative}`;
  }
  return "";
}

function StatusBadge({ value }) {
  const normalized = String(value || "UNKNOWN").toUpperCase();
  let tone = "badge-muted";
  if (["PASS", "COMPLETED", "RESOLVED"].includes(normalized)) tone = "badge-success";
  if (["WARN", "NEW", "UNCHANGED", "REGRESSED"].includes(normalized)) tone = "badge-warn";
  if (["BLOCK", "ERROR", "FAILED", "TIMED_OUT", "UNAVAILABLE"].includes(normalized)) {
    tone = "badge-danger";
  }
  return <span className={`badge ${tone}`}>{normalized}</span>;
}

function SeverityBadge({ value }) {
  const normalized = String(value || "UNKNOWN").toUpperCase();
  const tone =
    normalized === "CRITICAL" || normalized === "HIGH"
      ? "badge-danger"
      : normalized === "MEDIUM"
        ? "badge-warn"
        : normalized === "LOW" || normalized === "INFO"
          ? "badge-low"
          : "badge-muted";
  return <span className={`badge ${tone}`}>{normalized}</span>;
}

function AssessmentBadge({ value }) {
  return <StatusBadge value={value} />;
}

function shortHash(value) {
  if (!value) return "-";
  const text = String(value);
  return text.length > 12 ? text.slice(0, 12) + "…" : text;
}

function formatDate(value) {
  if (!value) return "-";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
}

function humanize(value) {
  return String(value || "-")
    .replaceAll("_", " ")
    .replace(/(^|\s)\S/g, (character) => character.toUpperCase());
}

export default BuildSecurity;
