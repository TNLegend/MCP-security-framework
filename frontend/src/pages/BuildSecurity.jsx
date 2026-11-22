import { formatServerTime, parseServerTime } from "../utils/serverTime.js";
import "./workflowPages.css";
import { useEffect, useMemo, useRef, useState } from "react";

import { Pagination, usePagination } from "../components/Pagination";

import {
  attachBuildScanToDraft,
  configureBuildSourceBinding,
  pickBuildLocalDirectory,
  fetchBuildScan,
  fetchBuildScanFindings,
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

const SCAN_BATCH_SIZE = 500;
const MAX_SCAN_OFFSET = 10000;
const DEFAULT_REASON = "Run Build Security before publishing or deploying this MCP source.";

// This is a draft-only assessment preview, not a claim about the active
// published policy. OPA independently verifies signature, binding and age.
export function buildDraftGatePreview(mode, status, scannersComplete) {
  if (mode === "DISABLED") {
    return "Build gate disabled for this draft. Other runtime security checks still apply.";
  }
  if (!["REQUIRE_PASS", "ALLOW_WARN"].includes(mode)) {
    return "Unknown gate mode; its runtime effect cannot be determined.";
  }
  if (!scannersComplete) {
    return "This assessment would block the enabled Build gate because required scanners are incomplete.";
  }
  if (status === "ERROR" || status === "BLOCK") {
    return "This assessment would block the enabled Build gate.";
  }
  if (mode === "REQUIRE_PASS" && status === "WARN") {
    return "WARN would block under REQUIRE_PASS. Only PASS satisfies this gate.";
  }
  if (status === "PASS" || (mode === "ALLOW_WARN" && status === "WARN")) {
    return "Assessment status meets this draft Build gate, but valid signed evidence, freshness and other Runtime checks are still required.";
  }
  return "Assessment status is not recognized; do not infer runtime permission.";
}

function BuildSecurity({
  activeRevision = null,
  refreshToken = 0,
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
  const [scanOffset, setScanOffset] = useState(0);
  const [scanHistoryMore, setScanHistoryMore] = useState(false);
  const [scanHistoryLoading, setScanHistoryLoading] = useState(false);
  const [scanHistoryError, setScanHistoryError] = useState("");
  const scanHistoryRequest = useRef(false);
  const [selectedScan, setSelectedScan] = useState(null);
  const [loading, setLoading] = useState(true);
  const [detailLoading, setDetailLoading] = useState(false);
  const [requestedScanId, setRequestedScanId] = useState(null);
  const [detailError, setDetailError] = useState("");
  const detailRequest = useRef(0);
  const buildDataRequest = useRef(0);
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
  const [scanStatusFilter, setScanStatusFilter] = useState("ALL");
  const [scanSort, setScanSort] = useState("RECENT");
  const scanStatuses = useMemo(
    () => [...new Set(scans.map((scan) => scan.status).filter(Boolean))].sort(),
    [scans],
  );

  const filteredScans = useMemo(() => {
    const query = scanSearch.trim().toLowerCase();
    return scans.filter((scan) => {
      if (scanStatusFilter !== "ALL" && scan.status !== scanStatusFilter) return false;
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
    }).sort((left, right) => {
      if (scanSort === "NAME") return (left.display_name || "").localeCompare(right.display_name || "");
      const byDate = (parseServerTime(left.created_at).getTime() || 0) - (parseServerTime(right.created_at).getTime() || 0);
      return scanSort === "OLDEST" ? byDate : -byDate;
    });
  }, [activeServers, scanSearch, scanSourceFilter, scanSources, scanStatusFilter, scanSort, scans]);
  const scanPagination = usePagination(
    filteredScans,
    `${scanSearch}|${scanSourceFilter}|${scanStatusFilter}|${scanSort}|${filteredScans.length}`,
  );

  async function loadBuildData() {
    const request = ++buildDataRequest.current;
    setLoading(true);
    scanHistoryRequest.current = false;
    setScanHistoryLoading(false);
    setScanHistoryError("");
    setError("");
    const requests = [
      fetchBuildScanners(),
      fetchBuildScans({ limit: SCAN_BATCH_SIZE }),
    ];
    if (isAdmin) {
      requests.push(fetchBuildSourceBindings(), fetchBuildScanSources());
    }
    const results = await Promise.allSettled(requests);
    if (request !== buildDataRequest.current) return;

    const failures = [];
    if (results[0].status === "fulfilled") {
      setScanners(results[0].value || []);
    } else {
      failures.push(safeErrorMessage(results[0].reason));
    }
    if (results[1].status === "fulfilled") {
      const firstBatch = results[1].value || [];
      setScans(firstBatch);
      setScanOffset(firstBatch.length);
      setScanHistoryMore(firstBatch.length === SCAN_BATCH_SIZE);
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

  async function loadOlderScans() {
    if (loading || scanHistoryRequest.current || !scanHistoryMore ||
        scanOffset > MAX_SCAN_OFFSET) return;
    const request = buildDataRequest.current;
    scanHistoryRequest.current = true;
    setScanHistoryLoading(true);
    setScanHistoryError("");
    try {
      const older = await fetchBuildScans({ limit: SCAN_BATCH_SIZE, offset: scanOffset });
      if (request !== buildDataRequest.current) return;
      const loadedIds = new Set(scans.map((scan) => scan.id));
      if (older.some((scan) => loadedIds.has(scan.id))) {
        setScanHistoryError("History changed while loading. Refresh the scan list before browsing older records.");
        return;
      }
      setScans([...scans, ...older]);
      setScanOffset(scanOffset + older.length);
      setScanHistoryMore(older.length === SCAN_BATCH_SIZE);
    } catch (err) {
      if (request === buildDataRequest.current) setScanHistoryError(safeErrorMessage(err));
    } finally {
      if (request === buildDataRequest.current) {
        scanHistoryRequest.current = false;
        setScanHistoryLoading(false);
      }
    }
  }

  useEffect(() => {
    loadBuildData();
    return () => {
      buildDataRequest.current += 1;
      detailRequest.current += 1;
    };
  }, [isAdmin, refreshToken]);

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
    const request = ++detailRequest.current;
    setRequestedScanId(scanId);
    setSelectedScan(null);
    setDetailError("");
    setDetailLoading(true);
    try {
      const detail = await fetchBuildScan(scanId);
      if (request === detailRequest.current) setSelectedScan(detail);
    } catch (err) {
      if (request === detailRequest.current) setDetailError(safeErrorMessage(err));
    } finally {
      if (request === detailRequest.current) setDetailLoading(false);
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
      setMessage(`Scan request recorded. Status: ${humanize(created.status)}. See Scan evidence for details.`);
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
      setMessage(`Scan request recorded. Status: ${humanize(created.status)}. See Scan evidence for details.`);
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
      setMessage(`Scan request recorded. Status: ${humanize(created.status)}. See Scan evidence for details.`);
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

      <nav aria-label="Code scan sections" className="workflow-links">
        {isAdmin && <a href="#build-new">New scan</a>}
        <a href="#build-history">Scan history</a>
        <a href="#build-evidence">Scan evidence</a>
        {isAdmin && <a href="#build-governance">Runtime governance</a>}
      </nav>
      {!loading && !scanners.length && <p className="workflow-progress" role="status">Scanner availability could not be confirmed.</p>}
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

      {error && <div className="error-banner" role="alert">{error}</div>}
      {message && <div className="success-banner" role="status">{message}</div>}

      {isAdmin ? (
        <section className="detail-panel build-new-scan" id="build-new">
          <div className="operations-section-heading">
            <h3>New scan</h3>
            <small>Administrator only: checks code, secrets and dependencies</small>
          </div>

          <div className="build-mode-tabs" role="group" aria-label="Build target type">
            {[
              ["LOCAL_DIRECTORY", "Local directory"],
              ["GIT_REPOSITORY", "Git repository"],
              ["INVENTORY", "MCP Inventory"],
            ].map(([id, label]) => (
              <button
                aria-pressed={mode === id}
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
                disabled={busy || pickerBusy}
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

      <section className="detail-panel" id="build-history">
        <div className="operations-section-heading">
          <div>
            <h3>Build scan history</h3>
            <small>{filteredScans.length} shown · {scans.length} loaded</small>
          </div>
          <div className="build-history-filters" role="search" aria-label="Filter Build scans">
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
            <select aria-label="Filter Build scans by status" value={scanStatusFilter}
              onChange={(event) => setScanStatusFilter(event.target.value)}>
              <option value="ALL">All statuses</option>
              {scanStatuses.map((status) => <option key={status} value={status}>{humanize(status)}</option>)}
            </select>
            <select aria-label="Sort Build scans" value={scanSort}
              onChange={(event) => setScanSort(event.target.value)}>
              <option value="RECENT">Newest first</option>
              <option value="OLDEST">Oldest first</option>
              <option value="NAME">Name A to Z</option>
            </select>
            {(scanSourceFilter !== "ALL" || scanSearch || scanStatusFilter !== "ALL") && (
              <button className="secondary-action" onClick={() => {
                setScanSourceFilter("ALL");
                setScanSearch("");
                setScanStatusFilter("ALL");
              }} type="button">Clear filters</button>
            )}
          </div>
        </div>
        {loading && <p className="workflow-progress" role="status">Refreshing scan history…</p>}
        {scanHistoryMore && <p className="hint-text">
          Filters apply to the {scans.length} loaded scans. {scanOffset > MAX_SCAN_OFFSET
            ? "The service limit for browsing older records has been reached."
            : "Load older records to extend this search."}
        </p>}
        {scanHistoryError && <p role="alert">{scanHistoryError}</p>}
        {scanHistoryMore && scanOffset <= MAX_SCAN_OFFSET &&
          <button type="button" className="secondary-action" onClick={loadOlderScans}
            disabled={scanHistoryLoading || loading}>
            {scanHistoryLoading ? "Loading older scans…" : "Load older scans"}
          </button>}
        <div className="table-wrap" role="region" aria-label="Build scan history table" tabIndex={0}>
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
                  className={requestedScanId === scan.id ? "selected-row" : ""}
                  key={scan.id}
                  onClick={() => openScan(scan.id)}
                >
                  <td>{formatDate(scan.created_at)}</td>
                  <td>{humanize(scan.target_type)}</td>
                  <td><button className="table-selection" aria-pressed={requestedScanId === scan.id}
                    onClick={(event) => { event.stopPropagation(); openScan(scan.id); }}
                    type="button">{scan.display_name}</button></td>
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
                      : "No loaded Build scan matches the current filters."}
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

      <section id="build-evidence" aria-label="Scan evidence" aria-busy={detailLoading}>
        {detailError && (
          <div className="error-banner" role="alert">
            <p>{detailError}</p>
            <button className="secondary-action" onClick={() => openScan(requestedScanId)} type="button">Retry loading scan evidence</button>
          </div>
        )}
        <BuildScanDetail
          activeRevision={activeRevision}
          detail={selectedScan}
          isAdmin={isAdmin}
          loading={detailLoading}
          source={selectedScan ? scanSources[String(selectedScan.scan.id)] || null : null}
        />
      </section>

      {isAdmin && (
        <section className="detail-panel build-governance-panel" id="build-governance">
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
              <p className="hint-text" role="note" aria-label="Build draft runtime effect preview">
                <strong>Draft Build gate impact:</strong>{" "}
                {buildDraftGatePreview(
                  governanceMode,
                  selectedScan.assessment?.status,
                  selectedScan.assessment?.required_scanners_complete,
                )}
                {" "}This is a preview for the selected DRAFT, not confirmation of the active signed runtime policy.
              </p>

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

    </section>
  );
}

function ServerSelector({
  disabled = false,
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
      <select disabled={disabled} onChange={(event) => onChange(event.target.value)} value={value}>
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

// UX-10: four independent facts for one Build scan. Each comes from its own
// record; a draft attachment is never presented as runtime enforcement.
const GATE_MODE_LABELS = {
  DISABLED: "Off (no runtime Build gate)",
  ALLOW_WARN: "Audit only (allows PASS and WARN)",
  REQUIRE_PASS: "Enforce (requires PASS)",
};

export function buildScanFacts(detail, activeRevision) {
  const runs = detail?.scanner_runs || [];
  const completed = runs.filter((run) => run.status === "COMPLETED");
  const incomplete = runs.filter((run) => run.status !== "COMPLETED");
  const requiredIncomplete = incomplete.filter((run) => run.required !== false);
  const assessment = detail?.assessment || null;
  const settings = activeRevision?.content?.build_security;
  const bound = settings?.evidence?.find?.((item) => item.scan_id === detail?.scan?.id) || null;
  let gate;
  if (!activeRevision) gate = { label: "Active signed configuration unavailable", detail: "Runtime gate behaviour cannot be stated from this page." };
  else if (!settings) gate = { label: "Not recorded in the active signed revision", detail: "Revision " + activeRevision.revision_number + " has no Build settings." };
  else gate = {
    label: GATE_MODE_LABELS[settings.mode] || settings.mode,
    detail: (bound ? "This scan is the bound evidence in active signed revision " : "This scan is not bound evidence in active signed revision ")
      + activeRevision.revision_number + ". A draft attachment alone has no runtime effect.",
    bound: Boolean(bound),
  };
  return {
    execution: { label: completed.length + " of " + runs.length + " scanner run(s) completed",
      detail: incomplete.length ? "Not completed: " + incomplete.map((run) => run.scanner_id + " (" + run.status.toLowerCase() + ")").join(", ") + "." : "Every recorded scanner run completed." },
    coverage: { label: requiredIncomplete.length ? "Required coverage incomplete" : runs.length ? "Required scanners complete" : "No scanner runs recorded",
      detail: requiredIncomplete.length ? "Missing coverage is not a PASS, even with zero findings." : "Coverage describes the recorded scanners only." },
    assessment: assessment ? { label: assessment.status + " · " + assessment.critical_count + " critical / " + assessment.high_count + " high",
      detail: "Policy " + assessment.policy_version + "." } : { label: "No assessment recorded", detail: "" },
    gate,
  };
}

const SEVERITY_REASON = {
  critical_findings: "CRITICAL", high_findings: "HIGH", medium_findings: "MEDIUM", low_findings: "LOW", info_findings: "INFO",
};

export function buildReasonTarget(code, detail) {
  if (SEVERITY_REASON[code]) return { kind: "severity", severity: SEVERITY_REASON[code], label: "Show " + SEVERITY_REASON[code].toLowerCase() + " findings" };
  if (code === "required_scanner_incomplete") {
    const run = (detail?.scanner_runs || []).find((item) => item.status !== "COMPLETED" && item.required !== false);
    return run ? { kind: "scanner", scannerId: run.scanner_id, label: "Open " + run.scanner_id + " run" }
      : { kind: "unknown", label: "Associated scanner run not identified" };
  }
  return { kind: "unknown", label: "No exact record is associated with this code" };
}

function BuildScanDetail({ activeRevision = null, detail, isAdmin, loading, source }) {
  const [findingRequest, setFindingRequest] = useState(null);
  if (loading) {
    return <section className="detail-panel"><p className="workflow-progress" role="status">Loading Build scan evidence…</p></section>;
  }
  if (!detail) {
    return (
      <section className="detail-panel">
        <h3>Scan evidence</h3>
        <p className="hint-text">Choose a scan from the history table to inspect its findings and evidence.</p>
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

      {(() => {
        const facts = buildScanFacts(detail, activeRevision);
        return (
          <div className="build-assessment-grid build-scan-facts" aria-label="Build scan facts" role="group">
            {[["Execution", facts.execution, "execution"], ["Coverage", facts.coverage, "coverage"],
              ["Build assessment", facts.assessment, "assessment"], ["Signed gate", facts.gate, "gate"]].map(([title, fact, key]) => (
              <article className="status-panel compact-status" data-fact={key} key={key}>
                <span>{title}</span>
                <strong>{fact.label}</strong>
                {fact.detail && <small>{fact.detail}</small>}
              </article>
            ))}
          </div>
        );
      })()}

      {assessment && <div className="detail-panel" aria-label="Build assessment explanation">
        <h4>Why this Build assessment?</h4>
        <p>{assessment.summary || "The assessment did not record a summary."}</p>
        {!assessment.required_scanners_complete && <p role="alert">
          At least one required scanner did not finish successfully. Missing
          coverage is not a PASS, even when no vulnerability findings appear.
          Review each scanner's status and error code below.</p>}
        {assessment.status === "PASS" && <p>A PASS describes the checks
          actually completed and recorded findings, not proof that the
          repository or deployment is free of security risks.</p>}
        <p role="note">This scan's assessment alone does not establish its
          active runtime effect. The published signed configuration selects
          a Build gate mode and requires current, bound evidence and all
          independent runtime checks.</p>
        {(assessment.reason_codes || []).length > 0 && <details>
          <summary>Recorded assessment reasons ({assessment.reason_codes.length})</summary>
          <ul>{assessment.reason_codes.map((code, index) => {
            const target = buildReasonTarget(code, detail);
            return <li key={index} data-reason-code={code}>
              <code>{code}</code>{" "}
              {target.kind === "severity" && <button className="tiny-action" type="button"
                onClick={() => setFindingRequest({ severity: target.severity, nonce: Date.now() })}>{target.label}</button>}
              {target.kind === "scanner" && <a className="tiny-action" href={"#build-scanner-run-" + target.scannerId}>{target.label}</a>}
              {target.kind === "unknown" && <span className="hint-text">{target.label}</span>}
            </li>;
          })}</ul>
        </details>}
      </div>}
      <h4>Scanner runs</h4>
      <div className="build-scanner-run-list">
        {detail.scanner_runs.map((run) => (
          <article id={"build-scanner-run-" + run.scanner_id} key={run.id} tabIndex={-1}>
            <strong>{run.scanner_id}</strong>
            <span>{run.scanner_version || "-"}</span>
            <StatusBadge value={run.status} />
            <small>{run.finding_count} active finding(s)</small>
            {run.status !== "COMPLETED" && <p role="note">
              No verified completed execution for this scanner. An empty
              findings list must not be interpreted as a successful scan.
            </p>}
            {run.error_code && <p role="alert">Scanner error:
              <code>{run.error_code}</code>. Check scanner installation,
              permissions and bounded worker logs before rerunning.</p>}
          </article>
        ))}
      </div>

      <BuildFindingsBrowser detail={detail} isAdmin={isAdmin} request={findingRequest} source={source} />
    </section>
  );
}

// UX-09: every stored finding is reachable with server paging and exact
// filters; totals come from the same query as the rows.
const FINDINGS_PAGE_SIZE = 50;
const EMPTY_FINDING_FILTERS = { finding_id: "", severity: "", finding_state: "", scanner_id: "", rule_id: "", path: "" };

export function findingsRangeText(page) {
  if (!page) return "";
  if (!page.total) return "No findings match" + (page.unfiltered_total ? " these filters (" + page.unfiltered_total + " stored)." : ".");
  const from = page.offset + 1;
  const to = page.offset + page.returned;
  const filtered = page.total !== page.unfiltered_total ? " · filtered from " + page.unfiltered_total + " stored" : " stored";
  return "Showing " + from + "–" + to + " of " + page.total + filtered + ".";
}

export function BuildFindingsBrowser({ detail, isAdmin, source, request = null, load = fetchBuildScanFindings }) {
  const scanId = detail?.scan?.id;
  const scanners = [...new Set((detail?.scanner_runs || []).map((run) => run.scanner_id))];
  const [draft, setDraft] = useState(EMPTY_FINDING_FILTERS);
  const [applied, setApplied] = useState(EMPTY_FINDING_FILTERS);
  const [offset, setOffset] = useState(0);
  const [state, setState] = useState({ status: "idle", page: null, error: "" });
  const generation = useRef(0);

  useEffect(() => {
    setDraft(EMPTY_FINDING_FILTERS);
    setApplied(EMPTY_FINDING_FILTERS);
    setOffset(0);
    setState({ status: "idle", page: null, error: "" });
  }, [scanId]);

  // UX-10: an assessment reason opens the matching findings filter.
  useEffect(() => {
    if (!request?.severity) return;
    const next = { ...EMPTY_FINDING_FILTERS, severity: request.severity };
    setDraft(next);
    setApplied(next);
    setOffset(0);
    document.getElementById("build-findings-title")?.scrollIntoView({ block: "start" });
  }, [request?.nonce]);

  useEffect(() => {
    if (!scanId) return undefined;
    const current = ++generation.current;
    setState((previous) => ({ ...previous, status: "loading", error: "" }));
    const params = Object.fromEntries(Object.entries(applied).filter(([, value]) => String(value).trim()));
    load(scanId, { ...params, offset, limit: FINDINGS_PAGE_SIZE })
      .then((page) => {
        if (current === generation.current) setState({ status: "ready", page, error: "" });
      })
      .catch((err) => {
        if (current === generation.current) {
          setState((previous) => ({ status: "error", page: previous.page,
            error: "Findings could not be loaded: " + safeErrorMessage(err) }));
        }
      });
    return () => { generation.current += 1; };
  }, [scanId, applied, offset]);

  const page = state.page;
  const items = page?.items || [];
  function update(field, value) {
    setDraft((current) => ({ ...current, [field]: value }));
  }
  return (
    <section aria-labelledby="build-findings-title" className="build-findings-browser">
      <div className="operations-section-heading build-findings-heading">
        <h4 id="build-findings-title">Normalized findings</h4>
        <small role="status" data-testid="build-findings-range">
          {state.status === "loading" && !page ? "Loading findings…" : findingsRangeText(page)}
        </small>
      </div>
      <form className="filter-toolbar build-findings-filters" aria-label="Filter findings" onSubmit={(event) => {
        event.preventDefault();
        setOffset(0);
        setApplied({ ...draft });
      }}>
        <label>Finding ID<input maxLength={36} onChange={(e) => update("finding_id", e.target.value)} value={draft.finding_id} /></label>
        <label>Severity
          <select onChange={(e) => update("severity", e.target.value)} value={draft.severity}>
            <option value="">All</option>
            {["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        </label>
        <label>Lifecycle
          <select onChange={(e) => update("finding_state", e.target.value)} value={draft.finding_state}>
            <option value="">All</option>
            {["NEW", "UNCHANGED", "REGRESSED", "RESOLVED"].map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        </label>
        <label>Scanner
          <select onChange={(e) => update("scanner_id", e.target.value)} value={draft.scanner_id}>
            <option value="">All</option>
            {scanners.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        </label>
        <label className="toolbar-search">Rule<input maxLength={255} onChange={(e) => update("rule_id", e.target.value)} value={draft.rule_id} /></label>
        <label className="toolbar-search">Path contains<input maxLength={512} onChange={(e) => update("path", e.target.value)} value={draft.path} /></label>
        <div className="toolbar-actions">
          <button className="primary-action" disabled={state.status === "loading"} type="submit">Apply</button>
          <button disabled={state.status === "loading"} className="secondary-action" onClick={() => { setDraft(EMPTY_FINDING_FILTERS); setOffset(0); setApplied(EMPTY_FINDING_FILTERS); }} type="button">Clear</button>
        </div>
      </form>
      {state.error && <p className="error-text" role="alert">{state.error}{page ? " The rows below are from the previous read." : ""}</p>}
      <div aria-busy={state.status === "loading"} aria-label="Build findings" className="table-wrap" role="region" tabIndex={0}>
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
            {items.map((finding) => (
              <tr data-finding-id={finding.id} key={finding.id}>
                <td><StatusBadge value={finding.finding_state} /></td>
                <td><SeverityBadge value={finding.severity} /></td>
                <td>{finding.scanner_id}</td>
                <td>
                  <strong>{finding.vulnerability_id || finding.rule_id}</strong>
                  <small className="build-finding-title">{finding.title}</small>
                  <small className="build-finding-id">ID <code>{finding.id}</code></small>
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
                        <a className="tiny-action build-source-link" href={gitFindingHref(source, detail.scan, finding)}
                          rel="noreferrer" target="_blank">
                          Open source at scanned revision
                        </a>
                      )}
                    </>
                  )}
                </td>
                <td>{finding.remediation || "-"}</td>
              </tr>
            ))}
            {state.status !== "loading" && page && items.length === 0 && (
              <tr><td colSpan="6">{page.unfiltered_total ? "No stored findings match these filters." : "No normalized findings for this scan."}</td></tr>
            )}
          </tbody>
        </table>
      </div>
      <div className="pagination-bar">
        <button disabled={state.status === "loading" || offset === 0} onClick={() => setOffset(Math.max(0, offset - FINDINGS_PAGE_SIZE))} type="button">Previous</button>
        <span>{page?.total ? "Page " + (Math.floor(offset / FINDINGS_PAGE_SIZE) + 1) + " of " + Math.ceil(page.total / FINDINGS_PAGE_SIZE) : ""}</span>
        <button disabled={state.status === "loading" || !page?.has_more} onClick={() => setOffset(offset + FINDINGS_PAGE_SIZE)} type="button">Next</button>
      </div>
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
  return formatServerTime(value);
}

function humanize(value) {
  return String(value || "-")
    .replaceAll("_", " ")
    .replace(/(^|\s)\S/g, (character) => character.toUpperCase());
}

export default BuildSecurity;
