const API_BASE_URL =
  import.meta.env?.VITE_API_BASE_URL || "http://127.0.0.1:8000/api/v1";
const REQUEST_TIMEOUT_MS = 20_000;
// Large third-party inventories run analyzer inference per observed tool/profile.
// Keep a finite deadline, but allow the same bounded window as a build scan.
const DISCOVERY_TIMEOUT_MS = 600_000;
const BUILD_SCAN_TIMEOUT_MS = 600_000;
const ERROR_MESSAGES = Object.freeze({
  upstream_oauth_dynamic_registration_unsupported:
    "This MCP does not support automatic OAuth registration. Enter a provider-issued OAuth client ID and try again.",
});

let csrfToken = "";

export class ApiError extends Error {
  constructor(message, { status = 0, code = "request_failed", fieldErrors = [] } = {}) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.fieldErrors = fieldErrors;
  }
}

export function setCsrfToken(value) {
  csrfToken = value || "";
}

function csrfFromCookie() {
  return document.cookie
    .split("; ")
    .find((part) => part.startsWith("mcp_control_plane_csrf="))
    ?.split("=")[1];
}

export function hasControlPlaneSession() {
  return Boolean(csrfFromCookie());
}

async function request(path, options = {}) {
  const { timeoutMs = REQUEST_TIMEOUT_MS, ...requestOptions } = options;
  const headers = { ...(requestOptions.headers || {}) };
  const method = requestOptions.method || "GET";
  const activeCsrfToken = csrfToken || csrfFromCookie();
  if (method !== "GET" && activeCsrfToken) {
    headers["x-csrf-token"] = decodeURIComponent(activeCsrfToken);
  }
  if (options.body && !headers["Content-Type"]) {
    headers["Content-Type"] = "application/json";
  }

  const controller = new AbortController();
  const timeout = globalThis.setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(`${API_BASE_URL}${path}`, {
      ...requestOptions,
      method,
      headers,
      credentials: "include",
      signal: controller.signal,
    });
    if (!response.ok) {
      let payload = null;
      let text = "";
      try {
        text = await response.text();
        payload = text ? JSON.parse(text) : null;
      } catch (err) {
        if (controller.signal.aborted || err?.name === "AbortError") throw err;
        payload = null;
      }
      if (controller.signal.aborted) throw new ApiError("Request timed out.", { code: "request_timeout", status: 0 });
      throw apiErrorFromResponse(response.status, payload, text);
    }
    if (response.status === 204) return null;
    const text = await response.text();
    if (controller.signal.aborted) throw new ApiError("Request timed out.", { code: "request_timeout", status: 0 });
    return text ? JSON.parse(text) : null;
  } catch (err) {
    if (controller.signal.aborted || err?.name === "AbortError") {
      throw new ApiError("Request timed out. Please retry.", {
        code: "request_timeout",
        status: 0,
      });
    }
    if (err instanceof ApiError || err instanceof SyntaxError) throw err;
    throw new ApiError("Network request failed.", {
      code: "network_error",
      status: 0,
    });
  } finally {
    // The deadline includes reading/parsing the entire response body.
    globalThis.clearTimeout(timeout);
  }
}

async function requestBlob(path) {
  const controller = new AbortController();
  const timeout = globalThis.setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    const response = await fetch(`${API_BASE_URL}${path}`, {
      credentials: "include",
      signal: controller.signal,
    });
    if (!response.ok) {
      let payload = null;
      let text = "";
      try {
        text = await response.text();
        payload = text ? JSON.parse(text) : null;
      } catch (err) {
        if (controller.signal.aborted || err?.name === "AbortError") throw err;
        payload = null;
      }
      if (controller.signal.aborted) throw new ApiError("Request timed out.", { code: "request_timeout", status: 0 });
      throw apiErrorFromResponse(response.status, payload, text);
    }
    const blob = await response.blob();
    if (controller.signal.aborted) throw new ApiError("Request timed out.", { code: "request_timeout", status: 0 });
    return blob;
  } catch (err) {
    if (controller.signal.aborted || err?.name === "AbortError") {
      throw new ApiError("Request timed out. Please retry.", {
        code: "request_timeout",
        status: 0,
      });
    }
    if (err instanceof ApiError) throw err;
    throw new ApiError("Network request failed.", {
      code: "network_error",
      status: 0,
    });
  } finally {
    globalThis.clearTimeout(timeout);
  }
}

export function apiErrorFromResponse(status, payload, text = "") {
  const formatted = formatApiErrorDetail(payload?.detail ?? payload ?? text);
  return new ApiError(`Backend request failed: ${status}${formatted.message ? `: ${formatted.message}` : ""}`, {
    status,
    code: formatted.code,
    fieldErrors: formatted.fieldErrors,
  });
}

export function formatApiErrorDetail(detail) {
  if (Array.isArray(detail)) {
    const fieldErrors = detail
      .map((item) => {
        if (!item || typeof item !== "object") {
          return null;
        }
        return {
          field: formatValidationPath(item.loc),
          message:
            safeScalarMessage(item.msg) ||
            safeScalarMessage(item.type) ||
            "Invalid value.",
          type: typeof item.type === "string" ? item.type : undefined,
        };
      })
      .filter(Boolean);
    return {
      code: "validation_error",
      fieldErrors,
      message: fieldErrors
        .map((error) => `${fieldLabel(error.field)}: ${error.message}`)
        .join(" "),
    };
  }
  if (typeof detail === "string") {
    const code = detail || "request_failed";
    return {
      code,
      fieldErrors: [],
      message: ERROR_MESSAGES[code] || safeMessage(detail),
    };
  }
  if (detail && typeof detail === "object") {
    const code =
      safeScalarMessage(detail.code) ||
      safeScalarMessage(detail.error) ||
      safeScalarMessage(detail.detail) ||
      "request_failed";
    const message =
      safeScalarMessage(detail.message) ||
      safeScalarMessage(detail.error) ||
      safeScalarMessage(detail.code) ||
      safeScalarMessage(detail.detail) ||
      "Request failed.";
    return { code, fieldErrors: [], message };
  }
  return { code: "request_failed", fieldErrors: [], message: "Request failed." };
}

export function safeErrorMessage(err) {
  const message = err instanceof ApiError ? err.message : safeMessage(err?.message || "");
  const code = String(err?.code || "");
  if (/security_pack_ai_unavailable|controlled_ai_unavailable|Gemini API returned HTTP 503|Groq API returned HTTP 503/i.test(message + " " + code)) {
    return "AI assistance is temporarily unavailable. You can continue manually or retry later; no security settings were changed.";
  }
  return message || "Request failed.";
}

export async function settleNamedRequests(requests) {
  const entries = Object.entries(requests);
  const settled = await Promise.allSettled(entries.map(([, run]) => run()));
  const result = { errors: {} };
  settled.forEach((entry, index) => {
    const key = entries[index][0];
    if (entry.status === "fulfilled") {
      result[key] = entry.value;
    } else {
      result.errors[key] = safeErrorMessage(entry.reason);
    }
  });
  return result;
}

function formatValidationPath(loc) {
  if (!Array.isArray(loc)) {
    return "request";
  }
  const parts = loc.filter((part) => part !== "body" && part !== "query" && part !== "path");
  return parts.length > 0 ? parts.join(".") : "request";
}

function fieldLabel(field) {
  return String(field || "request")
    .split(".")
    .map((part) => part.replace(/_/g, " "))
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function safeMessage(value) {
  return String(value || "")
    .replace(/\s+/g, " ")
    .slice(0, 500)
    .trim();
}

function safeScalarMessage(value) {
  if (typeof value !== "string" && typeof value !== "number") {
    return "";
  }
  return safeMessage(value);
}

export async function fetchServers() {
  return request("/servers");
}

export async function archiveServer(serverId, reason) {
  return request(`/servers/${serverId}/archive`, {
    method: "POST",
    body: JSON.stringify({ reason }),
  });
}

export async function trustServer(serverId, reason) {
  return request(`/servers/${serverId}/trust`, {
    method: "POST",
    body: JSON.stringify({ reason }),
  });
}

export async function revokeServerTrust(serverId, reason) {
  return request(`/servers/${serverId}/revoke-trust`, {
    method: "POST",
    body: JSON.stringify({ reason }),
  });
}

export async function fetchTools() {
  return request("/tools");
}

export async function fetchPolicies() {
  return request("/policies");
}

export async function fetchRuntimeLogs(filters = {}) {
  const query = new URLSearchParams();
  Object.entries(filters).forEach(([key, value]) => {
    if (value !== null && value !== undefined && value !== "") {
      query.set(key, String(value));
    }
  });
  const queryString = query.toString();
  const suffix = queryString ? `?${queryString}` : "";
  return request(`/runtime/logs${suffix}`);
}

export async function fetchHealth() {
  return request("/health");
}

export async function fetchLocalRuntimeStatus() {
  return request("/control-plane/local-runtime/status");
}

export async function fetchOperationsSummary() {
  return request("/control-plane/operations/summary");
}

export async function fetchRuntimeOperationReconciliation(operationId) {
  if (!/^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(String(operationId || ""))) {
    throw new ApiError("No valid operation ID was recorded for reconciliation.", {
      code: "invalid_runtime_operation_id",
    });
  }
  return request("/control-plane/operations/runtime-operations/" +
    encodeURIComponent(operationId) + "/reconciliation");
}

export async function fetchBuildScanners() {
  return request("/control-plane/build-security/scanners");
}

export async function fetchBuildScans(filters = {}) {
  const query = new URLSearchParams();
  Object.entries(filters).forEach(([key, value]) => {
    if (value !== null && value !== undefined && value !== "") {
      query.set(key, String(value));
    }
  });
  const suffix = query.toString() ? `?${query.toString()}` : "";
  return request(`/control-plane/build-security/scans${suffix}`);
}

export async function fetchBuildScan(scanId) {
  return request(
    `/control-plane/build-security/scans/${encodeURIComponent(scanId)}`,
  );
}

export async function pickBuildLocalDirectory() {
  return request("/control-plane/build-security/targets/local/pick-directory", {
    method: "POST",
    body: JSON.stringify({}),
    timeoutMs: 300000,
  });
}

export async function startLocalBuildScan(payload) {
  return request("/control-plane/build-security/scans/local", {
    method: "POST",
    body: JSON.stringify(payload),
    timeoutMs: BUILD_SCAN_TIMEOUT_MS,
  });
}

export async function startGitBuildScan(payload) {
  return request("/control-plane/build-security/scans/git", {
    method: "POST",
    body: JSON.stringify(payload),
    timeoutMs: BUILD_SCAN_TIMEOUT_MS,
  });
}

export async function startInventoryBuildScan(serverId, payload) {
  return request(
    `/control-plane/build-security/scans/inventory/${encodeURIComponent(serverId)}`,
    {
      method: "POST",
      body: JSON.stringify(payload),
      timeoutMs: BUILD_SCAN_TIMEOUT_MS,
    },
  );
}

export async function fetchBuildSourceBindings() {
  return request("/control-plane/build-security/inventory/sources");
}

export async function fetchBuildScanSources() {
  return request("/control-plane/build-security/scan-sources?limit=500");
}

export async function fetchBuildSourceBinding(serverId) {
  return request(
    `/control-plane/build-security/inventory/${encodeURIComponent(serverId)}/source`,
  );
}

export async function attachBuildScanToDraft(scanId, payload) {
  return request(
    `/control-plane/build-security/scans/${encodeURIComponent(scanId)}/attach-to-draft`,
    {
      method: "POST",
      body: JSON.stringify(payload),
    },
  );
}

export async function configureBuildSourceBinding(serverId, payload) {
  return request(
    `/control-plane/build-security/inventory/${encodeURIComponent(serverId)}/source`,
    {
      method: "PUT",
      body: JSON.stringify(payload),
    },
  );
}


export async function cleanupRuntimeLogs(payload) {
  return request("/control-plane/operations/runtime-logs/cleanup", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function loginControlPlane(username, password) {
  const payload = await request("/control-plane/auth/login", {
    method: "POST",
    body: JSON.stringify({ username, password }),
  });
  setCsrfToken(payload.csrf_token);
  return payload;
}

export async function fetchControlPlaneMe() {
  return request("/control-plane/auth/me");
}

export async function logoutControlPlane() {
  const payload = await request("/control-plane/auth/logout", { method: "POST" });
  setCsrfToken("");
  return payload;
}

export async function requestControlledAIAssistance(toolId, payload) {
  return request(`/control-plane/ai-assistance/tools/${toolId}`, {
    method: "POST",
    body: JSON.stringify(payload),
    timeoutMs: 60_000,
  });
}

/** Advisory M4 only: ADMIN-authenticated, on-demand and read-only. */
export async function fetchM4Semantics(toolId) {
  return request(`/control-plane/tool-analysis/tools/${toolId}/m4-semantics`, {
    timeoutMs: 180_000,
  });
}

export async function fetchToolAnalysisBundle(toolId) {
  const bundle = await settleNamedRequests({
    status: () => request(`/tool-analysis/tools/${toolId}/status`),
    analyses: () => request(`/tool-analysis/tools/${toolId}/analyses`),
    findings: () => request(`/tool-analysis/tools/${toolId}/findings`),
    versions: () => request(`/tool-analysis/tools/${toolId}/versions`),
    baseline: () => request(`/tool-analysis/tools/${toolId}/baseline`),
    reviews: () => request(`/tool-analysis/tools/${toolId}/reviews`),
    diff: () => request(`/tool-analysis/tools/${toolId}/diff`),
  });

  return {
    status: bundle.status ?? null,
    analyses: bundle.analyses ?? [],
    findings: bundle.findings ?? [],
    versions: bundle.versions ?? [],
    baseline: bundle.baseline ?? null,
    reviews: bundle.reviews ?? [],
    diff: bundle.diff ?? null,
    errors: bundle.errors,
  };
}

export async function fetchSecurityPacks(draftRevisionId = null) {
  return request(withDraftRevision("/control-plane/security-packs", draftRevisionId));
}

export async function fetchSecurityPackLifecycle(draftRevisionId = null) {
  return request(withDraftRevision(
    "/control-plane/security-packs/lifecycle",
    draftRevisionId,
  ));
}

export async function fetchTrustedAdapters() {
  return request("/control-plane/security-packs/adapters");
}

export async function downloadTrustedAdapterStarter(starterId, adapterId) {
  return requestBlob(
    `/control-plane/security-packs/adapters/starters/${encodeURIComponent(starterId)}`
      + `?adapter_id=${encodeURIComponent(adapterId)}`,
  );
}

export async function validateSecurityPackPackage(payload) {
  return request("/control-plane/security-packs/lifecycle/validate", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function installSecurityPackPackage(payload) {
  return request("/control-plane/security-packs/lifecycle/install", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function setSecurityPackEnabled(packId, enabled, payload) {
  return request(
    `/control-plane/security-packs/lifecycle/${encodeURIComponent(packId)}/${enabled ? "enable" : "disable"}`,
    { method: "POST", body: JSON.stringify(payload) },
  );
}

export async function activateSecurityPackVersion(packId, payload) {
  return request(
    `/control-plane/security-packs/lifecycle/${encodeURIComponent(packId)}/activate-version`,
    { method: "POST", body: JSON.stringify(payload) },
  );
}

export async function deprecateSecurityPackVersion(packId, payload) {
  return request(
    `/control-plane/security-packs/lifecycle/${encodeURIComponent(packId)}/deprecate-version`,
    { method: "POST", body: JSON.stringify(payload) },
  );
}

export async function removeSecurityPackInstallation(packId, payload) {
  return request(
    `/control-plane/security-packs/lifecycle/${encodeURIComponent(packId)}`,
    { method: "DELETE", body: JSON.stringify(payload) },
  );
}

export async function fetchToolTemplateSuggestions(toolId, draftRevisionId = null) {
  return request(withDraftRevision(
    `/control-plane/security-packs/tools/${toolId}/suggestions`,
    draftRevisionId,
  ));
}

export async function fetchToolAdapterGuidance(toolId, draftRevisionId = null) {
  return request(withDraftRevision(
    `/control-plane/security-packs/tools/${toolId}/adapter-guidance`,
    draftRevisionId,
  ));
}

export async function fetchAIToolTemplateSuggestion(toolId, draftRevisionId = null) {
  return request(withDraftRevision(
    `/control-plane/security-packs/tools/${toolId}/ai-suggestion`,
    draftRevisionId,
  ), {
    method: "POST",
  });
}

export async function fetchAIToolSecurityPackDraft(toolId, draftRevisionId = null) {
  return request(withDraftRevision(
    `/control-plane/security-packs/tools/${toolId}/ai-pack-draft`,
    draftRevisionId,
  ), { method: "POST" });
}

export async function createToolSecurityPackDraft(toolId, payload) {
  return request(`/control-plane/security-packs/tools/${toolId}/packs/draft`, {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function createToolContractDraft(toolId, payload) {
  return request(`/control-plane/security-packs/tools/${toolId}/contracts/draft`, {
    method: "POST",
    body: JSON.stringify(payload),
    timeoutMs: DISCOVERY_TIMEOUT_MS,
  });
}

export async function addDeclarativeSecurityPack(payload) {
  return request("/control-plane/security-packs/declarative", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function renewApprovedToolObservations(toolId, payload) {
  return request(`/control-plane/security-packs/tools/${toolId}/contracts/renew-approved-observations`, {
    method: "POST",
    body: JSON.stringify(payload),
    timeoutMs: DISCOVERY_TIMEOUT_MS,
  });
}

export async function reanalyzeToolContract(toolId) {
  return request(`/control-plane/security-packs/tools/${toolId}/reanalyze`, {
    method: "POST",
  });
}

function withDraftRevision(path, draftRevisionId) {
  return draftRevisionId
    ? `${path}?draft_revision_id=${encodeURIComponent(draftRevisionId)}`
    : path;
}

export async function fetchAllToolAnalyses() {
  return request("/control-plane/tool-analysis/analyses");
}

export async function approveTool(toolId, fingerprint, justification) {
  return request(`/control-plane/tool-analysis/tools/${toolId}/approve`, {
    method: "POST",
    body: JSON.stringify({ fingerprint, justification }),
  });
}

export async function blockTool(toolId, fingerprint, justification) {
  return request(`/control-plane/tool-analysis/tools/${toolId}/block`, {
    method: "POST",
    body: JSON.stringify({ fingerprint, justification }),
  });
}

export function buildDiscoveryRequestBody(
  endpoint,
  protocolVersion = "2025-11-25",
  authMode = "NONE",
  credentialRef = null,
) {
  return {
    endpoint,
    protocol_version: protocolVersion,
    auth_mode: authMode,
    credential_ref: credentialRef || null,
  };
}

export async function discoverHttpMcpServer(
  endpoint,
  protocolVersion = "2025-11-25",
  authMode = "NONE",
  credentialRef = null,
) {
  return request("/inventory/discover-http", {
    method: "POST",
    body: JSON.stringify(
      buildDiscoveryRequestBody(endpoint, protocolVersion, authMode, credentialRef),
    ),
    timeoutMs: DISCOVERY_TIMEOUT_MS,
  });
}

export async function discoverRegisteredMcpServer(serverId) {
  return request(`/inventory/servers/${serverId}/discover`, {
    method: "POST",
    timeoutMs: DISCOVERY_TIMEOUT_MS,
  });
}

export async function registerOAuthMcpServer(payload) {
  return request("/control-plane/upstream-oauth/servers", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function fetchOAuthCallbackUri() {
  return request("/control-plane/upstream-oauth/callback-uri");
}

export async function startOAuthConnection(serverId) {
  return request(`/control-plane/upstream-oauth/servers/${serverId}/connect`, {
    method: "POST",
  });
}

export async function disconnectOAuthMcpServer(serverId) {
  return request(`/control-plane/upstream-oauth/servers/${serverId}/disconnect`, {
    method: "POST",
  });
}

export async function fetchConfigRevisions() {
  return request("/control-plane/config/revisions");
}

export async function fetchActiveConfigRevision() {
  return request("/control-plane/config/active");
}

export async function createDraftRevision(publishedId, changeSummary) {
  return request(`/control-plane/config/revisions/${publishedId}/draft`, {
    method: "POST",
    body: JSON.stringify({ change_summary: changeSummary }),
  });
}

export async function createLatestConfigRevision(changeSummary) {
  return request("/control-plane/config/revisions/latest", {
    method: "POST",
    body: JSON.stringify({ change_summary: changeSummary }),
  });
}

export async function patchConfigRevision(draftId, content, changeSummary, expectedContentHash) {
  return request(`/control-plane/config/revisions/${draftId}`, {
    method: "PATCH",
    body: JSON.stringify({
      content,
      change_summary: changeSummary,
      expected_content_hash: expectedContentHash,
    }),
  });
}

export async function validateConfigRevision(draftId, changeSummary) {
  return request(`/control-plane/config/revisions/${draftId}/validate`, {
    method: "POST",
    body: JSON.stringify({ change_summary: changeSummary }),
  });
}

export async function publishConfigRevision(draftId, changeSummary) {
  return request(`/control-plane/config/revisions/${draftId}/publish`, {
    method: "POST",
    body: JSON.stringify({ change_summary: changeSummary }),
  });
}

export async function rollbackConfigRevision(revisionId, changeSummary) {
  return request(`/control-plane/config/revisions/${revisionId}/rollback`, {
    method: "POST",
    body: JSON.stringify({ change_summary: changeSummary }),
  });
}

export async function deleteConfigRevision(revisionId, changeSummary) {
  return request(`/control-plane/config/revisions/${revisionId}`, {
    method: "DELETE",
    body: JSON.stringify({ change_summary: changeSummary }),
  });
}

export async function fetchEmergencyDenies() {
  return request("/control-plane/emergency-denies");
}

export async function createEmergencyDeny(payload) {
  return request("/control-plane/emergency-denies", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function revokeEmergencyDeny(denyId) {
  return request(`/control-plane/emergency-denies/${denyId}`, {
    method: "DELETE",
  });
}

export async function fetchAuditEvents() {
  return request("/control-plane/audit/events");
}

export async function fetchAuditEventPage({ limit = 20, offset = 0, search = "" } = {}) {
  const params = new URLSearchParams({
    limit: String(limit),
    offset: String(offset),
  });
  if (search.trim()) {
    params.set("search", search.trim());
  }
  return request(`/control-plane/audit/events/page?${params.toString()}`);
}

export async function fetchUsers() {
  return request("/control-plane/users");
}

export async function createUser(payload) {
  return request("/control-plane/users", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function updateUser(userId, payload) {
  return request(`/control-plane/users/${userId}`, {
    method: "PATCH",
    body: JSON.stringify(payload),
  });
}

export async function enableUser(userId) {
  return request(`/control-plane/users/${userId}/enable`, {
    method: "POST",
  });
}

export async function disableUser(userId, reason) {
  return request(`/control-plane/users/${userId}/disable`, {
    method: "POST",
    body: JSON.stringify({ reason }),
  });
}

export async function resetUserPassword(userId, newPassword, reason) {
  return request(`/control-plane/users/${userId}/reset-password`, {
    method: "POST",
    body: JSON.stringify({ new_password: newPassword, reason }),
  });
}

export async function revokeUserSessions(userId, reason) {
  return request(`/control-plane/users/${userId}/revoke-sessions`, {
    method: "POST",
    body: JSON.stringify({ reason }),
  });
}


export async function fetchCloudEnvironments() {
  return request("/control-plane/cloud-security/environments", { timeoutMs: 45000 });
}

export async function createCloudEnvironment(payload) {
  return request("/control-plane/cloud-security/environments", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function updateCloudEnvironment(id, payload) {
  return request(`/control-plane/cloud-security/environments/${id}`, {
    method: "PATCH",
    body: JSON.stringify(payload),
  });
}

export async function testCloudEnvironment(id) {
  return request(`/control-plane/cloud-security/environments/${id}/test`, {
    method: "POST", timeoutMs: 45000,
  });
}

export async function startCloudScan(id) {
  return request(`/control-plane/cloud-security/environments/${id}/scans`, {
    method: "POST",
  });
}

export async function fetchCloudScans(environmentId = null) {
  const qs = environmentId ? `?environment_id=${encodeURIComponent(environmentId)}` : "";
  return request(`/control-plane/cloud-security/scans${qs}`, { timeoutMs: 45000 });
}

export async function fetchCloudScanDetail(scanId) {
  return request(`/control-plane/cloud-security/scans/${scanId}`, { timeoutMs: 45000 });
}

// ZIP bytes are sent verbatim, not as JSON or multipart form data.
export async function uploadTerraformZip(file) {
  return request("/control-plane/cloud-security/iac/scans", {
    method: "POST",
    headers: { "Content-Type": "application/zip" },
    body: file,
    timeoutMs: 45000,
  });
}

export async function fetchIaCScannerAvailability() {
  return request("/control-plane/cloud-security/iac/scanners", { timeoutMs: 45000 });
}

// Prowler audits reuse an already verified AWS environment and audit role.
export async function fetchProwlerAvailability() {
  return request("/control-plane/cloud-security/advanced/scanner", { timeoutMs: 45000 });
}

export async function startProwlerCloudScan(id) {
  return request(
    "/control-plane/cloud-security/environments/" + encodeURIComponent(id) + "/advanced-scans",
    { method: "POST", timeoutMs: 45000 },
  );
}


export async function fetchProwlerPermissionPreview(id) {
  return request(
    "/control-plane/cloud-security/environments/" + encodeURIComponent(id) + "/advanced/permissions",
    { timeoutMs: 45000 },
  );
}

export async function fetchIAMMappings(environmentId) {
  return request("/control-plane/cloud-security/environments/" +
    encodeURIComponent(environmentId) + "/iam-mappings");
}

export async function fetchIAMMappingContext(environmentId, serverId) {
  return request("/control-plane/cloud-security/environments/" +
    encodeURIComponent(environmentId) + "/iam-mapping-context?mcp_server_id=" +
    encodeURIComponent(serverId));
}

export async function createIAMMapping(environmentId, data) {
  return request("/control-plane/cloud-security/environments/" +
    encodeURIComponent(environmentId) + "/iam-mappings", {
      method: "POST", body: JSON.stringify(data), timeoutMs: 45000,
    });
}

export async function approveIAMMapping(environmentId, mappingId) {
  return request("/control-plane/cloud-security/environments/" +
    encodeURIComponent(environmentId) + "/iam-mappings/" +
    encodeURIComponent(mappingId) + "/approve", {
      method: "POST", body: JSON.stringify({ confirm: true }), timeoutMs: 45000,
    });
}

export async function startIAMMCPComparison(environmentId, mappingId) {
  return request("/control-plane/cloud-security/environments/" +
    encodeURIComponent(environmentId) + "/iam-comparisons", {
      method: "POST", body: JSON.stringify({ mapping_id: mappingId }),
      timeoutMs: 45000,
    });
}

export async function evaluateDeployGovernance(scanId) {
  return request("/control-plane/cloud-security/scans/" +
    encodeURIComponent(scanId) + "/deploy-governance/evaluations", {
      method: "POST", timeoutMs: 15000,
    });
}

export async function fetchDeployGovernanceHistory(scanId) {
  return request("/control-plane/cloud-security/scans/" +
    encodeURIComponent(scanId) + "/deploy-governance/history");
}

export async function fetchDeployExceptions(scanId) {
  return request("/control-plane/cloud-security/scans/" +
    encodeURIComponent(scanId) + "/deploy-exceptions");
}

export async function requestDeployException(scanId, data) {
  return request("/control-plane/cloud-security/scans/" +
    encodeURIComponent(scanId) + "/deploy-exceptions", {
      method: "POST", body: JSON.stringify(data),
    });
}

export async function decideDeployException(scanId, exceptionId, data) {
  return request("/control-plane/cloud-security/scans/" +
    encodeURIComponent(scanId) + "/deploy-exceptions/" +
    encodeURIComponent(exceptionId) + "/decide", {
      method: "POST", body: JSON.stringify(data),
    });
}

export async function fetchDeployGovernance(scanId) {
  return request("/control-plane/cloud-security/scans/" +
    encodeURIComponent(scanId) + "/deploy-governance",
    { timeoutMs: 15000 });
}

export async function fetchIAMMCPResults(scanId) {
  return request("/control-plane/cloud-security/scans/" + encodeURIComponent(scanId) + "/iam-comparisons",
    { timeoutMs: 45000 });
}
