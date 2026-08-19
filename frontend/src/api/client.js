const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000/api/v1";

let csrfToken = "";

export function setCsrfToken(value) {
  csrfToken = value || "";
}

function csrfFromCookie() {
  return document.cookie
    .split("; ")
    .find((part) => part.startsWith("mcp_control_plane_csrf="))
    ?.split("=")[1];
}

async function request(path, options = {}) {
  const headers = { ...(options.headers || {}) };
  const method = options.method || "GET";
  const activeCsrfToken = csrfToken || csrfFromCookie();
  if (method !== "GET" && activeCsrfToken) {
    headers["x-csrf-token"] = decodeURIComponent(activeCsrfToken);
  }
  if (options.body && !headers["Content-Type"]) {
    headers["Content-Type"] = "application/json";
  }

  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...options,
    method,
    headers,
    credentials: "include",
  });

  if (!response.ok) {
    let detail = "";
    try {
      const payload = await response.json();
      detail = payload?.detail ? `: ${payload.detail}` : "";
    } catch {
      detail = "";
    }
    throw new Error(`Backend request failed: ${response.status}${detail}`);
  }

  if (response.status === 204) {
    return null;
  }
  const text = await response.text();
  return text ? JSON.parse(text) : null;
}

export async function fetchServers() {
  return request("/servers");
}

export async function fetchTools() {
  return request("/tools");
}

export async function fetchPolicies() {
  return request("/policies");
}

export async function fetchRuntimeLogs() {
  return request("/runtime/logs");
}

export async function fetchHealth() {
  return request("/health");
}

export async function fetchLocalRuntimeStatus() {
  return request("/control-plane/local-runtime/status");
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

export async function fetchToolAnalysisBundle(toolId) {
  const [status, analyses, findings, versions, baseline, diff] = await Promise.all([
    request(`/tool-analysis/tools/${toolId}/status`),
    request(`/tool-analysis/tools/${toolId}/analyses`),
    request(`/tool-analysis/tools/${toolId}/findings`),
    request(`/tool-analysis/tools/${toolId}/versions`),
    request(`/tool-analysis/tools/${toolId}/baseline`),
    request(`/tool-analysis/tools/${toolId}/diff`),
  ]);

  return { status, analyses, findings, versions, baseline, diff };
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

export async function discoverHttpMcpServer(
  endpoint,
  protocolVersion = "2025-11-25",
  authMode = "NONE",
  credentialRef = null,
) {
  return request("/inventory/discover-http", {
    method: "POST",
    body: JSON.stringify({
      endpoint,
      protocol_version: protocolVersion,
      auth_mode: authMode,
      credential_ref: credentialRef || null,
    }),
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

export async function patchConfigRevision(draftId, content, changeSummary) {
  return request(`/control-plane/config/revisions/${draftId}`, {
    method: "PATCH",
    body: JSON.stringify({ content, change_summary: changeSummary }),
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
