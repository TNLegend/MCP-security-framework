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
    throw new Error(`Backend request failed: ${response.status}`);
  }

  return response.json();
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
