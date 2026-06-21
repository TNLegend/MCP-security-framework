const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000/api/v1";

async function request(path) {
  const response = await fetch(`${API_BASE_URL}${path}`);

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
