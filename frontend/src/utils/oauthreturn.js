// A callback fragment is an untrusted browser hint, not proof of a
// successful provider or Control Plane authorization.
export function parseOAuthReturn(fragment) {
  if (typeof fragment !== "string" || !fragment.startsWith("#?oauth=")) {
    return null;
  }
  const params = new URLSearchParams(fragment.slice(2));
  const result = params.get("oauth");
  if (!["connected", "failed"].includes(result)) return null;
  const raw = params.get("server_id");
  const serverId = raw && /^[1-9][0-9]{0,9}$/.test(raw) ? Number(raw) : null;
  return { result, serverId };
}

export function oauthReturnDescription(callback, verifiedServer) {
  if (!callback) return "";
  if (callback.result === "failed") {
    return "OAuth connection was reported unsuccessful. Review the server OAuth status and its recorded error; retry only after correcting the cause.";
  }
  if (verifiedServer?.oauth_status === "CONNECTED") {
    return "OAuth callback reported completion and the latest server inventory confirms CONNECTED.";
  }
  return "OAuth callback reported completion, but the persisted server connection has not been verified. Refresh the inventory before attempting discovery.";
}
