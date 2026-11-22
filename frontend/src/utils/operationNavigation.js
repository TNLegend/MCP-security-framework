// Only immutable, syntactically valid operation IDs may become investigation
// links. Do not treat a generic audit target as a Runtime operation.
const OPERATION_ID = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i;

export function normalizeOperationId(candidate) {
  const value = String(candidate || "").trim();
  return OPERATION_ID.test(value) ? value.toLowerCase() : null;
}

export function operationFromQuery(search) {
  const params = new URLSearchParams(search || "");
  if (params.get("view") !== "operations") return null;
  return normalizeOperationId(params.get("operation_id"));
}

export function auditOperationLink(targetType, targetId) {
  const id = targetType === "runtime_operation" ? normalizeOperationId(targetId) : null;
  return id ? "?view=operations&operation_id=" + encodeURIComponent(id) : null;
}

const exactTargetViews = {
  mcp_server: "inventory",
  tool_protocol_observation: "analysis",
  control_plane_config_revision: "config",
  emergency_deny: "emergency",
  control_plane_user: "users",
};

export function recordTypeForView(view) {
  return Object.keys(exactTargetViews).find((type) => exactTargetViews[type] === view) || null;
}

// Only create exact-target links supported by the destination screen's
// identity guard. Do not substitute a generic module page for a deep link.
export function auditTargetLink(targetType, targetId) {
  const operation = auditOperationLink(targetType, targetId);
  if (operation) return operation;
  if (targetType === "mcp_tool" && typeof targetId !== "object") {
    const id = String(targetId || "");
    if (/^[1-9][0-9]{0,12}$/.test(id) && Number.isSafeInteger(Number(id))) {
      return "?view=analysis&tool=" + encodeURIComponent(id);
    }
  }
  const view = exactTargetViews[targetType];
  if (targetType === "mcp_server" || targetType === "tool_protocol_observation") {
    const id = String(targetId || "");
    return /^[1-9][0-9]{0,9}$/.test(id) && Number(id) <= 2147483647
      ? "?view=" + view + "&record=" + id : null;
  }
  const uuid = normalizeOperationId(targetId);
  if (uuid && targetType === "cloud_scan") return "?view=cloud&scan=" + uuid;
  return uuid && view ? "?view=" + view + "&record=" + uuid : null;
}
