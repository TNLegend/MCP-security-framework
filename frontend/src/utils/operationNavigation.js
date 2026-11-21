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