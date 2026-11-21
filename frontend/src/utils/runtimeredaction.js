// Defense-in-depth for historical Runtime records. These can predate the
// current Proxy's bounded summaries and can contain untrusted upstream text.
// This presentation helper neither deletes nor rewrites persisted evidence.
const SENSITIVE_KEY = /(?:^|[_-])(api[_-]?key|private[_-]?key|access[_-]?token|refresh[_-]?token|secret|password|passwd|credential|authorization|cookie|session[_-]?token)(?:$|[_-])/i;
const MAX_DEPTH = 6;
const MAX_ARRAY = 32;
const MAX_OBJECT = 64;
const MAX_STRING = 800;

export function safeRuntimeText(value) {
  let text = String(value ?? "");
  text = text
    .replace(/\b(Bearer\s+)[A-Za-z0-9._~+/-]{8,}/gi, "$1[REDACTED]")
    .replace(/\b(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{16})\b/g, "[REDACTED]")
    .replace(/\b((?:api[_-]?key|token|secret|password|passwd|authorization|cookie)\s*[:=]\s*["']?)[^"'\s,;}{]{5,}/gi, "$1[REDACTED]");
  return text.length > MAX_STRING ? text.slice(0, MAX_STRING) + " [truncated]" : text;
}

export function sanitizeRuntimeEvidence(value, depth = 0) {
  if (value === null || value === undefined) return value ?? null;
  if (typeof value === "string") return safeRuntimeText(value);
  if (typeof value === "number") return Number.isFinite(value) ? value : null;
  if (typeof value === "boolean") return value;
  if (depth >= MAX_DEPTH) return "[further detail omitted]";
  if (Array.isArray(value)) {
    const items = value.slice(0, MAX_ARRAY).map((item) => sanitizeRuntimeEvidence(item, depth + 1));
    if (value.length > MAX_ARRAY) items.push("[additional items omitted]");
    return items;
  }
  if (typeof value === "object") {
    const result = {};
    const entries = Object.entries(value);
    for (const [key, item] of entries.slice(0, MAX_OBJECT)) {
      const safeKey = safeRuntimeText(key).slice(0, 100);
      result[safeKey] = SENSITIVE_KEY.test(key)
        ? "[REDACTED]" : sanitizeRuntimeEvidence(item, depth + 1);
    }
    if (entries.length > MAX_OBJECT) result["[additional fields omitted]"] = true;
    return result;
  }
  return "[unsupported value]";
}

export function formatSafeRuntimeEvidence(value) {
  if (value === null || value === undefined || value === "") return "-";
  if (typeof value === "string") {
    try { return JSON.stringify(sanitizeRuntimeEvidence(JSON.parse(value)), null, 2); }
    catch { return safeRuntimeText(value); }
  }
  try { return JSON.stringify(sanitizeRuntimeEvidence(value), null, 2); }
  catch { return "[unreadable historical evidence]"; }
}
