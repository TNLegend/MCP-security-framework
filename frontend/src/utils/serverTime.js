// Backend legacy DateTime fields are UTC even when their serialized ISO
// timestamp omits the timezone. Never reinterpret them in the browser's zone.
// User-entered datetime-local form values must NOT use this function.
const ISO_WITHOUT_ZONE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?$/;
const ISO_WITH_SPACE = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?$/;

export function parseServerTime(value) {
  if (value instanceof Date) return new Date(value.getTime());
  if (typeof value !== "string" || !value.trim()) return new Date(NaN);
  const normalized = value.trim().replace(ISO_WITH_SPACE, (stamp) => stamp.replace(" ", "T"));
  const utcValue = ISO_WITHOUT_ZONE.test(normalized) ? normalized + "Z" : normalized;
  return new Date(utcValue);
}

export function formatServerTime(value) {
  if (!value) return "-";
  const date = parseServerTime(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
}

export function isServerTimeFuture(value, now = new Date()) {
  const parsed = parseServerTime(value);
  return !Number.isNaN(parsed.getTime()) && parsed.getTime() > now.getTime();
}
