const MISSING = Symbol("missing");
const sensitiveName = /(?:^|_)(?:password|secret|token|credential|private_key|api_key|authorization_header)(?:_|$)/i;

function kind(value) {
  if (value === MISSING) return "missing";
  if (value === null) return "null";
  return Array.isArray(value) ? "array" : typeof value;
}

function display(value) {
  if (value === MISSING) return "—";
  const serialized = JSON.stringify(value, (name, entry) =>
    sensitiveName.test(name) ? "[redacted]" : entry);
  return serialized.length > 480 ? serialized.slice(0, 480) + "…" : serialized;
}

export function nestedPathDiff(before, after, limit = 100) {
  const rows = [];
  let changed = 0;
  let unchanged = 0;

  function compare(old, next, path) {
    if (path.some((key) => sensitiveName.test(key))) return;
    const beforeType = kind(old);
    const afterType = kind(next);
    if (beforeType === afterType && ["array", "object"].includes(beforeType)) {
      const keys = [...new Set([...Object.keys(old), ...Object.keys(next)])];
      if (!keys.length && path.length) unchanged += 1;
      for (const key of keys) compare(Object.hasOwn(old, key) ? old[key] : MISSING,
        Object.hasOwn(next, key) ? next[key] : MISSING, [...path, key]);
      return;
    }
    if (Object.is(old, next)) {
      if (path.length) unchanged += 1;
      return;
    }
    changed += 1;
    if (rows.length >= limit) return;
    rows.push({
      path: "/" + path.map((segment) => segment.replaceAll("~", "~0").replaceAll("/", "~1")).join("/"),
      kind: old === MISSING ? "Added" : next === MISSING ? "Removed" : "Changed",
      before: display(old), after: display(next), beforeType, afterType,
    });
  }
  compare(before, after, []);
  return { rows, unchanged, omitted: changed - rows.length };
}

export function publicationDiffInputs(preview, draft, active) {
  const matches = (reference, revision) => Boolean(reference?.id && reference.content_hash &&
    reference.id === revision?.id && reference.content_hash === revision.content_hash &&
    revision.content && typeof revision.content === "object");
  if (!matches(preview?.draft, draft)) return null;
  if (preview.active !== null && (active?.status !== "PUBLISHED" || !matches(preview.active, active))) {
    return null;
  }
  return { before: preview.active === null ? {} : active.content, after: draft.content };
}
