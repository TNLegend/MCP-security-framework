// UX-01: compare independently probed build identities. Unknown, unreachable
// and mismatched are separate states; readiness is never used as a proxy.

/* global __MCP_UI_BUILD__ */
export const UI_BUILD = (() => {
  try {
    // Defined by vite.config.js at build/dev-server start.
    return typeof __MCP_UI_BUILD__ === "object" && __MCP_UI_BUILD__ ? __MCP_UI_BUILD__ : null;
  } catch {
    return null;
  }
})();

export const PROVENANCE_STATUS_LABELS = {
  match: "Match",
  mismatch: "Mismatch",
  unknown: "Version unknown",
  unreachable: "Unreachable",
};

export function shortRevision(value) {
  return value ? String(value).slice(0, 12) : "Unknown";
}

export function compareUiToApi(uiBuild, apiBuild) {
  const ui = uiBuild?.revision || null;
  const api = apiBuild?.revision || null;
  let status;
  if (!apiBuild) status = "unreachable";
  else if (!ui || !api) status = "unknown";
  else status = ui === api ? "match" : "mismatch";
  return {
    key: "ui_revision_vs_api",
    label: "UI bundle revision compared with API revision",
    status,
    expected: api,
    observed: ui,
    uncommitted_changes_at_start: Boolean(uiBuild?.worktree_dirty || apiBuild?.worktree_dirty),
  };
}

export function provenanceRows(provenance, uiBuild = UI_BUILD) {
  const comparisons = [compareUiToApi(uiBuild, provenance?.components?.api?.build || null),
    ...(provenance?.comparisons || [])];
  const states = new Set(comparisons.map((item) => item.status));
  const overall = states.has("mismatch") ? "mismatch" : states.has("unreachable") ? "unreachable"
    : states.has("unknown") ? "unknown" : "match";
  return { comparisons, overall };
}
