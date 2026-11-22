import assert from "node:assert/strict";
import test from "node:test";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { createServer } from "vite";

async function withDashboard(run) {
  const server = await createServer({
    configFile: false, plugins: [(await import("@vitejs/plugin-react")).default()],
    server: { middlewareMode: true, hmr: false }, appType: "custom", logLevel: "silent",
  });
  try {
    const { default: Dashboard } = await server.ssrLoadModule("/src/pages/Dashboard.jsx");
    return await run(Dashboard);
  } finally {
    await server.close();
  }
}

const props = {
  activeRevision: { revision_number: 80, status: "PUBLISHED", content_hash: "a".repeat(64) },
  auditEvents: [{ id: "audit-1", action: "EMERGENCY_DENY_CREATED", timestamp: "2026-11-21T20:00:00" }],
  emergencyDenies: [
    { id: "d1", state: "ACTIVE" },
    { id: "d2", state: "REVOKED" },
    { id: "d3", state: "EXPIRED" },
  ],
  health: { status: "ok", checked_at: "2026-11-21T20:01:00+00:00" },
  runtimeStatus: {
    database: { status: "ok", checked_at: "2026-11-21T20:02:00+00:00" },
    opa: { status: "ok", checked_at: "2026-11-21T20:03:00+00:00" },
    gateway: { status: "ok", checked_at: "2026-11-21T20:04:00+00:00" },
  },
  servers: [{ id: 1, status: "active" }, { id: 2, status: "active" }],
  tools: [
    { id: 1, analysis_status: "APPROVED", approved_fingerprint_match: true },
    { id: 2, analysis_status: "PENDING_ANALYSIS" },
    { id: 3, analysis_status: "BLOCKED" },
    { id: 4, analysis_status: "ADMIN_ALLOWED", approved_fingerprint_match: false },
  ],
  runtimeSummary: { allowed: 4, blocked: 3 },
  isAdmin: true, onNavigate: () => {},
  readStates: Object.fromEntries(
    ["health", "runtimeStatus", "servers", "tools", "audit", "emergencyDenies",
     "runtimeLogs", "activeRevision"].map((x) => [x, "ready"]),
  ),
  readTimestamps: Object.fromEntries(
    ["health", "runtimeStatus", "servers", "tools", "audit", "emergencyDenies",
     "runtimeLogs", "activeRevision"].map((x, i) => [x, new Date(1784920000000 + i * 60000).toISOString()]),
  ),
};

test("DB-01/HOME-02: each ready source carries a successful response timestamp and correct population", async () => {
  await withDashboard((Dashboard) => {
    const html = renderToStaticMarkup(React.createElement(Dashboard, props));
    assert.match(html, />MCP servers<\/span><strong>2<\/strong>/);
    assert.match(html, />MCP tools<\/span><strong>4<\/strong>/);
    assert.match(html, />Reviews approved<\/span><strong>1<\/strong>/);
    assert.match(html, />Tools requiring review<\/span><strong>1<\/strong>/);
    assert.match(html, />Blocked tools<\/span><strong>1<\/strong>/);
    assert.match(html, />Active emergency blocks<\/span><strong>1<\/strong>/);
    // UX-04: policy decisions are labelled as decisions, not outcomes.
    assert.match(html, />Recorded policy allows \(OPA or Proxy decision\)<\/span><strong>4<\/strong>/);
    assert.match(html, />Recorded policy blocks \(OPA or Proxy decision\)<\/span><strong>3<\/strong>/);
    assert.doesNotMatch(html, /Allowed outcome events/);
    // Without backend outcome states nothing is inferred and the link is disabled.
    assert.match(html, />Outcome uncertain after send<\/span><strong>—<\/strong>/);
    assert.match(html, /disabled="">Review uncertain outcomes/);
    assert.equal((html.match(/Response received:/g) || []).length, 8);
    // Each priority card names its population and the time it was read.
    assert.equal((html.match(/class="priority-population">[^<]+ · read /g) || []).length, 4);
    assert.equal((html.match(/Checked by server:/g) || []).length, 4);
    assert.match(html, /API receipt times, not measurement times/);
  });
});

test("HOME-02: a failed refresh never re-labels old status or revision metadata as current", async () => {
  await withDashboard((Dashboard) => {
    const html = renderToStaticMarkup(React.createElement(Dashboard, {
      ...props,
      readStates: { ...props.readStates, health: "unavailable", runtimeStatus: "unavailable", activeRevision: "unavailable" },
    }));
    assert.match(html, /Current API response unavailable/);
    assert.match(html, /previously loaded metadata, not proof of what is currently active/);
    assert.doesNotMatch(html, /<span>API<\/span><strong>Ok<\/strong>/);
    assert.doesNotMatch(html, /Checked by server:/);
    assert.doesNotMatch(html, /signature metadata must still be verified independently/);
  });
});
