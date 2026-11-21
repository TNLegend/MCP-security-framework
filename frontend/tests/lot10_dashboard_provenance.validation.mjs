import assert from "node:assert/strict";
import test from "node:test";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { createServer } from "vite";

test("HOME-02: unavailable refresh does not disguise stale revision/endpoint metadata as live security state", async () => {
  const server = await createServer({
    configFile: false,
    plugins: [(await import("@vitejs/plugin-react")).default()],
    server: { middlewareMode: true, hmr: false },
    appType: "custom", logLevel: "silent",
  });
  try {
    const { default: Dashboard } = await server.ssrLoadModule("/src/pages/Dashboard.jsx");
    const base = {
      activeRevision: { revision_number: 7, status: "PUBLISHED", schema_version: "v2", content_hash: "01234567890123456789" },
      auditEvents: [], emergencyDenies: [], health: { status: "healthy" },
      isAdmin: false, runtimeStatus: {
        database: { status: "healthy", detail: "postgres.internal:5432" },
        opa: { status: "healthy", endpoint: "http://opa.internal:8181" },
        gateway: { status: "healthy", endpoint: "http://gateway.internal:8766" },
      },
      servers: [], tools: [], runtimeLogs: [],
      runtimeSummary: { allowed: 0, blocked: 0 },
      dashboardRefreshedAt: null, loading: false, onNavigate: () => {},
    };
    const view = (readStates) => renderToStaticMarkup(React.createElement(Dashboard, { ...base, readStates }));
    const stale = view({
      health: "ready", runtimeStatus: "unavailable", activeRevision: "unavailable",
      servers: "ready", tools: "ready", runtimeLogs: "ready", audit: "ready",
      emergencyDenies: "ready",
    });
    assert.match(stale, /previously loaded metadata, not proof/);
    assert.match(stale, /latest signed configuration could not be checked/);
    assert.doesNotMatch(stale, /http:\/\/opa.internal:8181/);
    assert.doesNotMatch(stale, /http:\/\/gateway.internal:8766/);
    assert.doesNotMatch(stale, /postgres.internal:5432/);

    const current = view({
      health: "ready", runtimeStatus: "ready", activeRevision: "ready",
      servers: "ready", tools: "ready", runtimeLogs: "ready", audit: "ready",
      emergencyDenies: "ready",
    });
    assert.doesNotMatch(current, /previously loaded metadata, not proof/);
    assert.match(current, /http:\/\/opa.internal:8181/);
    assert.match(current, /PUBLISHED/);
    assert.match(current, /up to six of the latest 200 loaded audit events/);
  } finally {
    await server.close();
  }
});