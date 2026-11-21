import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs/promises";
import { createServer } from "vite";

test("XC-05: execution statuses and severity have distinct visual meaning", async () => {
  const server = await createServer({
    configFile: false,
    plugins: [(await import("@vitejs/plugin-react")).default()],
    server: { middlewareMode: true, hmr: false },
    appType: "custom", logLevel: "silent",
  });
  try {
    const { getExecutionBadgeClass } = await server.ssrLoadModule("/src/pages/RuntimeLogs.jsx");
    assert.match(getExecutionBadgeClass("result_blocked"), /badge-danger/);
    assert.match(getExecutionBadgeClass("blocked"), /badge-danger/);
    assert.equal(getExecutionBadgeClass("upstream_outcome_unknown"), "badge-warn badge-warning");
    assert.equal(getExecutionBadgeClass("authorized_pending_execution"), "badge-warn badge-warning");
    assert.equal(getExecutionBadgeClass("success"), "badge-success");
    assert.equal(getExecutionBadgeClass("unknown"), "badge-unknown");
    assert.notEqual(getExecutionBadgeClass("blocked"), getExecutionBadgeClass("unknown"));
    assert.notEqual(getExecutionBadgeClass("success"), getExecutionBadgeClass("upstream_outcome_unknown"));
    const css = await fs.readFile("src/styles.css", "utf8");
    const low = css.match(/\.badge-low\s*\{([^}]*)\}/)?.[1];
    const medium = css.match(/\.badge-medium,\s*\.badge-warning\s*\{([^}]*)\}/)?.[1];
    assert.ok(low && medium);
    assert.notEqual(low.match(/background:\s*([^;]+)/)?.[1], medium.match(/background:\s*([^;]+)/)?.[1]);
    assert.notEqual(low.match(/color:\s*([^;]+)/)?.[1], medium.match(/color:\s*([^;]+)/)?.[1]);
  } finally {
    await server.close();
  }
});
