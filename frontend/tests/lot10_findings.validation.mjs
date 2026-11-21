import assert from "node:assert/strict";
import test from "node:test";
import { createServer } from "vite";

test("TA-03: finding decision impact comes only from backend evidence", async () => {
  const server = await createServer({
    configFile: false,
    plugins: [(await import("@vitejs/plugin-react")).default()],
    server: { middlewareMode: true, hmr: false },
    appType: "custom",
    logLevel: "silent",
  });
  try {
    const { findingImpactLabel } = await server.ssrLoadModule("/src/pages/ToolAnalysis.jsx");
    assert.match(findingImpactLabel({ evidence: { decision: "BLOCK" } }), /blocking|blocks/i);
    assert.match(findingImpactLabel({ evidence: { decision: "REVIEW" } }), /human security review/i);
    assert.match(findingImpactLabel({ evidence: { decision: "INFO" } }), /informational/i);
    assert.match(findingImpactLabel({ severity: "critical" }), /not recorded/i);
    assert.match(findingImpactLabel({ evidence: { decision: "UNKNOWN" } }), /not recorded/i);
    assert.match(findingImpactLabel(null), /not recorded/i);
  } finally {
    await server.close();
  }
});
