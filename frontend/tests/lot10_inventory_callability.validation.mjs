import assert from "node:assert/strict";
import test from "node:test";
import { createServer } from "vite";

test("TA-05: tool overview does not mistake an approved analysis for runtime permission", async () => {
  const server = await createServer({
    configFile: false,
    plugins: [(await import("@vitejs/plugin-react")).default()],
    server: { middlewareMode: true, hmr: false },
    appType: "custom", logLevel: "silent",
  });
  try {
    const { toolCallabilityContext: describe } = await server.ssrLoadModule("/src/pages/Inventory.jsx");
    assert.match(describe({ analysis_status: "BLOCKED" }), /blocked/i);
    assert.match(describe({ analysis_status: "QUARANTINED" }), /restricted/i);
    assert.match(describe({ analysis_status: "ANALYSIS_FAILED" }), /not complete/i);
    assert.match(describe({ analysis_status: "ADMIN_ALLOWED", approved_fingerprint_match: true }), /does not authorize/i);
    assert.match(describe({ analysis_status: "APPROVED", approved_fingerprint_match: true }), /signed contracts/i);
    assert.match(describe({ analysis_status: "APPROVED", approved_fingerprint_match: false }), /not proven/i);
    assert.match(describe(null), /unknown/i);
  } finally {
    await server.close();
  }
});
