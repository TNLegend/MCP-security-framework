import assert from "node:assert/strict";
import test from "node:test";
import { createServer } from "vite";

test("UX-05: Inventory names the exact observation blocker and never promises a call", async () => {
  const server = await createServer({
    configFile: false,
    plugins: [(await import("@vitejs/plugin-react")).default()],
    server: { middlewareMode: true, hmr: false }, appType: "custom", logLevel: "silent",
  });
  try {
    const { observationBlocker: blocker } = await server.ssrLoadModule("/src/pages/Inventory.jsx");
    assert.match(blocker({ analysis_status: "PENDING_ANALYSIS" }), /not completed/);
    assert.match(blocker({ analysis_status: "BLOCKED", status_reason: "Scope mismatch" }), /^Blocked: Scope mismatch/);
    assert.match(blocker({ analysis_status: "APPROVED", approved_fingerprint_match: true }), /runtime checks still apply/);
    assert.match(blocker({ analysis_status: "APPROVED", approved_fingerprint_match: false }), /does not match the current fingerprint/);
    assert.match(blocker({ analysis_status: "APPROVED" }, "503"), /could not be read/);
    assert.match(blocker({}), /No analysis recorded/);
    for (const status of ["PENDING_ANALYSIS", "BLOCKED", "APPROVED", "REVIEW_REQUIRED"]) {
      assert.doesNotMatch(blocker({ analysis_status: status, approved_fingerprint_match: true }), /\b(can be called|callable|authorized)\b/i);
    }
  } finally {
    await server.close();
  }
});
