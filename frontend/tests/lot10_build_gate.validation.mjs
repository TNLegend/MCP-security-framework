import assert from "node:assert/strict";
import test from "node:test";
import { createServer } from "vite";

test("BS-01: draft Build mode is interpreted without implying active permission", async () => {
  const server = await createServer({
    configFile: false, plugins: [(await import("@vitejs/plugin-react")).default()],
    server: { middlewareMode: true, hmr: false }, appType: "custom", logLevel: "silent",
  });
  try {
    const { buildDraftGatePreview: preview } = await server.ssrLoadModule("/src/pages/BuildSecurity.jsx");
    assert.match(preview("DISABLED", "BLOCK", false), /disabled/i);
    assert.match(preview("REQUIRE_PASS", "WARN", true), /would block/i);
    assert.match(preview("REQUIRE_PASS", "BLOCK", true), /would block/i);
    assert.match(preview("ALLOW_WARN", "ERROR", true), /would block/i);
    assert.match(preview("ALLOW_WARN", "WARN", true), /meets this draft/i);
    assert.match(preview("REQUIRE_PASS", "PASS", true), /signed evidence/i);
    assert.match(preview("ALLOW_WARN", "PASS", false), /scanners are incomplete/i);
    assert.match(preview("REQUIRE_PASS", "UNKNOWN", true), /do not infer/i);
    assert.match(preview("INVALID", "PASS", true), /cannot be determined/i);
    assert.doesNotMatch(preview("ALLOW_WARN", "WARN", true), /authorized to run|runtime allowed/i);
  } finally {
    await server.close();
  }
});
