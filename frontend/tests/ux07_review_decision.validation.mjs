import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { createServer } from "vite";

test("UX-07: unreadable eligibility is never shown as a verified refusal; reason codes are bound", async () => {
  const server = await createServer({
    configFile: false,
    plugins: [(await import("@vitejs/plugin-react")).default()],
    server: { middlewareMode: true, hmr: false }, appType: "custom", logLevel: "silent",
  });
  try {
    const { reviewDecisionState: state } = await server.ssrLoadModule("/src/pages/ToolAnalysis.jsx");
    const analysis = { fingerprint: "a".repeat(64) };
    assert.equal(state({ errors: { eligibility: "503" } }, analysis).state, "unavailable");
    assert.equal(state({ errors: {} }, analysis).state, "unavailable");
    assert.equal(state({ errors: {}, eligibility: { eligible: false, fingerprint: "b".repeat(64), reasons: [] } }, analysis).state, "stale");
    const scope = state({ errors: {}, eligibility: { eligible: false, fingerprint: analysis.fingerprint,
      next_action: "RUN_DISCOVERY", reasons: [{ code: "SCOPE_MISMATCH", message: "Observation scope differs." },
        { code: "PROTOCOL_OBSERVATION_MISSING", message: "No protocol observation." }] } }, analysis);
    assert.equal(scope.state, "ineligible");
    assert.deepEqual(scope.reasons.map((r) => r.code), ["SCOPE_MISMATCH", "PROTOCOL_OBSERVATION_MISSING"]);
    assert.match(scope.next, /Refresh discovery/);
    assert.equal(state({ errors: {}, eligibility: { eligible: true, fingerprint: analysis.fingerprint, reasons: [] } }, analysis).state, "eligible");
    assert.equal(state(null, analysis, true).state, "loading");
  } finally {
    await server.close();
  }
  const source = readFileSync(fileURLToPath(new URL("../src/pages/ToolAnalysis.jsx", import.meta.url)), "utf8");
  assert.ok(source.indexOf("<ReviewDecisionEvidence") < source.indexOf("<ReviewActionControls"), "evidence precedes controls");
  assert.ok(source.indexOf("<AnalysisWorkspace") < source.indexOf('className="analysis-technical-identity"'), "identifiers after evidence");
  assert.match(source, /<th>Analysis<\/th>\s*<th>Human review<\/th>/);
});
