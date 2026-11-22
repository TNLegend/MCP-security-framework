import assert from "node:assert/strict";
import test from "node:test";
import { createServer } from "vite";

test("UX-10: signed gate state comes from the active signed revision, never a draft", async () => {
  const server = await createServer({
    configFile: false,
    plugins: [(await import("@vitejs/plugin-react")).default()],
    server: { middlewareMode: true, hmr: false }, appType: "custom", logLevel: "silent",
  });
  try {
    const { buildScanFacts: facts, buildReasonTarget: target } = await server.ssrLoadModule("/src/pages/BuildSecurity.jsx");
    const detail = { scan: { id: "scan-1" }, assessment: null,
      scanner_runs: [{ scanner_id: "semgrep", status: "COMPLETED" }, { scanner_id: "trivy", status: "FAILED", required: true }] };
    const revision = (mode, bound) => ({ revision_number: 3, content: { build_security: { mode,
      evidence: bound ? [{ scan_id: "scan-1" }] : [] } } });
    assert.match(facts(detail, revision("DISABLED", false)).gate.label, /^Off/);
    assert.match(facts(detail, revision("ALLOW_WARN", true)).gate.label, /^Audit only/);
    assert.match(facts(detail, revision("ALLOW_WARN", true)).gate.detail, /is the bound evidence in active signed revision 3/);
    assert.match(facts(detail, revision("REQUIRE_PASS", false)).gate.detail, /is not bound evidence.*draft attachment alone has no runtime effect/);
    assert.match(facts(detail, null).gate.label, /unavailable/);
    assert.equal(facts(detail, null).coverage.label, "Required coverage incomplete");
    assert.match(facts(detail, null).execution.detail, /trivy \(failed\)/);
    assert.deepEqual(target("critical_findings", detail), { kind: "severity", severity: "CRITICAL", label: "Show critical findings" });
    assert.equal(target("required_scanner_incomplete", detail).scannerId, "trivy");
    assert.equal(target("future_code", detail).kind, "unknown");
  } finally {
    await server.close();
  }
});
